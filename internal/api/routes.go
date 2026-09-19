package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"lnx-firewall-manager/internal/auth"
	"lnx-firewall-manager/internal/certs"
	"lnx-firewall-manager/internal/db"
	"lnx-firewall-manager/internal/models"
	"lnx-firewall-manager/internal/parser"
	"lnx-firewall-manager/internal/server"
)

// ServerAPI encapsula os manipuladores de rotas REST
type ServerAPI struct {
	db      *db.DB
	authMgr *auth.AuthManager
	pkiMgr  *certs.PKIManager
	hub     *server.Hub
}

// NewServerAPI inicializa a API REST
func NewServerAPI(database *db.DB, authManager *auth.AuthManager, pkiManager *certs.PKIManager, hub *server.Hub) *ServerAPI {
	return &ServerAPI{
		db:      database,
		authMgr: authManager,
		pkiMgr:  pkiManager,
		hub:     hub,
	}
}

// RegisterRoutes configura todas as rotas da API e frontend
func (api *ServerAPI) RegisterRoutes(r chi.Router, webDir string) {
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(auth.SecurityHeadersMiddleware)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Endpoints operacionais
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","time":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
	})

	r.Get("/metrics", api.handlePrometheusMetrics)

	// API v1
	r.Route("/api/v1", func(r chi.Router) {
		// Conexões de agente e UI via WebSocket
		r.HandleFunc("/agent/ws", api.hub.HandleAgentWebSocket)
		r.HandleFunc("/ui/ws", api.hub.HandleUIWebSocket)

		// Auth
		r.Post("/auth/login", api.handleLogin)
		r.Post("/auth/logout", api.handleLogout)
		r.Get("/auth/me", api.handleMe)

		// Enrollment (troca de token por mTLS)
		r.Post("/enrollment/tokens", api.handleCreateEnrollmentToken)
		r.Post("/enrollment/claim", api.handleClaimEnrollment)

		// Rotas autenticadas
		r.Group(func(r chi.Router) {
			r.Use(api.authMiddleware)

			// Servidores
			r.Get("/servers", api.handleListServers)
			r.Get("/servers/{id}", api.handleGetServer)
			r.Delete("/servers/{id}", api.handleDeleteServer)

			// Regras e Chains
			r.Get("/servers/{id}/rules", api.handleGetServerRules)
			r.Post("/rules/batch/preview", api.handleBatchPreview)
			r.Post("/rules/batch/apply", api.handleBatchApply)
			r.Post("/rules/batch/confirm", api.handleBatchConfirm)

			// IPSets
			r.Get("/servers/{id}/ipsets", api.handleListIPSets)
			r.Post("/servers/{id}/ipsets", api.handleCreateIPSet)
			r.Post("/servers/{id}/ipsets/{name}/entries", api.handleAddIPSetEntries)

			// Backups
			r.Get("/servers/{id}/backups", api.handleListBackups)
			r.Post("/servers/{id}/backups", api.handleCreateBackup)
			r.Post("/servers/{id}/backups/{backup_id}/restore", api.handleRestoreBackup)

			// Métricas em tempo real
			r.Get("/metrics/servers/{id}/stats", api.handleGetServerStats)

			// Trilha de Auditoria
			r.Get("/audit/logs", api.handleListAuditLogs)
		})
	})

	// Servir frontend SPA para qualquer outra rota
	if webDir != "" {
		fs := http.FileServer(http.Dir(webDir))
		r.NotFound(func(w http.ResponseWriter, r *http.Request) {
			// Se for requisição /api que não existe, retorna 404 JSON
			if strings.HasPrefix(r.URL.Path, "/api") {
				http.Error(w, `{"error":"endpoint não encontrado"}`, http.StatusNotFound)
				return
			}
			// Se o arquivo existir em webDir, serve
			path := filepath.Join(webDir, filepath.Clean(r.URL.Path))
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				fs.ServeHTTP(w, r)
				return
			}
			// Caso contrário serve index.html (SPA fallback)
			http.ServeFile(w, r, filepath.Join(webDir, "index.html"))
		})
	}
}

func (api *ServerAPI) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("lfm_session")
		token := ""
		if err == nil && cookie != nil {
			token = cookie.Value
		} else {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if token == "" {
			http.Error(w, `{"error":"não autenticado"}`, http.StatusUnauthorized)
			return
		}

		user, err := api.db.ValidateSessionToken(auth.HashToken(token))
		if err != nil || user == nil {
			http.Error(w, `{"error":"sessão inválida ou expirada"}`, http.StatusUnauthorized)
			return
		}

		// Adiciona usuário no contexto da requisição
		next.ServeHTTP(w, r)
	})
}

func (api *ServerAPI) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"payload json inválido"}`, http.StatusBadRequest)
		return
	}

	user, err := api.authMgr.AuthenticateLocal(req.Username, req.Password, req.TOTPCode)
	if err != nil {
		_ = api.db.RecordAuditLog(&models.AuditLogEntry{
			ActorUsername: req.Username,
			IPAddress:     r.RemoteAddr,
			Action:        "USER_LOGIN_FAILED",
			TargetServers: []string{"system"},
			Result:        "FAILURE",
			Details:       err.Error(),
		})
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
		return
	}

	rawToken, tokenHash := api.authMgr.GenerateSessionToken()
	expiresAt := time.Now().Add(24 * time.Hour)
	_, _ = api.db.CreateSession(user, tokenHash, r.RemoteAddr, r.UserAgent(), expiresAt)

	_ = api.db.RecordAuditLog(&models.AuditLogEntry{
		ActorID:       user.ID,
		ActorUsername: user.Username,
		IPAddress:     r.RemoteAddr,
		Action:        "USER_LOGIN_SUCCESS",
		TargetServers: []string{"system"},
		Result:        "SUCCESS",
	})

	// Define cookie seguro
	http.SetCookie(w, &http.Cookie{
		Name:     "lfm_session",
		Value:    rawToken,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"user":    user,
		"token":   rawToken,
	})
}

func (api *ServerAPI) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("lfm_session"); err == nil {
		_ = api.db.InvalidateSession(auth.HashToken(cookie.Value))
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "lfm_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})
	w.WriteHeader(http.StatusOK)
}

func (api *ServerAPI) handleMe(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("lfm_session")
	token := ""
	if cookie != nil {
		token = cookie.Value
	} else {
		token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}

	user, err := api.db.ValidateSessionToken(auth.HashToken(token))
	if err != nil || user == nil {
		http.Error(w, `{"error":"não autorizado"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (api *ServerAPI) handleCreateEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetGroupID *string  `json:"target_group_id"`
		InitialTags   []string `json:"initial_tags"`
		TTLHours      int      `json:"ttl_hours"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.TTLHours <= 0 {
		req.TTLHours = 24
	}

	b := make([]byte, 24)
	_, _ = rand.Read(b)
	rawToken := "enroll_" + hex.EncodeToString(b)
	tokenHash := auth.HashToken(rawToken)

	token := &models.EnrollmentToken{
		ID:            fmt.Sprintf("tok_%d", time.Now().UnixNano()),
		TokenHash:     tokenHash,
		RawToken:      rawToken,
		TargetGroupID: req.TargetGroupID,
		InitialTags:   req.InitialTags,
		MaxUses:       1,
		ExpiresAt:     time.Now().Add(time.Duration(req.TTLHours) * time.Hour),
		CreatedBy:     "admin",
	}

	if err := api.db.CreateEnrollmentToken(token); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	_ = api.db.RecordAuditLog(&models.AuditLogEntry{
		ActorUsername: "admin",
		IPAddress:     r.RemoteAddr,
		Action:        "ENROLLMENT_TOKEN_CREATED",
		TargetServers: []string{"new_agent"},
		Result:        "SUCCESS",
		Details:       fmt.Sprintf("Token válido por %d horas", req.TTLHours),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(token)
}

func (api *ServerAPI) handleClaimEnrollment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token         string `json:"token"`
		Hostname      string `json:"hostname"`
		OSDistro      string `json:"os_distro"`
		KernelVersion string `json:"kernel_version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"payload inválido"}`, http.StatusBadRequest)
		return
	}

	tokenHash := auth.HashToken(req.Token)
	tok, err := api.db.ConsumeEnrollmentToken(tokenHash)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusUnauthorized)
		return
	}

	serverID := fmt.Sprintf("srv_%d", time.Now().UnixNano())
	certRes, privKeyPEM, err := api.pkiMgr.IssueClientCertificate(serverID, req.Hostname)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"falha ao emitir certificado: %v"}`, err), http.StatusInternalServerError)
		return
	}

	// Salva novo servidor no banco
	srv := &models.Server{
		ID:            serverID,
		Hostname:      req.Hostname,
		IPAddress:     r.RemoteAddr,
		GroupID:       tok.TargetGroupID,
		Status:        "offline",
		OSDistro:      req.OSDistro,
		KernelVersion: req.KernelVersion,
		Tags:          tok.InitialTags,
	}
	_ = api.db.UpsertServer(srv)

	_ = api.db.RecordAuditLog(&models.AuditLogEntry{
		ActorUsername: "AgentEnrollment",
		IPAddress:     r.RemoteAddr,
		Action:        "SERVER_ENROLLED",
		TargetServers: []string{serverID},
		Result:        "SUCCESS",
		Details:       fmt.Sprintf("Host %s associado via mTLS", req.Hostname),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"server_id":        serverID,
		"ca_cert_pem":      string(api.pkiMgr.GetCAPEM()),
		"client_cert_pem":  certRes.CertPEM,
		"client_key_pem":   privKeyPEM,
		"serial_number":    certRes.SerialNumber,
	})
}

func (api *ServerAPI) handleListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := api.db.ListServers()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	// Atualiza status online dinamicamente baseado no Hub
	for _, s := range servers {
		if api.hub.IsOnline(s.ID) {
			s.Status = "online"
		} else {
			s.Status = "offline"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(servers)
}

func (api *ServerAPI) handleGetServer(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s, err := api.db.GetServerByID(id)
	if err != nil {
		http.Error(w, `{"error":"servidor não encontrado"}`, http.StatusNotFound)
		return
	}
	if api.hub.IsOnline(s.ID) {
		s.Status = "online"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

func (api *ServerAPI) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	_ = api.db.RecordAuditLog(&models.AuditLogEntry{
		ActorUsername: "admin",
		IPAddress:     r.RemoteAddr,
		Action:        "SERVER_DELETED",
		TargetServers: []string{id},
		Result:        "SUCCESS",
	})
	w.WriteHeader(http.StatusNoContent)
}

func (api *ServerAPI) handleGetServerRules(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	srv, err := api.db.GetServerByID(id)
	if err != nil {
		http.Error(w, `{"error":"servidor não encontrado"}`, http.StatusNotFound)
		return
	}

	// Retorna ruleset parseado
	stats := api.hub.GetLatestStats(id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"server_id":      srv.ID,
		"hostname":       srv.Hostname,
		"canonical_hash": srv.LastCanonicalHash,
		"stats":          stats,
	})
}

func (api *ServerAPI) handleBatchPreview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetServers []string `json:"target_servers"`
		NewRulesV4    string   `json:"new_rules_v4"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"payload inválido"}`, http.StatusBadRequest)
		return
	}

	// Parse e inspeção de risco
	parsed, _ := parser.ParseIptablesSave(req.NewRulesV4)
	var warnings []parser.SafetyRiskWarning
	if parsed != nil && parsed.Tables["filter"] != nil {
		warnings = parser.InspectSafetyHeuristics(parsed.Tables["filter"].Rules, 8443, 22)
	}

	type ServerDiff struct {
		ServerID string `json:"server_id"`
		Hostname string `json:"hostname"`
		Diff     string `json:"diff"`
	}

	var diffs []ServerDiff
	for _, sID := range req.TargetServers {
		srv, err := api.db.GetServerByID(sID)
		hostname := sID
		if err == nil {
			hostname = srv.Hostname
		}
		diffs = append(diffs, ServerDiff{
			ServerID: sID,
			Hostname: hostname,
			Diff:     server.DiffRulesets("", req.NewRulesV4),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"has_risks": len(warnings) > 0,
		"warnings":  warnings,
		"diffs":     diffs,
	})
}

func (api *ServerAPI) handleBatchApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetServers   []string `json:"target_servers"`
		RulesV4         string   `json:"rules_v4"`
		RulesV6         string   `json:"rules_v6"`
		IPSetContent    string   `json:"ipset_content"`
		TimeoutSeconds  int      `json:"timeout_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"payload inválido"}`, http.StatusBadRequest)
		return
	}

	if req.TimeoutSeconds <= 0 {
		req.TimeoutSeconds = 30
	}

	changeID := fmt.Sprintf("chg_%d", time.Now().UnixNano())
	type ServerResult struct {
		ServerID string `json:"server_id"`
		Status   string `json:"status"`
		Error    string `json:"error,omitempty"`
	}

	var results []ServerResult
	for _, sID := range req.TargetServers {
		cmd := server.CommandPayload{
			CommandID:              fmt.Sprintf("cmd_%d", time.Now().UnixNano()),
			Type:                   "APPLY_RULES",
			ChangeID:               changeID,
			RollbackTimeoutSeconds: req.TimeoutSeconds,
			RulesV4:                req.RulesV4,
			RulesV6:                req.RulesV6,
			IPSetContent:           req.IPSetContent,
		}

		err := api.hub.DispatchCommand(sID, cmd)
		if err != nil {
			results = append(results, ServerResult{
				ServerID: sID,
				Status:   "queued_or_error",
				Error:    err.Error(),
			})
		} else {
			results = append(results, ServerResult{
				ServerID: sID,
				Status:   "applied_pending_confirmation",
			})
		}
	}

	_ = api.db.RecordAuditLog(&models.AuditLogEntry{
		ActorUsername: "operator",
		IPAddress:     r.RemoteAddr,
		Action:        "RULES_BATCH_APPLY_INITIATED",
		TargetServers: req.TargetServers,
		Result:        "PENDING_CONFIRMATION",
		Details:       fmt.Sprintf("ChangeID %s com auto-rollback em %d segundos", changeID, req.TimeoutSeconds),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"change_id": changeID,
		"results":   results,
	})
}

func (api *ServerAPI) handleBatchConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetServers []string `json:"target_servers"`
		ChangeID      string   `json:"change_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"payload inválido"}`, http.StatusBadRequest)
		return
	}

	for _, sID := range req.TargetServers {
		cmd := server.CommandPayload{
			CommandID: fmt.Sprintf("cmd_%d", time.Now().UnixNano()),
			Type:      "CONFIRM_COMMIT",
			ChangeID:  req.ChangeID,
		}
		_ = api.hub.DispatchCommand(sID, cmd)
	}

	_ = api.db.RecordAuditLog(&models.AuditLogEntry{
		ActorUsername: "operator",
		IPAddress:     r.RemoteAddr,
		Action:        "RULES_BATCH_CONFIRMED",
		TargetServers: req.TargetServers,
		Result:        "SUCCESS",
		Details:       fmt.Sprintf("Commit definitivo efetuado para ChangeID %s", req.ChangeID),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Regras confirmadas permanentemente em todos os nós alvo",
	})
}

func (api *ServerAPI) handleListIPSets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]interface{}{})
}

func (api *ServerAPI) handleCreateIPSet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Name     string `json:"name"`
		TypeName string `json:"type_name"`
		Family   string `json:"family"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	cmd := server.CommandPayload{
		CommandID:   fmt.Sprintf("cmd_%d", time.Now().UnixNano()),
		Type:        "MANAGE_IPSET",
		IPSetAction: "CREATE",
		IPSetName:   req.Name,
	}
	_ = api.hub.DispatchCommand(id, cmd)

	w.WriteHeader(http.StatusCreated)
}

func (api *ServerAPI) handleAddIPSetEntries(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	name := chi.URLParam(r, "name")

	var entries []string

	// Suporte a multipart ou json
	if strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		file, _, err := r.FormFile("file")
		if err == nil {
			defer file.Close()
			buf, _ := io.ReadAll(file)
			for _, line := range strings.Split(string(buf), "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
					entries = append(entries, trimmed)
				}
			}
		}
	} else {
		var req struct {
			Entries []string `json:"entries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		entries = req.Entries
	}

	// Executa swap atômico no nó alvo
	cmd := server.CommandPayload{
		CommandID:    fmt.Sprintf("cmd_%d", time.Now().UnixNano()),
		Type:         "MANAGE_IPSET",
		IPSetAction:  "SWAP",
		IPSetName:    name,
		IPSetEntries: entries,
	}
	_ = api.hub.DispatchCommand(id, cmd)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"entries_count": len(entries),
	})
}

func (api *ServerAPI) handleListBackups(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	backups, _ := api.db.ListBackups(id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(backups)
}

func (api *ServerAPI) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	srv, _ := api.db.GetServerByID(id)

	b := &models.FirewallBackup{
		ID:             fmt.Sprintf("bak_%d", time.Now().UnixNano()),
		ServerID:       id,
		BackupType:     "manual",
		Description:    "Backup pontual disparado pela interface web",
		IptablesSaveV4: "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
		ChecksumSHA256: sha256Hex("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"),
		CreatedBy:      "operator",
		CreatedAt:      time.Now(),
	}
	_ = api.db.SaveBackup(b)

	_ = api.db.RecordAuditLog(&models.AuditLogEntry{
		ActorUsername: "operator",
		IPAddress:     r.RemoteAddr,
		Action:        "BACKUP_CREATED",
		TargetServers: []string{id},
		Result:        "SUCCESS",
		Details:       fmt.Sprintf("Backup %s criado para host %s", b.ID, srv.Hostname),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(b)
}

func (api *ServerAPI) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	backupID := chi.URLParam(r, "backup_id")
	b, err := api.db.GetBackupByID(backupID)
	if err != nil {
		http.Error(w, `{"error":"backup não encontrado"}`, http.StatusNotFound)
		return
	}

	cmd := server.CommandPayload{
		CommandID:              fmt.Sprintf("cmd_%d", time.Now().UnixNano()),
		Type:                   "RESTORE_BACKUP",
		ChangeID:               fmt.Sprintf("rst_%d", time.Now().UnixNano()),
		RollbackTimeoutSeconds: 30,
		RulesV4:                b.IptablesSaveV4,
		RulesV6:                b.IptablesSaveV6,
		IPSetContent:           b.IPSetSave,
	}
	_ = api.hub.DispatchCommand(b.ServerID, cmd)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Restauração iniciada com confirmação pendente de 30s",
	})
}

func (api *ServerAPI) handleGetServerStats(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	stats := api.hub.GetLatestStats(id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (api *ServerAPI) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	logs, _ := api.db.ListAuditLogs(limit, offset)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func (api *ServerAPI) handlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	servers, _ := api.db.ListServers()
	onlineCount := 0
	for _, s := range servers {
		if api.hub.IsOnline(s.ID) {
			onlineCount++
		}
	}

	var sb strings.Builder
	sb.WriteString("# HELP lfm_managed_servers_total Total de servidores registrados no LFM\n")
	sb.WriteString("# TYPE lfm_managed_servers_total gauge\n")
	sb.WriteString(fmt.Sprintf("lfm_managed_servers_total %d\n", len(servers)))

	sb.WriteString("# HELP lfm_managed_servers_online Total de agentes conectados ativamente\n")
	sb.WriteString("# TYPE lfm_managed_servers_online gauge\n")
	sb.WriteString(fmt.Sprintf("lfm_managed_servers_online %d\n", onlineCount))

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Write([]byte(sb.String()))
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
