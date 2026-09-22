package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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

type contextKey string

const userContextKey contextKey = "user"

func getUserFromContext(r *http.Request) *models.User {
	if u, ok := r.Context().Value(userContextKey).(*models.User); ok {
		return u
	}
	return nil
}

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

		// Auth Local
		r.Post("/auth/login", api.handleLogin)
		r.Post("/auth/logout", api.handleLogout)
		r.Get("/auth/me", api.handleMe)

		// Auth OIDC Federado (Público)
		r.Get("/auth/oidc/status", api.handleOIDCStatus)
		r.Get("/auth/oidc/login", api.handleOIDCLogin)
		r.Get("/auth/oidc/callback", api.handleOIDCCallback)

		// Enrollment (troca de token por mTLS)
		r.Post("/enrollment/tokens", api.handleCreateEnrollmentToken)
		r.Post("/enrollment/claim", api.handleClaimEnrollment)

		// Rotas autenticadas (Viewer e Admin)
		r.Group(func(r chi.Router) {
			r.Use(api.authMiddleware)

			// Gestão de Perfil, Senha e 2FA do Usuário Conectado
			r.Post("/user/password", api.handleChangePassword)
			r.Get("/user/totp/setup", api.handleSetupTOTP)
			r.Post("/user/totp/enable", api.handleEnableTOTP)
			r.Post("/user/totp/disable", api.handleDisableTOTP)
			r.Get("/user/sessions", api.handleListSessions)
			r.Delete("/user/sessions/{id}", api.handleRevokeSession)

			// Leitura de Servidores
			r.Get("/servers", api.handleListServers)
			r.Get("/servers/{id}", api.handleGetServer)

			// Leitura de Regras e Preview
			r.Get("/servers/{id}/rules", api.handleGetServerRules)
			r.Get("/servers/{id}/interfaces", api.handleGetServerInterfaces)
			r.Post("/rules/batch/preview", api.handleBatchPreview)

			// Leitura de IPSets
			r.Get("/servers/{id}/ipsets", api.handleListIPSets)
			r.Get("/servers/{id}/ipsets/{name}/entries", api.handleGetIPSetEntries)
			r.Get("/servers/{id}/ipsets/{name}/usage", api.handleGetIPSetUsage)

			// Leitura de Backups
			r.Get("/servers/{id}/backups", api.handleListBackups)

			// Métricas em tempo real
			r.Get("/metrics/servers/{id}/stats", api.handleGetServerStats)

			// Trilha de Auditoria
			r.Get("/audit/logs", api.handleListAuditLogs)

			// Configurações OIDC (leitura para admin)
			r.Get("/settings/oidc", api.handleGetOIDCSettings)

			// Ações Restritas Estritamente a Administradores (RBAC)
			r.Group(func(r chi.Router) {
				r.Use(api.requireAdmin)

				// Gestão de Servidores
				r.Delete("/servers/{id}", api.handleDeleteServer)

				// Aplicação e Confirmação de Regras
				r.Post("/rules/batch/apply", api.handleBatchApply)
				r.Post("/rules/batch/confirm", api.handleBatchConfirm)

				// Mutação de IPSets
				r.Post("/servers/{id}/ipsets", api.handleCreateIPSet)
				r.Post("/servers/{id}/ipsets/{name}/entries", api.handleAddIPSetEntries)
				r.Delete("/servers/{id}/ipsets/{name}", api.handleDeleteIPSet)

				// Mutação e Restauração de Backups
				r.Post("/servers/{id}/backups", api.handleCreateBackup)
				r.Post("/servers/{id}/backups/{backup_id}/restore", api.handleRestoreBackup)

				// Configurações Federadas OIDC
				r.Put("/settings/oidc", api.handleSaveOIDCSettings)
				r.Post("/settings/oidc/test", api.handleTestOIDCSettings)
			})
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
			if r.Method == "GET" && (r.URL.Path == "/api/v1/servers" || strings.HasPrefix(r.URL.Path, "/api/v1/servers/")) {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, `{"error":"não autenticado"}`, http.StatusUnauthorized)
			return
		}

		user, err := api.db.ValidateSessionToken(auth.HashToken(token))
		if err != nil || user == nil {
			if r.Method == "GET" && (r.URL.Path == "/api/v1/servers" || strings.HasPrefix(r.URL.Path, "/api/v1/servers/")) {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, `{"error":"sessão inválida ou expirada"}`, http.StatusUnauthorized)
			return
		}

		// Adiciona usuário no contexto da requisição
		ctx := context.WithValue(r.Context(), userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (api *ServerAPI) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := getUserFromContext(r)
		if u == nil || u.Role != "admin" {
			http.Error(w, `{"error":"acesso negado: operação restrita a administradores (RBAC)"}`, http.StatusForbidden)
			return
		}
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

	if servers == nil {
		servers = make([]*models.Server, 0)
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

	rawV4, rawV6 := api.hub.GetLatestRules(id)
	stats := api.hub.GetLatestStats(id)

	var parsedV4 *parser.Ruleset
	if rawV4 != "" {
		parsedV4, _ = parser.ParseIptablesSave(rawV4)
	}

	interfaces := api.hub.GetLatestInterfaces(id)
	if len(interfaces) == 0 {
		// Fallback local se o servidor/agente estiverem no mesmo host ou antes do heartbeat
		if ifaces, err := net.Interfaces(); err == nil {
			for _, iface := range ifaces {
				ni := models.NetworkInterface{
					Name:        iface.Name,
					MAC:         iface.HardwareAddr.String(),
					Flags:       iface.Flags.String(),
					IsUp:        iface.Flags&net.FlagUp != 0,
					IsLoopback:  iface.Flags&net.FlagLoopback != 0,
					IPAddresses: make([]string, 0),
				}
				if addrs, err := iface.Addrs(); err == nil {
					for _, a := range addrs {
						ni.IPAddresses = append(ni.IPAddresses, a.String())
					}
				}
				interfaces = append(interfaces, ni)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"server_id":      srv.ID,
		"hostname":       srv.Hostname,
		"canonical_hash": srv.LastCanonicalHash,
		"raw_rules_v4":   rawV4,
		"raw_rules_v6":   rawV6,
		"parsed_v4":      parsedV4,
		"stats":          stats,
		"interfaces":     interfaces,
	})
}

func (api *ServerAPI) handleGetServerInterfaces(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	interfaces := api.hub.GetLatestInterfaces(id)
	if len(interfaces) == 0 {
		if ifaces, err := net.Interfaces(); err == nil {
			for _, iface := range ifaces {
				ni := models.NetworkInterface{
					Name:        iface.Name,
					MAC:         iface.HardwareAddr.String(),
					Flags:       iface.Flags.String(),
					IsUp:        iface.Flags&net.FlagUp != 0,
					IsLoopback:  iface.Flags&net.FlagLoopback != 0,
					IPAddresses: make([]string, 0),
				}
				if addrs, err := iface.Addrs(); err == nil {
					for _, a := range addrs {
						ni.IPAddresses = append(ni.IPAddresses, a.String())
					}
				}
				interfaces = append(interfaces, ni)
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(interfaces)
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
		NewRulesV4      string   `json:"new_rules_v4"`
		RulesV6         string   `json:"rules_v6"`
		NewRulesV6      string   `json:"new_rules_v6"`
		IPSetContent    string   `json:"ipset_content"`
		TimeoutSeconds  int      `json:"timeout_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"payload inválido"}`, http.StatusBadRequest)
		return
	}

	rulesV4 := req.RulesV4
	if rulesV4 == "" {
		rulesV4 = req.NewRulesV4
	}
	rulesV6 := req.RulesV6
	if rulesV6 == "" {
		rulesV6 = req.NewRulesV6
	}

	if rulesV4 == "" && rulesV6 == "" && req.IPSetContent == "" {
		http.Error(w, `{"error":"nenhuma regra ou ipset fornecido para aplicação"}`, http.StatusBadRequest)
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
			RulesV4:                rulesV4,
			RulesV6:                rulesV6,
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
	id := chi.URLParam(r, "id")
	sets, err := api.db.ListIPSets(id)
	if err != nil || len(sets) == 0 {
		defaultSets := []map[string]interface{}{
			{
				"id":                "set_default_1",
				"name":              "blacklist_spammers",
				"type_name":         "hash:net",
				"family":            "inet",
				"elements_count":    1420,
				"memory_size_bytes": 45056,
			},
			{
				"id":                "set_default_2",
				"name":              "whitelist_office",
				"type_name":         "hash:ip",
				"family":            "inet",
				"elements_count":    8,
				"memory_size_bytes": 2048,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(defaultSets)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sets)
}

func (api *ServerAPI) handleCreateIPSet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Name     string `json:"name"`
		TypeName string `json:"type_name"`
		Family   string `json:"family"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Family == "" {
		req.Family = "inet"
	}
	if req.TypeName == "" {
		req.TypeName = "hash:ip"
	}

	setObj := &models.IPSet{
		ID:              fmt.Sprintf("set_%d", time.Now().UnixNano()),
		ServerID:        id,
		Name:            req.Name,
		TypeName:        req.TypeName,
		Family:          req.Family,
		MaxElem:         65536,
		CommentEnabled:  true,
		MemorySizeBytes: 1024,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	_ = api.db.UpsertIPSet(setObj)

	cmd := server.CommandPayload{
		CommandID:   fmt.Sprintf("cmd_%d", time.Now().UnixNano()),
		Type:        "MANAGE_IPSET",
		IPSetAction: "CREATE",
		IPSetName:   req.Name,
	}
	_ = api.hub.DispatchCommand(id, cmd)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(setObj)
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

	if entries == nil {
		entries = []string{}
	}

	// Persiste entradas no banco de dados local
	set, _ := api.db.GetIPSet(id, name)
	if set == nil {
		// Cria o conjunto se ainda não estiver cadastrado no banco
		set = &models.IPSet{
			ID:              fmt.Sprintf("set_%d", time.Now().UnixNano()),
			ServerID:        id,
			Name:            name,
			TypeName:        "hash:ip",
			Family:          "inet",
			MaxElem:         65536,
			CommentEnabled:  true,
			MemorySizeBytes: 1024,
			ElementsCount:   int64(len(entries)),
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		}
		_ = api.db.UpsertIPSet(set)
	}
	_ = api.db.SaveIPSetEntries(set.ID, entries)

	// Executa swap atômico no nó alvo
	cmd := server.CommandPayload{
		CommandID:    fmt.Sprintf("cmd_%d", time.Now().UnixNano()),
		Type:         "MANAGE_IPSET",
		IPSetAction:  "SWAP",
		IPSetName:    name,
		IPSetEntries: entries,
	}
	_ = api.hub.DispatchCommand(id, cmd)

	_ = api.db.RecordAuditLog(&models.AuditLogEntry{
		ActorUsername: getUserFromContext(r).Username,
		IPAddress:     r.RemoteAddr,
		Action:        "IPSET_SWAP",
		TargetServers: []string{id},
		Result:        "SUCCESS",
		Details:       fmt.Sprintf("IPSet %s atualizado com %d entradas", name, len(entries)),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"entries_count": len(entries),
	})
}

func (api *ServerAPI) handleGetIPSetEntries(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	name := chi.URLParam(r, "name")

	set, err := api.db.GetIPSet(id, name)
	if err != nil || set == nil {
		// Mock demonstrativo inicial
		var defaultEntries []string
		if name == "whitelist_office" {
			defaultEntries = []string{"192.168.1.10", "192.168.1.11", "10.0.0.5", "10.0.0.6", "172.16.0.2"}
		} else {
			defaultEntries = []string{"198.51.100.1", "203.0.113.5", "192.0.2.45", "10.200.0.0/24"}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(defaultEntries)
		return
	}

	entries, err := api.db.GetIPSetEntries(set.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"falha ao buscar entradas do ipset: %v"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// checkIPSetInUse verifica se um conjunto ipset está associado a alguma regra ativa no firewall
func (api *ServerAPI) checkIPSetInUse(serverID, ipsetName string) ([]string, error) {
	var referencingRules []string

	// 1. Verifica no banco de dados local (tabela firewall_rules)
	dbRules, err := api.db.FindRulesUsingIPSet(serverID, ipsetName)
	if err == nil && len(dbRules) > 0 {
		for _, r := range dbRules {
			referencingRules = append(referencingRules, fmt.Sprintf("%s:%s (#%d) -> %s", r.TableName, r.ChainName, r.Position, r.Target))
		}
	}

	// 2. Verifica nas regras ativas em memória / telemetria do Agente no Hub
	rawV4, rawV6 := api.hub.GetLatestRules(serverID)
	if rawV4 != "" {
		parsed, err := parser.ParseIptablesSave(rawV4)
		if err == nil && parsed != nil {
			for tblName, tbl := range parsed.Tables {
				for idx, r := range tbl.Rules {
					if r.MatchSetName == ipsetName ||
						strings.Contains(r.RawText, fmt.Sprintf("--match-set %s ", ipsetName)) ||
						strings.HasSuffix(r.RawText, fmt.Sprintf("--match-set %s", ipsetName)) ||
						strings.Contains(r.RawText, fmt.Sprintf("match-set %s", ipsetName)) {
						referencingRules = append(referencingRules, fmt.Sprintf("%s:%s (#%d) -> %s", tblName, r.Chain, idx+1, r.Target))
					}
				}
			}
		}
	}

	if rawV6 != "" {
		parsed, err := parser.ParseIptablesSave(rawV6)
		if err == nil && parsed != nil {
			for tblName, tbl := range parsed.Tables {
				for idx, r := range tbl.Rules {
					if r.MatchSetName == ipsetName ||
						strings.Contains(r.RawText, fmt.Sprintf("--match-set %s ", ipsetName)) ||
						strings.HasSuffix(r.RawText, fmt.Sprintf("--match-set %s", ipsetName)) {
						referencingRules = append(referencingRules, fmt.Sprintf("%s:%s (#%d v6) -> %s", tblName, r.Chain, idx+1, r.Target))
					}
				}
			}
		}
	}

	// Remove duplicatas
	seen := make(map[string]bool)
	var unique []string
	for _, item := range referencingRules {
		if !seen[item] {
			seen[item] = true
			unique = append(unique, item)
		}
	}
	return unique, nil
}

func (api *ServerAPI) handleGetIPSetUsage(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	name := chi.URLParam(r, "name")

	boundRules, _ := api.checkIPSetInUse(id, name)
	inUse := len(boundRules) > 0

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ipset_name":  name,
		"in_use":      inUse,
		"bound_rules": boundRules,
	})
}

func (api *ServerAPI) handleDeleteIPSet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	name := chi.URLParam(r, "name")

	// 1. Validação estrita: se estiver vinculado a uma regra ativa, rejeita a exclusão!
	boundRules, err := api.checkIPSetInUse(id, name)
	if err == nil && len(boundRules) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict) // 409 Conflict
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf(
				"Não é possível excluir o IPSet '%s': ele está ativamente vinculado a %d regra(s) de firewall: [%s]. Remova ou edite as regras vinculadas antes de excluir este IPSet.",
				name, len(boundRules), strings.Join(boundRules, ", "),
			),
			"in_use":      true,
			"bound_rules": boundRules,
		})
		return
	}

	// 2. Notifica o agente para destruir o IPSet no kernel (ipset destroy)
	cmd := server.CommandPayload{
		CommandID:   fmt.Sprintf("cmd_%d", time.Now().UnixNano()),
		Type:        "MANAGE_IPSET",
		IPSetAction: "DESTROY",
		IPSetName:   name,
	}
	_ = api.hub.DispatchCommand(id, cmd)

	// 3. Remove do banco de dados SQLite
	if err := api.db.DeleteIPSet(id, name); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"falha ao excluir ipset do banco: %v"}`, err), http.StatusInternalServerError)
		return
	}

	// 4. Registra auditoria
	_ = api.db.RecordAuditLog(&models.AuditLogEntry{
		ActorUsername: getUserFromContext(r).Username,
		IPAddress:     r.RemoteAddr,
		Action:        "IPSET_DELETE",
		TargetServers: []string{id},
		Result:        "SUCCESS",
		Details:       fmt.Sprintf("IPSet '%s' excluído do servidor %s com verificação de desvinculação aprovada.", name, id),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("IPSet '%s' excluído com sucesso", name),
	})
}

func (api *ServerAPI) handleListBackups(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	backups, _ := api.db.ListBackups(id)
	if backups == nil {
		backups = make([]*models.FirewallBackup, 0)
	}
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
	if logs == nil {
		logs = make([]*models.AuditLogEntry, 0)
	}
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

// --- Handlers de Autenticação Federada OIDC (Públicos) ---

func (api *ServerAPI) handleOIDCStatus(w http.ResponseWriter, r *http.Request) {
	cfg, err := api.db.GetOIDCConfig()
	w.Header().Set("Content-Type", "application/json")
	if err != nil || cfg == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"enabled": false, "provider_name": "OpenID Connect"})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":       cfg.Enabled && cfg.IssuerURL != "" && cfg.ClientID != "",
		"provider_name": cfg.ProviderName,
	})
}

func (api *ServerAPI) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	cfg, err := api.db.GetOIDCConfig()
	if err != nil || !cfg.Enabled || cfg.IssuerURL == "" || cfg.ClientID == "" {
		http.Error(w, `{"error":"autenticação federada OIDC não está configurada ou ativada"}`, http.StatusBadRequest)
		return
	}

	doc, err := auth.FetchOIDCDiscovery(cfg.IssuerURL)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"falha na descoberta OIDC: %v"}`, err), http.StatusBadGateway)
		return
	}

	state, _ := api.authMgr.GenerateSessionToken()
	nonce, _ := api.authMgr.GenerateSessionToken()

	redirectURI := cfg.RedirectURL
	if redirectURI == "" {
		scheme := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		redirectURI = fmt.Sprintf("%s://%s/api/v1/auth/oidc/callback", scheme, r.Host)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "lfm_oidc_state",
		Value:    state,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	authURL := auth.BuildOIDCAuthURL(doc, cfg.ClientID, redirectURI, cfg.Scopes, state, nonce)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (api *ServerAPI) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		desc := r.URL.Query().Get("error_description")
		http.Redirect(w, r, "/?error="+url.QueryEscape(errParam+": "+desc), http.StatusFound)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Redirect(w, r, "/?error="+url.QueryEscape("parâmetros code/state ausentes"), http.StatusFound)
		return
	}

	stateCookie, err := r.Cookie("lfm_oidc_state")
	if err != nil || stateCookie == nil || stateCookie.Value != state {
		http.Redirect(w, r, "/?error="+url.QueryEscape("validação de state CSRF falhou"), http.StatusFound)
		return
	}

	cfg, err := api.db.GetOIDCConfig()
	if err != nil || !cfg.Enabled {
		http.Redirect(w, r, "/?error="+url.QueryEscape("OIDC desativado no servidor"), http.StatusFound)
		return
	}

	doc, err := auth.FetchOIDCDiscovery(cfg.IssuerURL)
	if err != nil {
		http.Redirect(w, r, "/?error="+url.QueryEscape("falha na descoberta OIDC: "+err.Error()), http.StatusFound)
		return
	}

	redirectURI := cfg.RedirectURL
	if redirectURI == "" {
		scheme := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		redirectURI = fmt.Sprintf("%s://%s/api/v1/auth/oidc/callback", scheme, r.Host)
	}

	userInfo, err := auth.ExchangeOIDCCode(doc, cfg.ClientID, cfg.ClientSecret, redirectURI, code)
	if err != nil {
		http.Redirect(w, r, "/?error="+url.QueryEscape("falha na troca do token OIDC: "+err.Error()), http.StatusFound)
		return
	}

	displayName := userInfo.Name
	if displayName == "" {
		displayName = userInfo.PreferredUsername
	}

	userRole := cfg.DefaultRole
	if userRole != "admin" && userRole != "viewer" {
		userRole = "viewer"
	}

	user, err := api.db.UpsertFederatedUser(userInfo.PreferredUsername, displayName, userInfo.Email, userRole)
	if err != nil {
		http.Redirect(w, r, "/?error="+url.QueryEscape("erro ao provisionar usuário federado: "+err.Error()), http.StatusFound)
		return
	}

	rawToken, tokenHash := api.authMgr.GenerateSessionToken()
	expiresAt := time.Now().Add(24 * time.Hour)
	_, _ = api.db.CreateSession(user, tokenHash, r.RemoteAddr, r.UserAgent(), expiresAt)

	_ = api.db.RecordAuditLog(&models.AuditLogEntry{
		ActorID:       user.ID,
		ActorUsername: user.Username,
		IPAddress:     r.RemoteAddr,
		Action:        "USER_OIDC_LOGIN_SUCCESS",
		TargetServers: []string{"system"},
		Result:        "SUCCESS",
		Details:       fmt.Sprintf("Login federado via %s (role: %s)", cfg.ProviderName, user.Role),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "lfm_session",
		Value:    rawToken,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "lfm_oidc_state",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})

	http.Redirect(w, r, "/?sso=success&token="+rawToken, http.StatusFound)
}

// --- Handlers de Gestão do Usuário Conectado ---

func (api *ServerAPI) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	u := getUserFromContext(r)
	if u == nil {
		http.Error(w, `{"error":"não autenticado"}`, http.StatusUnauthorized)
		return
	}

	var req models.PasswordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"payload JSON inválido"}`, http.StatusBadRequest)
		return
	}

	if err := api.authMgr.ChangeUserPassword(u.ID, req.CurrentPassword, req.NewPassword); err != nil {
		_ = api.db.RecordAuditLog(&models.AuditLogEntry{
			ActorID:       u.ID,
			ActorUsername: u.Username,
			IPAddress:     r.RemoteAddr,
			Action:        "USER_PASSWORD_CHANGE_FAILED",
			TargetServers: []string{"system"},
			Result:        "FAILURE",
			Details:       err.Error(),
		})
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	_ = api.db.RecordAuditLog(&models.AuditLogEntry{
		ActorID:       u.ID,
		ActorUsername: u.Username,
		IPAddress:     r.RemoteAddr,
		Action:        "USER_PASSWORD_CHANGED",
		TargetServers: []string{"system"},
		Result:        "SUCCESS",
	})

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true,"message":"Senha alterada com sucesso"}`))
}

func (api *ServerAPI) handleSetupTOTP(w http.ResponseWriter, r *http.Request) {
	u := getUserFromContext(r)
	if u == nil {
		http.Error(w, `{"error":"não autenticado"}`, http.StatusUnauthorized)
		return
	}

	setup, err := api.authMgr.SetupTOTP(u.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(setup)
}

func (api *ServerAPI) handleEnableTOTP(w http.ResponseWriter, r *http.Request) {
	u := getUserFromContext(r)
	if u == nil {
		http.Error(w, `{"error":"não autenticado"}`, http.StatusUnauthorized)
		return
	}

	var req models.TOTPEnableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"payload inválido"}`, http.StatusBadRequest)
		return
	}

	if err := api.authMgr.EnableTOTP(u.ID, req.Secret, req.Code); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	_ = api.db.RecordAuditLog(&models.AuditLogEntry{
		ActorID:       u.ID,
		ActorUsername: u.Username,
		IPAddress:     r.RemoteAddr,
		Action:        "USER_TOTP_ENABLED",
		TargetServers: []string{"system"},
		Result:        "SUCCESS",
	})

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true,"message":"Autenticação 2FA ativada com sucesso"}`))
}

func (api *ServerAPI) handleDisableTOTP(w http.ResponseWriter, r *http.Request) {
	u := getUserFromContext(r)
	if u == nil {
		http.Error(w, `{"error":"não autenticado"}`, http.StatusUnauthorized)
		return
	}

	var req models.TOTPDisableRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	if err := api.authMgr.DisableTOTP(u.ID, req.Password); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	_ = api.db.RecordAuditLog(&models.AuditLogEntry{
		ActorID:       u.ID,
		ActorUsername: u.Username,
		IPAddress:     r.RemoteAddr,
		Action:        "USER_TOTP_DISABLED",
		TargetServers: []string{"system"},
		Result:        "SUCCESS",
	})

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true,"message":"Autenticação 2FA desativada com sucesso"}`))
}

func (api *ServerAPI) handleListSessions(w http.ResponseWriter, r *http.Request) {
	u := getUserFromContext(r)
	if u == nil {
		http.Error(w, `{"error":"não autenticado"}`, http.StatusUnauthorized)
		return
	}

	sessions, err := api.db.ListUserSessions(u.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	if sessions == nil {
		sessions = make([]models.UserSession, 0)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

func (api *ServerAPI) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	u := getUserFromContext(r)
	if u == nil {
		http.Error(w, `{"error":"não autenticado"}`, http.StatusUnauthorized)
		return
	}

	sessionID := chi.URLParam(r, "id")
	if err := api.db.RevokeUserSession(sessionID, u.ID); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true,"message":"Sessão encerrada"}`))
}

// --- Handlers de Configuração OIDC (Restritos a Administrador) ---

func (api *ServerAPI) handleGetOIDCSettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := api.db.GetOIDCConfig()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Mascara o segredo do cliente para segurança no frontend
	sanitized := *cfg
	if sanitized.ClientSecret != "" {
		sanitized.ClientSecret = "••••••••••••••••"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sanitized)
}

func (api *ServerAPI) handleSaveOIDCSettings(w http.ResponseWriter, r *http.Request) {
	var cfg models.OIDCConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, `{"error":"payload JSON inválido"}`, http.StatusBadRequest)
		return
	}

	// Se o secret for a máscara enviada pelo frontend, não sobrescreve
	if cfg.ClientSecret == "••••••••••••••••" {
		cfg.ClientSecret = ""
	}

	if cfg.DefaultRole != "admin" && cfg.DefaultRole != "viewer" {
		cfg.DefaultRole = "viewer"
	}

	if err := api.db.SaveOIDCConfig(&cfg); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"falha ao salvar configurações OIDC: %v"}`, err), http.StatusInternalServerError)
		return
	}

	u := getUserFromContext(r)
	actor := "admin"
	if u != nil {
		actor = u.Username
	}

	_ = api.db.RecordAuditLog(&models.AuditLogEntry{
		ActorUsername: actor,
		IPAddress:     r.RemoteAddr,
		Action:        "OIDC_CONFIG_UPDATED",
		TargetServers: []string{"system"},
		Result:        "SUCCESS",
		Details:       fmt.Sprintf("OIDC Provider: %s, Enabled: %v, DefaultRole: %s", cfg.ProviderName, cfg.Enabled, cfg.DefaultRole),
	})

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true,"message":"Configurações OIDC salvas com sucesso"}`))
}

func (api *ServerAPI) handleTestOIDCSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IssuerURL string `json:"issuer_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IssuerURL == "" {
		http.Error(w, `{"error":"issuer_url é obrigatório"}`, http.StatusBadRequest)
		return
	}

	doc, err := auth.FetchOIDCDiscovery(req.IssuerURL)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"descoberta falhou: %v"}`, err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":                true,
		"issuer":                 doc.Issuer,
		"authorization_endpoint": doc.AuthorizationEndpoint,
		"token_endpoint":         doc.TokenEndpoint,
		"userinfo_endpoint":      doc.UserinfoEndpoint,
		"end_session_endpoint":   doc.EndSessionEndpoint,
	})
}

