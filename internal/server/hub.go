package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"lnx-firewall-manager/internal/db"
	"lnx-firewall-manager/internal/models"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Configurado para permitir conexões de controle
	},
}

// AgentSession representa uma conexão ativa com um fw-agent
type AgentSession struct {
	ServerID       string
	Hostname       string
	Conn           *websocket.Conn
	ConnectedAt    time.Time
	LastSeenAt     time.Time
	LastRulesHash  string
	LastRulesV4    string
	LastRulesV6    string
	Interfaces     []models.NetworkInterface
	WriteMu        sync.Mutex
	PendingCommits map[string]time.Time // changeID -> timestamp
}

// Hub gerencia todas as conexões ativas com agentes e broadcast para o frontend
type Hub struct {
	mu           sync.RWMutex
	db           *db.DB
	agents       map[string]*AgentSession    // serverID -> session
	uiClients    map[*websocket.Conn]bool    // frontend WebSocket clients
	pendingQueue map[string][]CommandPayload // serverID -> fila de comandos offline
	latestStats  map[string][]models.RuleCounterSample // serverID -> amostras recentes
}

// CommandPayload representa um comando enviado pelo servidor para o agente
type CommandPayload struct {
	CommandID              string      `json:"command_id"`
	Type                   string      `json:"type"` // APPLY_RULES, CONFIRM_COMMIT, RESTORE_BACKUP, MANAGE_IPSET, RESET_COUNTERS, COLLECT_STATE
	ChangeID               string      `json:"change_id,omitempty"`
	RollbackTimeoutSeconds int         `json:"rollback_timeout_seconds,omitempty"`
	RulesV4                string      `json:"rules_v4,omitempty"`
	RulesV6                string      `json:"rules_v6,omitempty"`
	IPSetContent           string      `json:"ipset_content,omitempty"`
	IPSetAction            string      `json:"ipset_action,omitempty"`
	IPSetName              string      `json:"ipset_name,omitempty"`
	IPSetEntries           []string    `json:"ipset_entries,omitempty"`
	ExpiresAt              time.Time   `json:"expires_at"`
}

// AgentInboundMessage representa mensagens recebidas do agente
type AgentInboundMessage struct {
	Type          string                      `json:"type"` // HELLO, HEARTBEAT, TELEMETRY, CMD_RESULT, ROLLBACK_REPORT, DRIFT_ALERT
	ServerID      string                      `json:"server_id"`
	Hostname      string                      `json:"hostname,omitempty"`
	AgentVersion  string                      `json:"agent_version,omitempty"`
	OSDistro      string                      `json:"os_distro,omitempty"`
	KernelVersion string                      `json:"kernel_version,omitempty"`
	Backend       string                      `json:"backend,omitempty"`
	IPv6          bool                        `json:"ipv6,omitempty"`
	RulesHash     string                      `json:"rules_hash,omitempty"`
	CommandID     string                      `json:"command_id,omitempty"`
	Success       bool                        `json:"success,omitempty"`
	ErrorMessage  string                      `json:"error_message,omitempty"`
	RollbackReason string                     `json:"rollback_reason,omitempty"`
	Telemetry     []models.RuleCounterSample  `json:"telemetry,omitempty"`
	CurrentRulesV4 string                     `json:"current_rules_v4,omitempty"`
	CurrentRulesV6 string                     `json:"current_rules_v6,omitempty"`
	Interfaces     []models.NetworkInterface  `json:"interfaces,omitempty"`
}

// NewHub inicializa o hub de comunicação
func NewHub(database *db.DB) *Hub {
	h := &Hub{
		db:           database,
		agents:       make(map[string]*AgentSession),
		uiClients:    make(map[*websocket.Conn]bool),
		pendingQueue: make(map[string][]CommandPayload),
		latestStats:  make(map[string][]models.RuleCounterSample),
	}

	// Goroutine para checar expiração de heartbeats
	go h.heartbeatChecker()

	return h
}

// HandleAgentWebSocket trata a conexão de saída iniciada pelo fw-agent
func (h *Hub) HandleAgentWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[HUB] Erro no upgrade WebSocket de agente: %v", err)
		return
	}
	defer conn.Close()

	var session *AgentSession

	defer func() {
		if session != nil {
			h.unregisterAgent(session.ServerID)
		}
	}()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("[HUB] Conexão encerrada com agente (%s): %v", sessionInfo(session), err)
			break
		}

		var msg AgentInboundMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("[HUB] Payload inválido do agente: %v", err)
			continue
		}

		switch msg.Type {
		case "HELLO":
			session = h.handleHello(conn, &msg, r.RemoteAddr)
		case "HEARTBEAT":
			if session != nil {
				h.handleHeartbeat(session, &msg)
			}
		case "TELEMETRY":
			if session != nil {
				h.handleTelemetry(session, &msg)
			}
		case "CMD_RESULT":
			if session != nil {
				h.handleCmdResult(session, &msg)
			}
		case "ROLLBACK_REPORT":
			if session != nil {
				h.handleRollbackReport(session, &msg)
			}
		case "DRIFT_ALERT":
			if session != nil {
				h.handleDriftAlert(session, &msg)
			}
		}
	}
}

func sessionInfo(s *AgentSession) string {
	if s == nil {
		return "desconhecido"
	}
	return fmt.Sprintf("%s (%s)", s.Hostname, s.ServerID)
}

func (h *Hub) handleHello(conn *websocket.Conn, msg *AgentInboundMessage, remoteAddr string) *AgentSession {
	session := &AgentSession{
		ServerID:       msg.ServerID,
		Hostname:       msg.Hostname,
		Conn:           conn,
		ConnectedAt:    time.Now(),
		LastSeenAt:     time.Now(),
		LastRulesHash:  msg.RulesHash,
		LastRulesV4:    msg.CurrentRulesV4,
		LastRulesV6:    msg.CurrentRulesV6,
		Interfaces:     msg.Interfaces,
		PendingCommits: make(map[string]time.Time),
	}

	h.mu.Lock()
	h.agents[msg.ServerID] = session
	queue := h.pendingQueue[msg.ServerID]
	delete(h.pendingQueue, msg.ServerID)
	h.mu.Unlock()

	// Atualiza banco de dados
	srv := &models.Server{
		ID:                msg.ServerID,
		Hostname:          msg.Hostname,
		IPAddress:         remoteAddr,
		Status:            "online",
		AgentVersion:      msg.AgentVersion,
		OSDistro:          msg.OSDistro,
		KernelVersion:     msg.KernelVersion,
		IptablesBackend:   msg.Backend,
		IPv6Supported:     msg.IPv6,
		LastCanonicalHash: msg.RulesHash,
	}
	_ = h.db.UpsertServer(srv)

	log.Printf("[HUB] Agente conectado e autenticado: %s (ID: %s, OS: %s, Backend: %s)", msg.Hostname, msg.ServerID, msg.OSDistro, msg.Backend)

	// Responde ACK com configurações
	ack := map[string]interface{}{
		"type":                  "HELLO_ACK",
		"accepted":              true,
		"heartbeat_interval_sec": 10,
		"telemetry_interval_sec": 10,
	}
	session.WriteMu.Lock()
	_ = conn.WriteJSON(ack)

	// Se houver comandos na fila offline, dispara
	for _, cmd := range queue {
		if time.Now().Before(cmd.ExpiresAt) {
			_ = conn.WriteJSON(cmd)
		}
	}
	session.WriteMu.Unlock()

	h.broadcastToUI(map[string]interface{}{
		"event":     "server_online",
		"server_id": msg.ServerID,
		"hostname":  msg.Hostname,
	})

	return session
}

func (h *Hub) handleHeartbeat(s *AgentSession, msg *AgentInboundMessage) {
	h.mu.Lock()
	s.LastSeenAt = time.Now()
	s.LastRulesHash = msg.RulesHash
	if msg.CurrentRulesV4 != "" {
		s.LastRulesV4 = msg.CurrentRulesV4
	}
	if msg.CurrentRulesV6 != "" {
		s.LastRulesV6 = msg.CurrentRulesV6
	}
	if len(msg.Interfaces) > 0 {
		s.Interfaces = msg.Interfaces
	}
	h.mu.Unlock()

	_ = h.db.UpdateServerStatus(s.ServerID, "online")
}

func (h *Hub) handleTelemetry(s *AgentSession, msg *AgentInboundMessage) {
	h.mu.Lock()
	s.LastSeenAt = time.Now()
	h.latestStats[s.ServerID] = msg.Telemetry
	h.mu.Unlock()

	// Notifica UI em tempo real
	h.broadcastToUI(map[string]interface{}{
		"event":     "telemetry_update",
		"server_id": s.ServerID,
		"samples":   msg.Telemetry,
	})
}

func (h *Hub) handleCmdResult(s *AgentSession, msg *AgentInboundMessage) {
	log.Printf("[HUB] Resultado de comando recebido de %s: CmdID=%s, Sucesso=%v, Erro=%s", s.Hostname, msg.CommandID, msg.Success, msg.ErrorMessage)
	if msg.CurrentRulesV4 != "" {
		h.mu.Lock()
		s.LastRulesV4 = msg.CurrentRulesV4
		if msg.CurrentRulesV6 != "" {
			s.LastRulesV6 = msg.CurrentRulesV6
		}
		if msg.RulesHash != "" {
			s.LastRulesHash = msg.RulesHash
		}
		h.mu.Unlock()

		if srv, err := h.db.GetServerByID(s.ServerID); err == nil && srv != nil {
			if msg.RulesHash != "" {
				srv.LastCanonicalHash = msg.RulesHash
			}
			_ = h.db.UpsertServer(srv)
		}
	}

	h.broadcastToUI(map[string]interface{}{
		"event":         "command_result",
		"server_id":     s.ServerID,
		"command_id":    msg.CommandID,
		"success":       msg.Success,
		"error_message": msg.ErrorMessage,
	})
	h.broadcastToUI(map[string]interface{}{
		"event":     "rules_updated",
		"server_id": s.ServerID,
	})
}

func (h *Hub) handleRollbackReport(s *AgentSession, msg *AgentInboundMessage) {
	log.Printf("[HUB] ALERTA DE ROLLBACK de %s: Regra revertida automaticamente! Motivo: %s", s.Hostname, msg.RollbackReason)

	if msg.CurrentRulesV4 != "" {
		h.mu.Lock()
		s.LastRulesV4 = msg.CurrentRulesV4
		if msg.CurrentRulesV6 != "" {
			s.LastRulesV6 = msg.CurrentRulesV6
		}
		if msg.RulesHash != "" {
			s.LastRulesHash = msg.RulesHash
		}
		h.mu.Unlock()
	}

	// Registra auditoria
	_ = h.db.RecordAuditLog(&models.AuditLogEntry{
		ActorID:       "system_safety",
		ActorUsername: "AgentAutoRollback",
		IPAddress:     "local",
		Action:        "ROLLBACK_AUTO",
		TargetServers: []string{s.ServerID},
		Result:        "REVERTED",
		Details:       fmt.Sprintf("Auto-rollback disparado no servidor %s. Motivo: %s", s.Hostname, msg.RollbackReason),
	})

	h.broadcastToUI(map[string]interface{}{
		"event":     "safety_rollback_triggered",
		"server_id": s.ServerID,
		"hostname":  s.Hostname,
		"reason":    msg.RollbackReason,
	})
	h.broadcastToUI(map[string]interface{}{
		"event":     "rules_updated",
		"server_id": s.ServerID,
	})
}

func (h *Hub) handleDriftAlert(s *AgentSession, msg *AgentInboundMessage) {
	log.Printf("[HUB] ALERTA: Drift detectado no host %s!", s.Hostname)
	srv, err := h.db.GetServerByID(s.ServerID)
	if err == nil {
		srv.DriftDetected = true
		_ = h.db.UpsertServer(srv)
	}

	h.broadcastToUI(map[string]interface{}{
		"event":     "drift_detected",
		"server_id": s.ServerID,
		"hostname":  s.Hostname,
	})
}

func (h *Hub) unregisterAgent(serverID string) {
	h.mu.Lock()
	delete(h.agents, serverID)
	h.mu.Unlock()

	_ = h.db.UpdateServerStatus(serverID, "offline")
	h.broadcastToUI(map[string]interface{}{
		"event":     "server_offline",
		"server_id": serverID,
	})
	log.Printf("[HUB] Agente desconectado: %s", serverID)
}

// DispatchCommand envia um comando para um agente online ou enfileira se offline
func (h *Hub) DispatchCommand(serverID string, cmd CommandPayload) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cmd.ExpiresAt.IsZero() {
		cmd.ExpiresAt = time.Now().Add(1 * time.Hour)
	}

	session, online := h.agents[serverID]
	if !online || session.Conn == nil {
		// Enfileira para quando o agente conectar
		h.pendingQueue[serverID] = append(h.pendingQueue[serverID], cmd)
		return fmt.Errorf("agente %s está offline. Comando enfileirado para execução quando conectar", serverID)
	}

	session.WriteMu.Lock()
	defer session.WriteMu.Unlock()

	if err := session.Conn.WriteJSON(cmd); err != nil {
		return fmt.Errorf("falha no envio de comando: %v", err)
	}

	return nil
}

// BroadcastToUI envia evento para todas as abas web abertas
func (h *Hub) broadcastToUI(payload interface{}) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.uiClients {
		_ = client.WriteJSON(payload)
	}
}

// HandleUIWebSocket registra conexões WebSocket vindas do frontend SPA
func (h *Hub) HandleUIWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	h.mu.Lock()
	h.uiClients[conn] = true
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.uiClients, conn)
		h.mu.Unlock()
		conn.Close()
	}()

	// Mantém lendo pings/pongs
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

// GetLatestStats retorna as estatísticas em tempo real em memória
func (h *Hub) GetLatestStats(serverID string) []models.RuleCounterSample {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.latestStats[serverID]
}

// IsOnline verifica se o servidor está conectado
func (h *Hub) IsOnline(serverID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.agents[serverID]
	return ok
}

// GetLatestRules retorna os últimos dumps de regras v4 e v6 recebidos do agente
func (h *Hub) GetLatestRules(serverID string) (string, string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	sess, ok := h.agents[serverID]
	if !ok || sess == nil {
		return "", ""
	}
	return sess.LastRulesV4, sess.LastRulesV6
}

// GetLatestInterfaces retorna as interfaces de rede do servidor
func (h *Hub) GetLatestInterfaces(serverID string) []models.NetworkInterface {
	h.mu.RLock()
	defer h.mu.RUnlock()
	sess, ok := h.agents[serverID]
	if !ok || sess == nil || len(sess.Interfaces) == 0 {
		return nil
	}
	return sess.Interfaces
}

func (h *Hub) heartbeatChecker() {
	ticker := time.NewTicker(15 * time.Second)
	for range ticker.C {
		h.mu.Lock()
		now := time.Now()
		for id, session := range h.agents {
			if now.Sub(session.LastSeenAt) > 45*time.Second {
				log.Printf("[HUB] Timeout de heartbeat para agente %s. Marcando offline.", session.Hostname)
				_ = session.Conn.Close()
				delete(h.agents, id)
				_ = h.db.UpdateServerStatus(id, "offline")
			}
		}
		h.mu.Unlock()
	}
}

// DiffRulesets calcula a diferença textual unificada entre dois rulesets
func DiffRulesets(oldV4, newV4 string) string {
	oldLines := strings.Split(strings.TrimSpace(oldV4), "\n")
	newLines := strings.Split(strings.TrimSpace(newV4), "\n")

	oldSet := make(map[string]bool)
	for _, l := range oldLines {
		if l != "" && !strings.HasPrefix(l, "#") {
			oldSet[l] = true
		}
	}

	newSet := make(map[string]bool)
	for _, l := range newLines {
		if l != "" && !strings.HasPrefix(l, "#") {
			newSet[l] = true
		}
	}

	var diff strings.Builder
	for _, l := range oldLines {
		if l != "" && !strings.HasPrefix(l, "#") && !newSet[l] {
			diff.WriteString(fmt.Sprintf("- %s\n", l))
		}
	}
	for _, l := range newLines {
		if l != "" && !strings.HasPrefix(l, "#") && !oldSet[l] {
			diff.WriteString(fmt.Sprintf("+ %s\n", l))
		}
	}

	if diff.Len() == 0 {
		return "Nenhuma alteração detectada."
	}
	return diff.String()
}
