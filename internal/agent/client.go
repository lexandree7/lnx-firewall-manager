package agent

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"lnx-firewall-manager/internal/models"
	"lnx-firewall-manager/internal/parser"
)

// AgentClient representa o daemon cliente do fw-agent
type AgentClient struct {
	mu              sync.Mutex
	writeMu         sync.Mutex
	serverURL       string
	agentID         string
	token           string
	executor        *Executor
	safety          *SafetyManager
	ipsetMgr        *IPSetManager
	conn            *websocket.Conn
	tlsConfig       *tls.Config
	stopCh          chan struct{}
	lastCounters    map[string]models.RuleCounterSample // "table:chain:pos" -> amostra
	lastAppliedHash string
}

// NewAgentClient inicializa o cliente gerenciado
func NewAgentClient(serverURL, agentID, stateDir string, tlsConfig *tls.Config) *AgentClient {
	exec := NewExecutor()
	ipset := NewIPSetManager()

	client := &AgentClient{
		serverURL:    serverURL,
		agentID:      agentID,
		executor:     exec,
		ipsetMgr:     ipset,
		tlsConfig:    tlsConfig,
		stopCh:       make(chan struct{}),
		lastCounters: make(map[string]models.RuleCounterSample),
	}

	client.safety = NewSafetyManager(exec, stateDir, client.onRollbackExecuted)

	return client
}

func (c *AgentClient) writeJSON(v interface{}) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("conexão websocket indisponível")
	}

	return conn.WriteJSON(v)
}

func (c *AgentClient) onRollbackExecuted(changeID, reason string) {
	msg := map[string]interface{}{
		"type":            "ROLLBACK_REPORT",
		"server_id":       c.agentID,
		"command_id":      changeID,
		"rollback_reason": reason,
	}
	_ = c.writeJSON(msg)
}

// Run inicia o loop de conexão contínua com reconexão automática e backoff
func (c *AgentClient) Run() {
	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		err := c.connectAndListen()
		if err != nil {
			log.Printf("[AGENT] Desconectado do servidor: %v. Reconectando em %v...", err, backoff)
		}

		// Backoff com jitter aleatório de +/- 20%
		jitter := time.Duration(float64(backoff) * (0.8 + 0.4*rand.Float64()))
		time.Sleep(jitter)

		backoff = time.Duration(float64(backoff) * 1.5)
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// Stop finaliza o agente
func (c *AgentClient) Stop() {
	close(c.stopCh)
	c.mu.Lock()
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.mu.Unlock()
}

func (c *AgentClient) connectAndListen() error {
	u, err := url.Parse(c.serverURL)
	if err != nil {
		return err
	}

	wsScheme := "ws"
	if u.Scheme == "https" || u.Scheme == "wss" {
		wsScheme = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s/api/v1/agent/ws", wsScheme, u.Host)

	dialer := websocket.Dialer{
		TLSClientConfig:  c.tlsConfig,
		HandshakeTimeout: 10 * time.Second,
	}
	if dialer.TLSClientConfig == nil && wsScheme == "wss" {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.conn = nil
		c.mu.Unlock()
		conn.Close()
	}()

	// 1. Envia HELLO inicial
	sysInfo, _ := c.executor.CollectSystemInfo()
	rawV4, _ := c.executor.DumpIptables(false)
	ruleset, _ := parser.ParseIptablesSave(rawV4)
	var rulesHash string
	if ruleset != nil {
		rulesHash = ruleset.CanonicalHash()
	}
	c.lastAppliedHash = rulesHash

	hello := map[string]interface{}{
		"type":           "HELLO",
		"server_id":      c.agentID,
		"hostname":       sysInfo.Hostname,
		"agent_version":  "1.0.0",
		"os_distro":      sysInfo.OSDistro,
		"kernel_version": sysInfo.KernelVersion,
		"backend":        sysInfo.IptablesBackend,
		"ipv6":           sysInfo.IPv6Supported,
		"rules_hash":     rulesHash,
	}

	if err := c.writeJSON(hello); err != nil {
		return err
	}

	// Inicia goroutines periódicas
	tickerDone := make(chan struct{})
	defer close(tickerDone)

	go c.heartbeatLoop(tickerDone)
	go c.telemetryLoop(tickerDone)

	// Loop de recebimento de comandos
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			return err
		}

		var cmd map[string]interface{}
		if err := json.Unmarshal(message, &cmd); err != nil {
			continue
		}

		c.handleServerCommand(cmd)
	}
}

func (c *AgentClient) heartbeatLoop(done <-chan struct{}) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			rawV4, _ := c.executor.DumpIptables(false)
			rs, _ := parser.ParseIptablesSave(rawV4)
			var hash string
			if rs != nil {
				hash = rs.CanonicalHash()
			}

			// Se houver divergência entre hash aplicado e hash atual no kernel -> Drift!
			if c.lastAppliedHash != "" && hash != "" && hash != c.lastAppliedHash {
				_ = c.writeJSON(map[string]interface{}{
					"type":       "DRIFT_ALERT",
					"server_id":  c.agentID,
					"rules_hash": hash,
				})
			}

			hb := map[string]interface{}{
				"type":       "HEARTBEAT",
				"server_id":  c.agentID,
				"rules_hash": hash,
			}
			if err := c.writeJSON(hb); err != nil {
				return
			}
		}
	}
}

func (c *AgentClient) telemetryLoop(done <-chan struct{}) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			rawV4, err := c.executor.DumpIptables(false)
			if err != nil {
				continue
			}

			rs, err := parser.ParseIptablesSave(rawV4)
			if err != nil || rs == nil {
				continue
			}

			var samples []models.RuleCounterSample
			c.mu.Lock()
			for tblName, tbl := range rs.Tables {
				for _, r := range tbl.Rules {
					key := fmt.Sprintf("%s:%s:%d", tblName, r.Chain, r.Position)
					prev, hasPrev := c.lastCounters[key]

					var deltaPkts, deltaBytes uint64
					pkts := uint64(r.PacketCounter)
					bytes := uint64(r.ByteCounter)

					if hasPrev && pkts >= prev.Packets && bytes >= prev.Bytes {
						deltaPkts = pkts - prev.Packets
						deltaBytes = bytes - prev.Bytes
					}

					pps := float64(deltaPkts) / 10.0
					bps := float64(deltaBytes*8) / 10.0

					sample := models.RuleCounterSample{
						TableName:    tblName,
						ChainName:    r.Chain,
						RulePosition: r.Position,
						RuleComment:  r.Comment,
						Packets:      pkts,
						Bytes:        bytes,
						DeltaPackets: deltaPkts,
						DeltaBytes:   deltaBytes,
						RatePPS:      pps,
						RateBPS:      bps,
					}
					c.lastCounters[key] = sample
					samples = append(samples, sample)
				}
			}
			c.mu.Unlock()

			msg := map[string]interface{}{
				"type":      "TELEMETRY",
				"server_id": c.agentID,
				"telemetry": samples,
			}
			_ = c.writeJSON(msg)
		}
	}
}

func (c *AgentClient) handleServerCommand(cmd map[string]interface{}) {
	cmdType, _ := cmd["type"].(string)
	cmdID, _ := cmd["command_id"].(string)
	changeID, _ := cmd["change_id"].(string)

	var errResult error

	switch cmdType {
	case "APPLY_RULES":
		v4, _ := cmd["rules_v4"].(string)
		v6, _ := cmd["rules_v6"].(string)
		ipset, _ := cmd["ipset_content"].(string)
		timeoutSec := 30
		if t, ok := cmd["rollback_timeout_seconds"].(float64); ok && t > 0 {
			timeoutSec = int(t)
		}

		errResult = c.safety.PrepareAndApply(changeID, v4, v6, ipset, timeoutSec)
		if errResult == nil {
			if rs, err := parser.ParseIptablesSave(v4); err == nil && rs != nil {
				c.lastAppliedHash = rs.CanonicalHash()
			}
		}

	case "CONFIRM_COMMIT":
		errResult = c.safety.ConfirmCommit(changeID)

	case "RESTORE_BACKUP":
		v4, _ := cmd["rules_v4"].(string)
		v6, _ := cmd["rules_v6"].(string)
		ipset, _ := cmd["ipset_content"].(string)
		errResult = c.safety.PrepareAndApply(changeID, v4, v6, ipset, 30)

	case "MANAGE_IPSET":
		action, _ := cmd["ipset_action"].(string)
		setName, _ := cmd["ipset_name"].(string)
		entriesRaw, _ := cmd["ipset_entries"].([]interface{})
		var entries []string
		for _, e := range entriesRaw {
			if s, ok := e.(string); ok {
				entries = append(entries, s)
			}
		}

		switch action {
		case "SWAP":
			errResult = c.ipsetMgr.AtomicSwapEntries(setName, "hash:ip", "inet", 65536, entries)
		case "FLUSH":
			errResult = c.ipsetMgr.FlushSet(setName)
		case "DESTROY":
			errResult = c.ipsetMgr.DestroySet(setName)
		default:
			errResult = fmt.Errorf("ação ipset desconhecida: %s", action)
		}

	case "COLLECT_STATE":
		v4, _ := c.executor.DumpIptables(false)
		v6, _ := c.executor.DumpIptables(true)
		_ = c.writeJSON(map[string]interface{}{
			"type":             "CMD_RESULT",
			"command_id":       cmdID,
			"success":          true,
			"current_rules_v4": v4,
			"current_rules_v6": v6,
		})
		return
	}

	errMsg := ""
	success := true
	if errResult != nil {
		success = false
		errMsg = errResult.Error()
	}

	resp := map[string]interface{}{
		"type":          "CMD_RESULT",
		"command_id":    cmdID,
		"server_id":     c.agentID,
		"success":       success,
		"error_message": errMsg,
	}
	_ = c.writeJSON(resp)
}
