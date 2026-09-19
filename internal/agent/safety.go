package agent

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SafetyManager gerencia o mecanismo de proteção contra lockout com reversão automática
type SafetyManager struct {
	mu           sync.Mutex
	executor     *Executor
	stateDir     string
	activeTimer  *time.Timer
	pendingID    string
	prevV4       string
	prevV6       string
	prevIPSet    string
	onRollbackFn func(changeID string, reason string)
}

// NewSafetyManager inicializa o gerenciador de proteção
func NewSafetyManager(executor *Executor, stateDir string, onRollback func(changeID, reason string)) *SafetyManager {
	if stateDir == "" {
		stateDir = "/var/lib/fw-agent"
	}
	_ = os.MkdirAll(stateDir, 0700)

	sm := &SafetyManager{
		executor:     executor,
		stateDir:     stateDir,
		onRollbackFn: onRollback,
	}

	// Verifica se houve reinicialização abrupta com lock pendente
	sm.CheckStartupRecovery()

	return sm
}

// CheckStartupRecovery verifica se havia uma transação pendente antes de um reboot
func (sm *SafetyManager) CheckStartupRecovery() {
	lockFile := filepath.Join(sm.stateDir, "rollback.lock")
	if _, err := os.Stat(lockFile); err == nil {
		log.Printf("[SAFETY] ATENÇÃO: Detectado lock de rollback não confirmado antes do reinício! Restaurando estado seguro...")
		sm.ExecuteRollback("REBOOT_DURING_PENDING_CONFIRMATION")
	}
}

// PrepareAndApply aplica novas regras com backup prévio e timer de reversão automática
func (sm *SafetyManager) PrepareAndApply(changeID string, newV4, newV6, newIPSet string, timeoutSeconds int) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 1. Cancela timer anterior se existente
	if sm.activeTimer != nil {
		sm.activeTimer.Stop()
		sm.activeTimer = nil
	}

	// 2. Tira snapshot completo do estado atual (v4, v6, ipset)
	curV4, _ := sm.executor.DumpIptables(false)
	curV6, _ := sm.executor.DumpIptables(true)
	curIPSet, _ := sm.executor.DumpIPSet()

	sm.pendingID = changeID
	sm.prevV4 = curV4
	sm.prevV6 = curV6
	sm.prevIPSet = curIPSet

	// 3. Grava arquivos de recuperação em disco
	lockFile := filepath.Join(sm.stateDir, "rollback.lock")
	_ = os.WriteFile(lockFile, []byte(fmt.Sprintf("%s\n%d", changeID, time.Now().Unix())), 0600)
	_ = os.WriteFile(filepath.Join(sm.stateDir, "backup_recovery.v4"), []byte(curV4), 0600)
	if curV6 != "" {
		_ = os.WriteFile(filepath.Join(sm.stateDir, "backup_recovery.v6"), []byte(curV6), 0600)
	}
	if curIPSet != "" {
		_ = os.WriteFile(filepath.Join(sm.stateDir, "backup_recovery.ipset"), []byte(curIPSet), 0600)
	}

	// 4. Aplica ipset primeiro se fornecido
	if newIPSet != "" {
		if err := sm.executor.RestoreIPSet(newIPSet); err != nil {
			sm.cleanupLockFiles()
			return fmt.Errorf("falha ao aplicar ipset: %v", err)
		}
	}

	// 5. Aplica novas regras de iptables
	if newV4 != "" {
		if err := sm.executor.RestoreIptables(newV4, false, false); err != nil {
			// Falhou ao aplicar, restaura imediatamente
			sm.doRestoreState(curV4, curV6, curIPSet)
			sm.cleanupLockFiles()
			return fmt.Errorf("falha ao aplicar iptables v4: %v (estado revertido)", err)
		}
	}

	if newV6 != "" {
		if err := sm.executor.RestoreIptables(newV6, true, false); err != nil {
			sm.doRestoreState(curV4, curV6, curIPSet)
			sm.cleanupLockFiles()
			return fmt.Errorf("falha ao aplicar iptables v6: %v (estado revertido)", err)
		}
	}

	// 6. Inicia o Timer de Rollback Local
	if timeoutSeconds <= 0 {
		timeoutSeconds = 30 // Padrão de 30 segundos
	}

	log.Printf("[SAFETY] Regras aplicadas com sucesso (ChangeID: %s). Aguardando confirmação em até %d segundos...", changeID, timeoutSeconds)

	sm.activeTimer = time.AfterFunc(time.Duration(timeoutSeconds)*time.Second, func() {
		log.Printf("[SAFETY] ALERTA: Tempo de confirmação expirou para ChangeID %s! Executando auto-rollback...", changeID)
		sm.ExecuteRollback("CONFIRMATION_TIMEOUT_EXPIRED")
	})

	return nil
}

// ConfirmCommit confirma a permanência definitiva das regras
func (sm *SafetyManager) ConfirmCommit(changeID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.pendingID != "" && changeID != "" && sm.pendingID != changeID {
		return fmt.Errorf("ID de confirmação divergente: esperado %s, recebido %s", sm.pendingID, changeID)
	}

	if sm.activeTimer != nil {
		sm.activeTimer.Stop()
		sm.activeTimer = nil
	}

	// Persiste o estado confirmado no disco do host
	activeV4, _ := sm.executor.DumpIptables(false)
	activeV6, _ := sm.executor.DumpIptables(true)
	_ = sm.executor.SavePersistent(activeV4, activeV6)

	sm.cleanupLockFiles()
	log.Printf("[SAFETY] Commit confirmado com sucesso (ChangeID: %s). Regras persistidas no host.", sm.pendingID)
	sm.pendingID = ""

	return nil
}

// ExecuteRollback restaura o estado anterior ao aplicar a alteração
func (sm *SafetyManager) ExecuteRollback(reason string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.activeTimer != nil {
		sm.activeTimer.Stop()
		sm.activeTimer = nil
	}

	changeID := sm.pendingID
	log.Printf("[SAFETY] Revertendo regras para o estado anterior. Motivo: %s", reason)

	// Lê de memória ou dos arquivos de recuperação
	v4 := sm.prevV4
	v6 := sm.prevV6
	ipset := sm.prevIPSet

	if v4 == "" {
		if data, err := os.ReadFile(filepath.Join(sm.stateDir, "backup_recovery.v4")); err == nil {
			v4 = string(data)
		}
	}
	if v6 == "" {
		if data, err := os.ReadFile(filepath.Join(sm.stateDir, "backup_recovery.v6")); err == nil {
			v6 = string(data)
		}
	}
	if ipset == "" {
		if data, err := os.ReadFile(filepath.Join(sm.stateDir, "backup_recovery.ipset")); err == nil {
			ipset = string(data)
		}
	}

	sm.doRestoreState(v4, v6, ipset)
	sm.cleanupLockFiles()
	sm.pendingID = ""

	if sm.onRollbackFn != nil {
		go sm.onRollbackFn(changeID, reason)
	}
}

func (sm *SafetyManager) doRestoreState(v4, v6, ipset string) {
	if ipset != "" {
		_ = sm.executor.RestoreIPSet(ipset)
	}
	if v4 != "" {
		_ = sm.executor.RestoreIptables(v4, false, false)
	}
	if v6 != "" {
		_ = sm.executor.RestoreIptables(v6, true, false)
	}
}

func (sm *SafetyManager) cleanupLockFiles() {
	_ = os.Remove(filepath.Join(sm.stateDir, "rollback.lock"))
	_ = os.Remove(filepath.Join(sm.stateDir, "backup_recovery.v4"))
	_ = os.Remove(filepath.Join(sm.stateDir, "backup_recovery.v6"))
	_ = os.Remove(filepath.Join(sm.stateDir, "backup_recovery.ipset"))
}
