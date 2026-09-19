package agent

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// IPSetManager gerencia sets com operações atômicas de swap
type IPSetManager struct {
	ipsetBin string
}

// NewIPSetManager inicializa o gerenciador de ipsets
func NewIPSetManager() *IPSetManager {
	return &IPSetManager{
		ipsetBin: findExecutable("ipset", "/sbin/ipset", "/usr/sbin/ipset"),
	}
}

// CreateSet cria um conjunto se não existir
func (m *IPSetManager) CreateSet(name, typeName, family string, maxelem int, timeout int, comment bool, counters bool) error {
	if m.ipsetBin == "" {
		return fmt.Errorf("binário ipset não encontrado")
	}

	if family == "" {
		family = "inet"
	}
	if maxelem <= 0 {
		maxelem = 65536
	}

	args := []string{"create", "-exist", name, typeName, "family", family, "maxelem", strconv.Itoa(maxelem)}
	if timeout > 0 {
		args = append(args, "timeout", strconv.Itoa(timeout))
	}
	if comment {
		args = append(args, "comment")
	}
	if counters {
		args = append(args, "counters")
	}

	cmd := exec.Command(m.ipsetBin, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("erro ao criar ipset %s: %v, out: %s", name, err, string(out))
	}

	return nil
}

// AtomicSwapEntries substitui todas as entradas de um set sem downtime usando ipset swap
func (m *IPSetManager) AtomicSwapEntries(name, typeName, family string, maxelem int, entries []string) error {
	if m.ipsetBin == "" {
		return fmt.Errorf("binário ipset não encontrado")
	}

	tmpName := fmt.Sprintf("%s_swap_tmp", name)
	// Trunca nome se exceder 31 caracteres do kernel
	if len(tmpName) > 31 {
		tmpName = fmt.Sprintf("tmp_%d", len(name))
	}

	// 1. Destrói tmpName anterior se existir
	_ = exec.Command(m.ipsetBin, "destroy", tmpName).Run()

	// 2. Cria set temporário
	if err := m.CreateSet(tmpName, typeName, family, maxelem, 0, true, false); err != nil {
		return fmt.Errorf("falha ao criar set temporário: %v", err)
	}

	// 3. Popula set temporário em lote via restore
	var sb strings.Builder
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		sb.WriteString(fmt.Sprintf("add %s %s\n", tmpName, entry))
	}

	restoreCmd := exec.Command(m.ipsetBin, "restore")
	restoreCmd.Stdin = strings.NewReader(sb.String())
	if out, err := restoreCmd.CombinedOutput(); err != nil {
		_ = exec.Command(m.ipsetBin, "destroy", tmpName).Run()
		return fmt.Errorf("falha ao popular set temporário: %v, out: %s", err, string(out))
	}

	// 4. Garante que o set alvo existe antes do swap
	_ = m.CreateSet(name, typeName, family, maxelem, 0, true, false)

	// 5. Troca atômica (swap)
	swapCmd := exec.Command(m.ipsetBin, "swap", name, tmpName)
	if out, err := swapCmd.CombinedOutput(); err != nil {
		_ = exec.Command(m.ipsetBin, "destroy", tmpName).Run()
		return fmt.Errorf("falha no ipset swap: %v, out: %s", err, string(out))
	}

	// 6. Destrói o conjunto antigo
	_ = exec.Command(m.ipsetBin, "destroy", tmpName).Run()

	return nil
}

// ListSets lista informações de todos os sets existentes
func (m *IPSetManager) ListSets() ([]string, error) {
	if m.ipsetBin == "" {
		return nil, fmt.Errorf("binário ipset não encontrado")
	}

	cmd := exec.Command(m.ipsetBin, "list", "-n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar ipsets: %v, out: %s", err, string(out))
	}

	var sets []string
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			sets = append(sets, trimmed)
		}
	}

	return sets, nil
}

// FlushSet remove todas as entradas de um set
func (m *IPSetManager) FlushSet(name string) error {
	cmd := exec.Command(m.ipsetBin, "flush", name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("falha ao limpar ipset %s: %v, out: %s", name, err, string(out))
	}
	return nil
}

// DestroySet remove o conjunto
func (m *IPSetManager) DestroySet(name string) error {
	cmd := exec.Command(m.ipsetBin, "destroy", name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("falha ao destruir ipset %s: %v, out: %s", name, err, string(out))
	}
	return nil
}

// AddEntry adiciona uma entrada individual
func (m *IPSetManager) AddEntry(setName, entry string) error {
	cmd := exec.Command(m.ipsetBin, "add", "-exist", setName, entry)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("falha ao adicionar %s no set %s: %v, stderr: %s", entry, setName, err, stderr.String())
	}
	return nil
}

// DelEntry remove uma entrada individual
func (m *IPSetManager) DelEntry(setName, entry string) error {
	cmd := exec.Command(m.ipsetBin, "del", "-exist", setName, entry)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("falha ao remover %s do set %s: %v, stderr: %s", entry, setName, err, stderr.String())
	}
	return nil
}
