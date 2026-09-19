package agent

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SystemInfo contém metadados do host gerenciado
type SystemInfo struct {
	Hostname        string   `json:"hostname"`
	OSDistro        string   `json:"os_distro"`
	KernelVersion   string   `json:"kernel_version"`
	IptablesBackend string   `json:"iptables_backend"` // "nftables" ou "legacy"
	IPv6Supported   bool     `json:"ipv6_supported"`
	IPSetSupported  bool     `json:"ipset_supported"`
	Interfaces      []string `json:"interfaces"`
}

// Executor encapsula comandos seguros do kernel sem invocação de shell
type Executor struct {
	iptablesBin        string
	ip6tablesBin       string
	iptablesSaveBin    string
	ip6tablesSaveBin   string
	iptablesRestoreBin string
	ip6tablesRestoreBin string
	ipsetBin           string
}

// NewExecutor localiza binários e inicializa o executor
func NewExecutor() *Executor {
	return &Executor{
		iptablesBin:         findExecutable("iptables", "/sbin/iptables", "/usr/sbin/iptables"),
		ip6tablesBin:        findExecutable("ip6tables", "/sbin/ip6tables", "/usr/sbin/ip6tables"),
		iptablesSaveBin:     findExecutable("iptables-save", "/sbin/iptables-save", "/usr/sbin/iptables-save"),
		ip6tablesSaveBin:    findExecutable("ip6tables-save", "/sbin/ip6tables-save", "/usr/sbin/ip6tables-save"),
		iptablesRestoreBin:  findExecutable("iptables-restore", "/sbin/iptables-restore", "/usr/sbin/iptables-restore"),
		ip6tablesRestoreBin: findExecutable("ip6tables-restore", "/sbin/ip6tables-restore", "/usr/sbin/ip6tables-restore"),
		ipsetBin:            findExecutable("ipset", "/sbin/ipset", "/usr/sbin/ipset"),
	}
}

func findExecutable(name string, fallbacks ...string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, f := range fallbacks {
		if _, err := os.Stat(f); err == nil {
			return f
		}
	}
	return name
}

// DetectBackend detecta se o iptables usa backend nftables ou legacy
func (e *Executor) DetectBackend() string {
	cmd := exec.Command(e.iptablesBin, "-V")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "unknown"
	}
	outStr := string(out)
	if strings.Contains(outStr, "nf_tables") {
		return "nftables"
	}
	if strings.Contains(outStr, "legacy") {
		return "legacy"
	}
	return "standard"
}

// CollectSystemInfo coleta métricas e inventário do host
func (e *Executor) CollectSystemInfo() (*SystemInfo, error) {
	hostname, _ := os.Hostname()

	// Distro via /etc/os-release
	distro := "Linux"
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				distro = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}

	// Kernel version via uname -r
	kernel := "unknown"
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		kernel = strings.TrimSpace(string(out))
	}

	// Interfaces ativas
	var ifaceNames []string
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp != 0 {
				ifaceNames = append(ifaceNames, iface.Name)
			}
		}
	}

	// IPv6 suportado
	ipv6Supported := false
	if _, err := os.Stat("/proc/net/if_inet6"); err == nil {
		ipv6Supported = true
	}

	// IPSet suportado
	ipsetSupported := false
	if e.ipsetBin != "" {
		if err := exec.Command(e.ipsetBin, "version").Run(); err == nil {
			ipsetSupported = true
		}
	}

	return &SystemInfo{
		Hostname:        hostname,
		OSDistro:        distro,
		KernelVersion:   kernel,
		IptablesBackend: e.DetectBackend(),
		IPv6Supported:   ipv6Supported,
		IPSetSupported:  ipsetSupported,
		Interfaces:      ifaceNames,
	}, nil
}

// DumpIptables executa iptables-save -c ou ip6tables-save -c de forma segura
func (e *Executor) DumpIptables(ipv6 bool) (string, error) {
	bin := e.iptablesSaveBin
	if ipv6 {
		bin = e.ip6tablesSaveBin
	}

	cmd := exec.Command(bin, "-c")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("falha ao executar %s: %v, stderr: %s", bin, err, stderr.String())
	}

	return stdout.String(), nil
}

// RestoreIptables aplica as regras com iptables-restore -c [--noflush] via stdin
func (e *Executor) RestoreIptables(content string, ipv6 bool, noflush bool) error {
	bin := e.iptablesRestoreBin
	if ipv6 {
		bin = e.ip6tablesRestoreBin
	}

	args := []string{"-c"}
	if noflush {
		args = append(args, "--noflush")
	}

	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("falha no %s: %v, detalhe: %s", bin, err, stderr.String())
	}

	return nil
}

// DumpIPSet executa ipset save
func (e *Executor) DumpIPSet() (string, error) {
	if e.ipsetBin == "" {
		return "", fmt.Errorf("binário ipset não encontrado")
	}

	cmd := exec.Command(e.ipsetBin, "save")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("falha ao exportar ipset: %v, stderr: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// RestoreIPSet aplica regras via ipset restore
func (e *Executor) RestoreIPSet(content string) error {
	if e.ipsetBin == "" {
		return fmt.Errorf("binário ipset não encontrado")
	}
	if strings.TrimSpace(content) == "" {
		return nil
	}

	cmd := exec.Command(e.ipsetBin, "restore", "-exist")
	cmd.Stdin = strings.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("falha ao restaurar ipset: %v, stderr: %s", err, stderr.String())
	}

	return nil
}

// SavePersistent salva em disco de acordo com o padrão da distribuição Linux
func (e *Executor) SavePersistent(v4Content, v6Content string) error {
	// Debian/Ubuntu: /etc/iptables/rules.v4 e rules.v6
	debianDir := "/etc/iptables"
	if _, err := os.Stat(debianDir); err == nil {
		if v4Content != "" {
			_ = os.WriteFile(filepath.Join(debianDir, "rules.v4"), []byte(v4Content), 0600)
		}
		if v6Content != "" {
			_ = os.WriteFile(filepath.Join(debianDir, "rules.v6"), []byte(v6Content), 0600)
		}
		return nil
	}

	// RHEL/CentOS/Rocky: /etc/sysconfig/iptables
	rhelDir := "/etc/sysconfig"
	if _, err := os.Stat(rhelDir); err == nil {
		if v4Content != "" {
			_ = os.WriteFile(filepath.Join(rhelDir, "iptables"), []byte(v4Content), 0600)
		}
		if v6Content != "" {
			_ = os.WriteFile(filepath.Join(rhelDir, "ip6tables"), []byte(v6Content), 0600)
		}
		return nil
	}

	// Fallback padrão: /var/lib/fw-agent/rules.active
	fallbackDir := "/var/lib/fw-agent"
	_ = os.MkdirAll(fallbackDir, 0700)
	if v4Content != "" {
		_ = os.WriteFile(filepath.Join(fallbackDir, "rules.v4"), []byte(v4Content), 0600)
	}
	if v6Content != "" {
		_ = os.WriteFile(filepath.Join(fallbackDir, "rules.v6"), []byte(v6Content), 0600)
	}

	return nil
}
