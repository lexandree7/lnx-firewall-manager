package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Table representa uma tabela iptables (filter, nat, mangle, raw, security)
type Table struct {
	Name   string
	Chains map[string]*Chain
	Rules  []*Rule
}

// Chain representa uma chain em uma tabela
type Chain struct {
	Name          string
	Policy        string // ACCEPT, DROP, etc., ou "-" para custom
	PacketCounter int64
	ByteCounter   int64
	IsBuiltin     bool
}

// Rule representa uma regra individual com contadores e parâmetros
type Rule struct {
	Table         string
	Chain         string
	PacketCounter int64
	ByteCounter   int64
	Position      int

	// Flags e matches
	Protocol          string // tcp, udp, icmp, all
	SrcIP             string
	DstIP             string
	InInterface       string
	OutInterface      string
	SrcPorts          string
	DstPorts          string
	StateMatch        string
	TCPFlags          string
	LimitRate         string
	LimitBurst        int
	MatchSetName      string
	MatchSetDirection string
	Target            string
	TargetOptions     string
	Comment           string

	RawText string // Argumentos da regra sem [pkts:bytes] e -A CHAIN
}

// Ruleset contém todas as tabelas parseadas de um iptables-save
type Ruleset struct {
	Tables map[string]*Table
}

// ParseIptablesSave faz o parsing completo de output do iptables-save -c
func ParseIptablesSave(content string) (*Ruleset, error) {
	rs := &Ruleset{
		Tables: make(map[string]*Table),
	}

	lines := strings.Split(content, "\n")
	var currentTable *Table

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "*") {
			tableName := strings.TrimPrefix(line, "*")
			currentTable = &Table{
				Name:   tableName,
				Chains: make(map[string]*Chain),
				Rules:  make([]*Rule, 0),
			}
			rs.Tables[tableName] = currentTable
			continue
		}

		if line == "COMMIT" {
			currentTable = nil
			continue
		}

		if currentTable == nil {
			continue
		}

		// Definição de Chain: :INPUT ACCEPT [123:456] ou :CUSTOM - [0:0]
		if strings.HasPrefix(line, ":") {
			parts := strings.Fields(line[1:])
			if len(parts) >= 2 {
				chainName := parts[0]
				policy := parts[1]
				isBuiltin := policy != "-"

				var pkts, bytes int64
				if len(parts) >= 3 && strings.HasPrefix(parts[2], "[") && strings.HasSuffix(parts[2], "]") {
					cnt := strings.Trim(parts[2], "[]")
					cntParts := strings.Split(cnt, ":")
					if len(cntParts) == 2 {
						pkts, _ = strconv.ParseInt(cntParts[0], 10, 64)
						bytes, _ = strconv.ParseInt(cntParts[1], 10, 64)
					}
				}

				currentTable.Chains[chainName] = &Chain{
					Name:          chainName,
					Policy:        policy,
					PacketCounter: pkts,
					ByteCounter:   bytes,
					IsBuiltin:     isBuiltin,
				}
			}
			continue
		}

		// Regra: [12:345] -A INPUT ... ou -A INPUT ...
		rule, err := parseRuleLine(currentTable.Name, line)
		if err == nil && rule != nil {
			rule.Position = len(currentTable.Rules) + 1
			currentTable.Rules = append(currentTable.Rules, rule)
		}
	}

	return rs, nil
}

// parseRuleLine analisa uma linha de regra
func parseRuleLine(tableName, line string) (*Rule, error) {
	rule := &Rule{
		Table:    tableName,
		Protocol: "all",
	}

	var remainder string
	if strings.HasPrefix(line, "[") {
		idx := strings.Index(line, "]")
		if idx != -1 {
			cnt := line[1:idx]
			cntParts := strings.Split(cnt, ":")
			if len(cntParts) == 2 {
				rule.PacketCounter, _ = strconv.ParseInt(cntParts[0], 10, 64)
				rule.ByteCounter, _ = strconv.ParseInt(cntParts[1], 10, 64)
			}
			remainder = strings.TrimSpace(line[idx+1:])
		} else {
			remainder = line
		}
	} else {
		remainder = line
	}

	tokens := tokenizeArgs(remainder)
	if len(tokens) < 2 || tokens[0] != "-A" {
		return nil, fmt.Errorf("não é uma regra append (-A): %s", line)
	}

	rule.Chain = tokens[1]
	args := tokens[2:]

	// Armazena a regra em texto cru normalizado
	rule.RawText = strings.Join(args, " ")

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-p", "--protocol":
			if i+1 < len(args) {
				rule.Protocol = args[i+1]
				i++
			}
		case "-s", "--source":
			if i+1 < len(args) {
				rule.SrcIP = args[i+1]
				i++
			}
		case "-d", "--destination":
			if i+1 < len(args) {
				rule.DstIP = args[i+1]
				i++
			}
		case "-i", "--in-interface":
			if i+1 < len(args) {
				rule.InInterface = args[i+1]
				i++
			}
		case "-o", "--out-interface":
			if i+1 < len(args) {
				rule.OutInterface = args[i+1]
				i++
			}
		case "--sport", "--source-port":
			if i+1 < len(args) {
				rule.SrcPorts = args[i+1]
				i++
			}
		case "--dport", "--destination-port":
			if i+1 < len(args) {
				rule.DstPorts = args[i+1]
				i++
			}
		case "-m":
			if i+1 < len(args) {
				matchModule := args[i+1]
				i++
				// Analisa submódulos
				switch matchModule {
				case "multiport":
					for i+1 < len(args) && strings.HasPrefix(args[i+1], "--") {
						if args[i+1] == "--dports" && i+2 < len(args) {
							rule.DstPorts = args[i+2]
							i += 2
						} else if args[i+1] == "--sports" && i+2 < len(args) {
							rule.SrcPorts = args[i+2]
							i += 2
						} else {
							break
						}
					}
				case "conntrack":
					if i+1 < len(args) && args[i+1] == "--ctstate" && i+2 < len(args) {
						rule.StateMatch = args[i+2]
						i += 2
					}
				case "state":
					if i+1 < len(args) && args[i+1] == "--state" && i+2 < len(args) {
						rule.StateMatch = args[i+2]
						i += 2
					}
				case "comment":
					if i+1 < len(args) && args[i+1] == "--comment" && i+2 < len(args) {
						rule.Comment = args[i+2]
						i += 2
					}
				case "set":
					if i+1 < len(args) && args[i+1] == "--match-set" && i+3 < len(args) {
						rule.MatchSetName = args[i+2]
						rule.MatchSetDirection = args[i+3]
						i += 3
					}
				case "limit":
					if i+1 < len(args) && args[i+1] == "--limit" && i+2 < len(args) {
						rule.LimitRate = args[i+2]
						i += 2
					}
					if i+1 < len(args) && args[i+1] == "--limit-burst" && i+2 < len(args) {
						rule.LimitBurst, _ = strconv.Atoi(args[i+2])
						i += 2
					}
				case "tcp":
					if i+1 < len(args) && args[i+1] == "--tcp-flags" && i+3 < len(args) {
						rule.TCPFlags = args[i+2] + " " + args[i+3]
						i += 3
					}
				}
			}
		case "-j", "--jump":
			if i+1 < len(args) {
				rule.Target = args[i+1]
				i++
				// Opções adicionais de target (ex: --to-destination)
				if i+1 < len(args) && strings.HasPrefix(args[i+1], "--") {
					targetOpts := []string{}
					for i+1 < len(args) && strings.HasPrefix(args[i+1], "-") {
						targetOpts = append(targetOpts, args[i+1])
						if i+2 < len(args) && !strings.HasPrefix(args[i+2], "-") {
							targetOpts = append(targetOpts, args[i+2])
							i += 2
						} else {
							i++
						}
					}
					rule.TargetOptions = strings.Join(targetOpts, " ")
				}
			}
		case "-g", "--goto":
			if i+1 < len(args) {
				rule.Target = args[i+1]
				i++
			}
		}
	}

	return rule, nil
}

// tokenizeArgs faz o split respeitando aspas
func tokenizeArgs(s string) []string {
	var tokens []string
	var current strings.Builder
	inQuotes := false
	quoteChar := rune(0)

	for _, r := range s {
		switch {
		case r == '"' || r == '\'':
			if inQuotes && r == quoteChar {
				inQuotes = false
				quoteChar = 0
			} else if !inQuotes {
				inQuotes = true
				quoteChar = r
			} else {
				current.WriteRune(r)
			}
		case r == ' ' || r == '\t':
			if inQuotes {
				current.WriteRune(r)
			} else if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

// FormatIptablesRestore compila o ruleset para formato iptables-restore
func (rs *Ruleset) FormatIptablesRestore(includeCounters bool) string {
	var sb strings.Builder

	tableOrder := []string{"raw", "mangle", "nat", "filter", "security"}
	for _, tblName := range tableOrder {
		table, ok := rs.Tables[tblName]
		if !ok {
			continue
		}

		sb.WriteString(fmt.Sprintf("*%s\n", tblName))

		// Chains ordenadas deterministicamente
		var chainNames []string
		for chainName := range table.Chains {
			chainNames = append(chainNames, chainName)
		}
		sort.Strings(chainNames)

		for _, chainName := range chainNames {
			chain := table.Chains[chainName]
			policy := chain.Policy
			if policy == "" {
				policy = "-"
			}
			if includeCounters {
				sb.WriteString(fmt.Sprintf(":%s %s [%d:%d]\n", chainName, policy, chain.PacketCounter, chain.ByteCounter))
			} else {
				sb.WriteString(fmt.Sprintf(":%s %s [0:0]\n", chainName, policy))
			}
		}

		// Rules
		for _, rule := range table.Rules {
			if includeCounters {
				sb.WriteString(fmt.Sprintf("[%d:%d] -A %s %s\n", rule.PacketCounter, rule.ByteCounter, rule.Chain, rule.FormatArgs()))
			} else {
				sb.WriteString(fmt.Sprintf("-A %s %s\n", rule.Chain, rule.FormatArgs()))
			}
		}

		sb.WriteString("COMMIT\n")
	}

	return sb.String()
}

// FormatArgs reconstrói os argumentos de uma regra
func (r *Rule) FormatArgs() string {
	if r.RawText != "" && r.Target == "" {
		return r.RawText
	}

	var parts []string

	if r.Protocol != "" && r.Protocol != "all" {
		parts = append(parts, "-p", r.Protocol)
	}
	if r.InInterface != "" {
		parts = append(parts, "-i", r.InInterface)
	}
	if r.OutInterface != "" {
		parts = append(parts, "-o", r.OutInterface)
	}
	if r.SrcIP != "" {
		parts = append(parts, "-s", r.SrcIP)
	}
	if r.DstIP != "" {
		parts = append(parts, "-d", r.DstIP)
	}

	// Portas
	if r.SrcPorts != "" {
		if strings.Contains(r.SrcPorts, ",") {
			parts = append(parts, "-m", "multiport", "--sports", r.SrcPorts)
		} else {
			parts = append(parts, "--sport", r.SrcPorts)
		}
	}
	if r.DstPorts != "" {
		if strings.Contains(r.DstPorts, ",") {
			parts = append(parts, "-m", "multiport", "--dports", r.DstPorts)
		} else {
			parts = append(parts, "--dport", r.DstPorts)
		}
	}

	// State / Conntrack
	if r.StateMatch != "" {
		parts = append(parts, "-m", "conntrack", "--ctstate", r.StateMatch)
	}

	// TCP Flags
	if r.TCPFlags != "" {
		flagParts := strings.Fields(r.TCPFlags)
		if len(flagParts) == 2 {
			parts = append(parts, "-m", "tcp", "--tcp-flags", flagParts[0], flagParts[1])
		}
	}

	// Limit
	if r.LimitRate != "" {
		parts = append(parts, "-m", "limit", "--limit", r.LimitRate)
		if r.LimitBurst > 0 {
			parts = append(parts, "--limit-burst", strconv.Itoa(r.LimitBurst))
		}
	}

	// IPSet
	if r.MatchSetName != "" {
		dir := r.MatchSetDirection
		if dir == "" {
			dir = "src"
		}
		parts = append(parts, "-m", "set", "--match-set", r.MatchSetName, dir)
	}

	// Comentário
	if r.Comment != "" {
		parts = append(parts, "-m", "comment", "--comment", fmt.Sprintf("\"%s\"", r.Comment))
	}

	// Target
	if r.Target != "" {
		parts = append(parts, "-j", r.Target)
		if r.TargetOptions != "" {
			parts = append(parts, r.TargetOptions)
		}
	}

	return strings.Join(parts, " ")
}

// CanonicalHash calcula o SHA-256 do ruleset normalizado (sem contadores voláteis)
// Usado para detecção de Drift imediata
func (rs *Ruleset) CanonicalHash() string {
	normalized := rs.FormatIptablesRestore(false)
	hasher := sha256.New()
	hasher.Write([]byte(normalized))
	return hex.EncodeToString(hasher.Sum(nil))
}

// SafetyRiskWarning contém os alertas de heurística preventiva contra lockout
type SafetyRiskWarning struct {
	Level   string // "CRITICAL", "WARNING"
	Message string
}

// InspectSafetyHeuristics analisa se a regra ou ruleset pode cortar o acesso do operador
func InspectSafetyHeuristics(rules []*Rule, controlPlanePort int, sshPort int) []SafetyRiskWarning {
	var warnings []SafetyRiskWarning

	if controlPlanePort == 0 {
		controlPlanePort = 8443
	}
	if sshPort == 0 {
		sshPort = 22
	}

	sshPortStr := strconv.Itoa(sshPort)
	cpPortStr := strconv.Itoa(controlPlanePort)

	for _, r := range rules {
		isDrop := r.Target == "DROP" || r.Target == "REJECT"

		if isDrop {
			// Bloqueio de SSH
			if (r.Chain == "INPUT" || r.Chain == "FORWARD") &&
				(r.DstPorts == sshPortStr || strings.Contains(r.DstPorts, sshPortStr)) {
				warnings = append(warnings, SafetyRiskWarning{
					Level:   "CRITICAL",
					Message: fmt.Sprintf("A regra na chain %s bloqueia expressamente a porta SSH (%d), o que pode causar lockout do servidor!", r.Chain, sshPort),
				})
			}

			// Bloqueio de Porta do Servidor de Controle
			if (r.Chain == "OUTPUT" || r.Chain == "INPUT") &&
				(r.DstPorts == cpPortStr || r.SrcPorts == cpPortStr || strings.Contains(r.DstPorts, cpPortStr)) {
				warnings = append(warnings, SafetyRiskWarning{
					Level:   "CRITICAL",
					Message: fmt.Sprintf("A regra na chain %s bloqueia a porta de telemetria do LFM (%d), o que desconectará o agente!", r.Chain, controlPlanePort),
				})
			}
		}
	}

	return warnings
}
