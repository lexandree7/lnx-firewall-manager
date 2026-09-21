package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"lnx-firewall-manager/internal/agent"
)

type AgentConfigFile struct {
	ServerURL string `json:"server_url"`
	ServerID  string `json:"server_id"`
	Hostname  string `json:"hostname"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]

	defaultConfig := "./agent_config.json"
	defaultCerts := "./agent_certs"
	defaultState := "./agent_state"

	// Se executado como root e o diretório /etc/fw-agent existir (ou se o binário foi instalado no sistema),
	// prioriza os caminhos de produção do systemd
	if os.Geteuid() == 0 {
		if _, err := os.Stat("/etc/fw-agent"); err == nil {
			defaultConfig = "/etc/fw-agent/config.json"
			defaultCerts = "/etc/fw-agent/certs"
			defaultState = "/var/lib/fw-agent"
		}
	}

	switch subcommand {
	case "enroll":
		enrollCmd := flag.NewFlagSet("enroll", flag.ExitOnError)
		serverFlag := enrollCmd.String("server", "http://localhost:8443", "URL do servidor de controle LFM")
		tokenFlag := enrollCmd.String("token", "", "Token de enrollment de uso único")
		certsDir := enrollCmd.String("certs-dir", defaultCerts, "Diretório para salvar os certificados mTLS emitidos")
		configFile := enrollCmd.String("config", defaultConfig, "Caminho do arquivo de configuração do agente")
		_ = enrollCmd.Parse(os.Args[2:])

		if *tokenFlag == "" {
			log.Fatal("[ERRO] A flag --token é obrigatória para o enrollment.")
		}

		executeEnrollment(*serverFlag, *tokenFlag, *certsDir, *configFile)

	case "run":
		runCmd := flag.NewFlagSet("run", flag.ExitOnError)
		serverFlag := runCmd.String("server", "", "URL do servidor (opcional se especificado no config)")
		idFlag := runCmd.String("id", "", "ID do servidor gerenciado")
		configFile := runCmd.String("config", defaultConfig, "Caminho do arquivo de configuração do agente")
		certsDir := runCmd.String("certs-dir", defaultCerts, "Diretório de certificados mTLS")
		stateDir := runCmd.String("state-dir", defaultState, "Diretório de estado e locks de segurança")
		_ = runCmd.Parse(os.Args[2:])

		executeRun(*serverFlag, *idFlag, *configFile, *certsDir, *stateDir)

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Linux Firewall Manager — fw-agent")
	fmt.Println("Uso:")
	fmt.Println("  fw-agent enroll --server <URL> --token <TOKEN> [--certs-dir <DIR>]")
	fmt.Println("  fw-agent run [--config <ARQUIVO>] [--certs-dir <DIR>]")
}

func executeEnrollment(serverURL, token, certsDir, configFile string) {
	log.Printf("[ENROLL] Iniciando processo de enrollment no servidor: %s", serverURL)

	hostname, _ := os.Hostname()
	exec := agent.NewExecutor()
	sysInfo, _ := exec.CollectSystemInfo()

	payload := map[string]string{
		"token":          token,
		"hostname":       hostname,
		"os_distro":      sysInfo.OSDistro,
		"kernel_version": sysInfo.KernelVersion,
	}

	body, _ := json.Marshal(payload)
	claimURL := fmt.Sprintf("%s/api/v1/enrollment/claim", serverURL)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(claimURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Fatalf("[FATAL] Falha de conexão com o servidor no enrollment: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		log.Fatalf("[FATAL] Enrollment rejeitado pelo servidor (%d): %s", resp.StatusCode, errResp["error"])
	}

	var res struct {
		ServerID      string `json:"server_id"`
		CACertPEM     string `json:"ca_cert_pem"`
		ClientCertPEM string `json:"client_cert_pem"`
		ClientKeyPEM  string `json:"client_key_pem"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		log.Fatalf("[FATAL] Erro ao decodificar resposta de certificados: %v", err)
	}

	// Salva certificados em disco
	_ = os.MkdirAll(certsDir, 0700)
	_ = os.WriteFile(filepath.Join(certsDir, "ca.crt"), []byte(res.CACertPEM), 0644)
	_ = os.WriteFile(filepath.Join(certsDir, "client.crt"), []byte(res.ClientCertPEM), 0644)
	_ = os.WriteFile(filepath.Join(certsDir, "client.key"), []byte(res.ClientKeyPEM), 0600)

	// Salva configuração
	_ = os.MkdirAll(filepath.Dir(configFile), 0700)
	cfg := AgentConfigFile{
		ServerURL: serverURL,
		ServerID:  res.ServerID,
		Hostname:  hostname,
	}
	cfgBytes, _ := json.MarshalIndent(cfg, "", "  ")
	_ = os.WriteFile(configFile, cfgBytes, 0600)

	log.Printf("[ENROLL] Sucesso! Agente registrado com ServerID: %s", res.ServerID)
	log.Printf("[ENROLL] Certificados mTLS salvos em %s", certsDir)
	log.Printf("[ENROLL] Configuração gravada em %s", configFile)
	log.Println("[ENROLL] Você já pode iniciar o daemon: fw-agent run")
}

func executeRun(serverURL, agentID, configFile, certsDir, stateDir string) {
	// Carrega do arquivo se não informado por flag
	if serverURL == "" || agentID == "" {
		data, err := os.ReadFile(configFile)
		// Fallbacks automáticos para localizar o arquivo de configuração
		if err != nil {
			candidates := []string{
				"/etc/fw-agent/config.json",
				"./agent_config.json",
			}
			for _, candidate := range candidates {
				if candidate == configFile {
					continue
				}
				if cData, cErr := os.ReadFile(candidate); cErr == nil {
					data = cData
					err = nil
					log.Printf("[INIT] Configuração carregada a partir do caminho alternativo: %s", candidate)
					break
				}
			}
		}

		if err == nil {
			var cfg AgentConfigFile
			if json.Unmarshal(data, &cfg) == nil {
				if serverURL == "" {
					serverURL = cfg.ServerURL
				}
				if agentID == "" {
					agentID = cfg.ServerID
				}
			}
		}
	}

	if serverURL == "" || agentID == "" {
		log.Fatal("[FATAL] ServerURL e AgentID são obrigatórios. Execute 'fw-agent enroll' primeiro ou use flags --server e --id.")
	}

	log.Println("==========================================================")
	log.Println(" Linux Firewall Manager (LFM) — Managed Agent (fw-agent)")
	log.Println("==========================================================")
	log.Printf("[INIT] Server URL: %s", serverURL)
	log.Printf("[INIT] Agent ID:   %s", agentID)

	// Verifica se os certificados existem no certsDir especificado ou em fallback
	caCertFile := filepath.Join(certsDir, "ca.crt")
	clientCertFile := filepath.Join(certsDir, "client.crt")
	clientKeyFile := filepath.Join(certsDir, "client.key")

	if _, err := os.Stat(clientCertFile); err != nil {
		certFallbacks := []string{
			"/etc/fw-agent/certs",
			"./agent_certs",
		}
		for _, fb := range certFallbacks {
			if fb == certsDir {
				continue
			}
			if _, statErr := os.Stat(filepath.Join(fb, "client.crt")); statErr == nil {
				certsDir = fb
				caCertFile = filepath.Join(certsDir, "ca.crt")
				clientCertFile = filepath.Join(certsDir, "client.crt")
				clientKeyFile = filepath.Join(certsDir, "client.key")
				log.Printf("[INIT] Certificados mTLS encontrados em diretório alternativo: %s", certsDir)
				break
			}
		}
	}

	// Carrega certificados se existirem
	var tlsConf *tls.Config

	if _, err := os.Stat(caCertFile); err == nil {
		caData, _ := os.ReadFile(caCertFile)
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(caData)

		cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err == nil {
			tlsConf = &tls.Config{
				RootCAs:            caPool,
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true, // Permitir hostnames dinâmicos em testes locais
			}
			log.Println("[INIT] Certificados mTLS carregados com sucesso.")
		}
	}

	client := agent.NewAgentClient(serverURL, agentID, stateDir, tlsConf)

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go client.Run()

	log.Println("[READY] fw-agent em execução contínua com proteção contra lockout.")
	<-stopChan
	log.Println("[SHUTDOWN] Finalizando agente...")
	client.Stop()
	log.Println("[SHUTDOWN] Agente encerrado.")
}
