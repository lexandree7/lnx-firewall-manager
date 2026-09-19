package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"lnx-firewall-manager/internal/api"
	"lnx-firewall-manager/internal/auth"
	"lnx-firewall-manager/internal/certs"
	"lnx-firewall-manager/internal/db"
	"lnx-firewall-manager/internal/server"
)

func main() {
	listenAddr := flag.String("listen", ":8443", "Endereço de escuta HTTP/HTTPS (ex: :8443 ou 0.0.0.0:8443)")
	dbPath := flag.String("db", "./data/lfm.db", "Caminho do arquivo SQLite")
	certsDir := flag.String("certs-dir", "./certs_data", "Diretório de certificados e CA interna")
	rootPassword := flag.String("root-password", "admin", "Senha inicial para o usuário root local")
	webDir := flag.String("web-dir", "./web/dist", "Diretório de arquivos estáticos do frontend SPA")
	flag.Parse()

	log.Println("==========================================================")
	log.Println(" Linux Firewall Manager (LFM) — Control Server (fw-server)")
	log.Println("==========================================================")

	// 1. Inicializa Banco de Dados
	database, err := db.NewDB(*dbPath)
	if err != nil {
		log.Fatalf("[FATAL] Falha ao inicializar banco de dados: %v", err)
	}
	log.Printf("[INIT] Banco de dados inicializado em %s", *dbPath)

	// 2. Inicializa CA Interna e PKI
	pki, err := certs.NewPKIManager(*certsDir)
	if err != nil {
		log.Fatalf("[FATAL] Falha ao inicializar autoridade certificadora: %v", err)
	}
	log.Printf("[INIT] PKI e CA mTLS prontas em %s", *certsDir)

	// 3. Inicializa Módulo de Autenticação
	authMgr, err := auth.NewAuthManager(database, *rootPassword)
	if err != nil {
		log.Fatalf("[FATAL] Falha ao configurar autenticação: %v", err)
	}
	log.Printf("[INIT] Autenticação configurada. Usuário 'root' garantido.")

	// 4. Inicializa Hub de Agentes
	agentHub := server.NewHub(database)
	log.Printf("[INIT] Agent Hub gRPC/WebSocket inicializado.")

	// 5. Inicializa API REST e Rotas
	serverAPI := api.NewServerAPI(database, authMgr, pki, agentHub)
	rootRouter := chi.NewRouter()
	serverAPI.RegisterRoutes(rootRouter, *webDir)
	log.Printf("[INIT] Rotas e Frontend registrados com sucesso.")

	httpServer := &http.Server{
		Addr:         *listenAddr,
		Handler:      rootRouter,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Canal de parada graciosa
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[READY] Servidor escutando em http://localhost%s", *listenAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] Erro de execução do servidor HTTP: %v", err)
		}
	}()

	<-stopChan
	log.Println("[SHUTDOWN] Encerrando servidor graciosamente...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
	log.Println("[SHUTDOWN] Servidor finalizado com sucesso.")
}
