# Linux Firewall Manager (LFM)

[![Go Version](https://img.shields.io/badge/Go-1.24-blue.svg)](https://golang.org)
[![React Version](https://img.shields.io/badge/React-18.3-61dafb.svg)](https://react.dev)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Aplicação corporativa para gerenciamento centralizado de firewalls `iptables`, `ip6tables` e `ipset` em frotas de servidores Linux heterogêneos.

---

## 🚀 Arquitetura e Características Principais

- **Conexão Exclusiva de Saída (Outbound-Only):** O agente conecta-se ao servidor de controle via mTLS sobre WebSocket/gRPC (porta `8443`), funcionando perfeitamente atrás de NAT e firewalls de borda.
- **Enrollment Seguro:** Adoção de nós via tokens de uso único e temporários. Emissão automática de certificados cliente X.509 pela CA interna, com rotação e revogação (CRL).
- **Zero-Shell Execution:** O agente nunca executa comandos em shell (`/bin/sh`). Todas as operações utilizam chamadas diretas de `os/exec` com argumentos estritamente tipados.
- **Proteção Contra Lockout ("Confirmar ou Reverter"):** Ao aplicar alterações, o agente cria um snapshot prévio e inicia uma contagem regressiva local (ex: 30 segundos). Se a conexão com o painel for perdida ou o operador não confirmar, o agente restaura automaticamente o estado anterior.
- **Detecção Automática de Drift:** Alerta quando alterações manuais forem realizadas localmente no host via SSH.
- **Estatísticas e Telemetria em Tempo Real:** Coleta contínua de pacotes, bytes, taxa (pps/bps) e identificação de regras sem hits há X dias.
- **IPSets Atômicos:** Atualização de conjuntos de IPs/redes sem perda de pacotes via `ipset swap`.
- **Autenticação Segura:** Usuário local único (`root`) com hash Argon2id, 2FA TOTP e bloqueio contra força bruta, além de suporte a SSO via OpenID Connect (OIDC).

---

## 📦 Estrutura do Projeto

```
lnx-firewall-manager/
├── cmd/
│   ├── fw-server/          # Servidor de controle central
│   └── fw-agent/           # Daemon instalado nas máquinas gerenciadas
├── docs/                   # Arquitetura, OpenAPI 3, DDL do banco e Modelo STRIDE
├── internal/
│   ├── agent/              # Executor seguro do kernel, safety manager e client mTLS
│   ├── api/                # Endpoints REST e middleware RBAC
│   ├── auth/               # Argon2id, TOTP RFC 6238 e sessões
│   ├── certs/              # PKI e Autoridade Certificadora mTLS interna
│   ├── db/                 # Repositório SQLite pure-Go e migrações
│   ├── models/             # Entidades de dados
│   ├── parser/             # Parser puro em Go de iptables-save/restore e hash canônico
│   └── server/             # Hub de conexões de agentes e broadcast em tempo real
├── packaging/              # Configurações nfpm (.deb/.rpm) e units do systemd
├── web/                    # Frontend SPA (React 18 + Vite + TypeScript + Tailwind CSS)
├── Dockerfile.server       # Imagem de container para o servidor de controle
├── docker-compose.yml
└── Makefile
```

---

## 🛠️ Como Compilar e Executar

### Pré-requisitos
- Go 1.24+
- Node.js 20+ e npm
- Linux com `iptables` e `ipset` instalados (ou WSL2 / Docker)

### Compilação Rápida
```bash
# Compilar ambos os binários e o frontend web
make build
make build-web
```

Os binários compilados estarão disponíveis em `bin/fw-server` e `bin/fw-agent`.

---

## 🖥️ Inicialização do Servidor de Controle (`fw-server`)

```bash
./bin/fw-server -listen :8443 -db ./data/lfm.db -certs-dir ./certs_data -web-dir ./web/dist
```

- Acesse no navegador: `http://localhost:8443`
- **Usuário inicial padrão:** `root`
- **Senha inicial padrão:** `admin` (alterável na inicialização ou no painel)

---

## 🤖 Provisionamento do Agente (`fw-agent`)

### 1. Gerar Token de Enrollment
No painel web, acesse a aba **Servidores** e clique em **"Adicionar Servidor"**, ou use a API:
```bash
curl -X POST http://localhost:8443/api/v1/enrollment/tokens \
  -H "Content-Type: application/json" \
  -d '{"initial_tags": ["web", "production"], "ttl_hours": 24}'
```

### 2. Registrar a Máquina Alvo
No servidor Linux que deseja gerenciar, execute:
```bash
sudo ./bin/fw-agent enroll --server http://<IP_DO_PAINEL>:8443 --token enroll_<TOKEN_GERADO>
```

### 3. Iniciar o Daemon do Agente
```bash
sudo ./bin/fw-agent run
```
O servidor aparecerá imediatamente como **ONLINE** no painel web!

---

## 🔐 Configuração do OpenID Connect (OIDC)

### Exemplo com Keycloak
No arquivo de configuração ou nas configurações do sistema:
```json
{
  "oidc_enabled": true,
  "issuer": "https://auth.exemplo.com/realms/empresa",
  "client_id": "lfm-firewall",
  "client_secret": "seu-segredo-oidc",
  "redirect_uri": "https://painel.exemplo.com/api/v1/auth/oidc/callback",
  "scopes": ["openid", "profile", "email", "groups"],
  "role_claim": "groups",
  "role_mapping": {
    "sysadmins": "admin",
    "netops": "operator",
    "auditors": "viewer"
  }
}
```

### Exemplo com Google Workspace
```json
{
  "oidc_enabled": true,
  "issuer": "https://accounts.google.com",
  "client_id": "xxxxx.apps.googleusercontent.com",
  "client_secret": "GOCSPX-yyyyy",
  "redirect_uri": "https://painel.exemplo.com/api/v1/auth/oidc/callback"
}
```

---

## 🛡️ Proteção Contra Lockout ("Confirm or Revert")

1. Ao aplicar qualquer alteração de regra na interface web, o `fw-agent` cria um snapshot prévio em `/var/lib/fw-agent/backup_recovery.v4`.
2. As regras são aplicadas no kernel e um **timer local de 30 segundos** é iniciado.
3. Se a conexão com o painel for interrompida (ou o operador não clicar em **"Confirmar Permanência"**), o agente automaticamente restaura o snapshot de recuperação e alerta o painel quando restabelecido.
4. Caso a máquina reinicie durante o teste, o lock de `/var/lib/fw-agent/rollback.lock` força a restauração segura imediatamente no boot.

---

## 🔧 Solução de Problemas (Troubleshooting)

- **Agente não conecta:** Verifique se a porta `8443` está acessível a partir da máquina alvo e se o relógio de ambos os servidores está sincronizado (NTP).
- **Erro de permissão no iptables:** O agente requer privilégios de rede (`CAP_NET_ADMIN` e `CAP_NET_RAW`) ou execução com `sudo`.
- **Divergência detectada (Drift):** Se alguém editar regras no host via console SSH, o painel exibirá o alerta de drift com o diff visual unificado entre o kernel e o banco central.
