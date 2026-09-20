# Plano de Implementação: Tela de Login, Painel de Usuário Local e Autenticação Federada OpenID Connect (OIDC)

Desenvolver uma arquitetura completa e segura de autenticação para o **Linux Firewall Manager (LFM)**, abrangendo:
1. **Tela de Login Dedicada:** Interface de autenticação com suporte a credenciais locais (`root`), segundo fator 2FA TOTP (RFC 6238), e botão de logon único (SSO via OpenID Connect).
2. **Painel de Gerenciamento do Usuário Local:** Perfil do operador, alteração segura de senha com **Argon2id**, configuração/ativação/desativação de 2FA TOTP com exibição de segredo Base32 e QR Code, e gerenciador de sessões ativas com revogação.
3. **Autenticação Federada com OpenID Connect (OIDC):** Provedor configurável no backend (Discovery via `.well-known/openid-configuration`, troca atômica de código de autorização, provisionamento Just-in-Time de usuários federados), endpoints de fluxo OIDC (`/auth/oidc/login`, `/auth/oidc/callback`, `/settings/oidc`) e aba de configuração administrativa para integração com Keycloak, Google, Okta, Authentik ou Azure AD.

---

## Revisão do Usuário Obrigatória

> [!IMPORTANT]
> - O usuário padrão do sistema permanece `root` com papel inicial `admin`. A senha inicial padrão é `admin`, devendo ser alterada no primeiro acesso através do novo Painel de Usuário.
> - O fluxo OpenID Connect opera via protocolo padrão OAuth 2.0 / OIDC Authorization Code Flow, compatível com qualquer Identity Provider padrão (Keycloak, Authentik, Google Workspace, Okta, Microsoft Entra ID).
> - Se o OIDC estiver desativado no painel, a tela de login exibirá apenas a autenticação local. Quando ativado pelo administrador, o botão de SSO é disponibilizado automaticamente.

---

## Mudanças Propostas

### 1. Banco de Dados e Modelos Go

#### [MODIFY] [models.go](file:///c:/Users/alexa/OneDrive/Documents/lnx-firewall-manager/internal/models/models.go)
- Adicionar estrutura `OIDCConfig`:
  - `Enabled bool`
  - `ProviderName string`
  - `IssuerURL string`
  - `ClientID string`
  - `ClientSecret string`
  - `RedirectURL string`
  - `Scopes string`
  - `DefaultRole string`
  - `UpdatedAt time.Time`
- Adicionar estruturas de requisição para mudança de senha (`PasswordChangeRequest`), setup de TOTP (`TOTPSetupResponse`), ativação de TOTP (`TOTPEnableRequest`) e revogação de sessão.

#### [MODIFY] [db.go](file:///c:/Users/alexa/OneDrive/Documents/lnx-firewall-manager/internal/db/db.go)
- Criar tabela `oidc_config` na migração do SQLite/PostgreSQL.
- Implementar métodos de banco de dados:
  - `UpdateUserPassword(userID, newHash string) error`
  - `UpdateUserTOTP(userID string, secret string, enabled bool) error`
  - `ListUserSessions(userID string) ([]UserSession, error)`
  - `RevokeUserSession(sessionID, userID string) error`
  - `GetOIDCConfig() (*models.OIDCConfig, error)`
  - `SaveOIDCConfig(cfg *models.OIDCConfig) error`
  - `UpsertFederatedUser(username, displayName, email, role string) (*models.User, error)`

---

### 2. Lógica de Autenticação e Provedor OIDC em Go

#### [MODIFY] [auth.go](file:///c:/Users/alexa/OneDrive/Documents/lnx-firewall-manager/internal/auth/auth.go)
- Implementar resolvedor OIDC nativo em Go (sem dependências externas):
  - Descoberta automática de endpoints via `<IssuerURL>/.well-known/openid-configuration` (`authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`).
  - Geração de URLs de autorização com `state` e `nonce` criptográficos contra ataques CSRF.
  - Troca do código de autorização (`authorization_code`) no `token_endpoint`.
  - Extração e validação de claims do usuário (`sub`, `preferred_username`, `email`, `name`).
- Métodos para validação de complexidade de senha mínima.

---

### 3. API REST e Endpoints do Servidor

#### [MODIFY] [routes.go](file:///c:/Users/alexa/OneDrive/Documents/lnx-firewall-manager/internal/api/routes.go)
- Endpoints públicos:
  - `GET /api/v1/auth/oidc/status`: Retorna se OIDC está ativo e o nome do provedor para a tela de login.
  - `GET /api/v1/auth/oidc/login`: Inicia o fluxo OIDC com redirecionamento para o IdP.
  - `GET /api/v1/auth/oidc/callback`: Callback do IdP, valida o state, troca o token, provisiona o usuário, cria sessão e redireciona para a raiz do painel `/`.
- Endpoints autenticados do usuário logado:
  - `POST /api/v1/user/password`: Altera a senha do usuário local com validação da senha atual e derivação Argon2id.
  - `GET /api/v1/user/totp/setup`: Gera novo segredo TOTP Base32 e string `otpauth://`.
  - `POST /api/v1/user/totp/enable`: Valida o primeiro código de 6 dígitos gerado no app e ativa o 2FA.
  - `POST /api/v1/user/totp/disable`: Desativa o 2FA mediante confirmação de senha.
  - `GET /api/v1/user/sessions`: Lista sessões ativas do usuário.
  - `DELETE /api/v1/user/sessions/{id}`: Encerra uma sessão específica.
- Endpoints administrativos de configuração OIDC:
  - `GET /api/v1/settings/oidc`: Obtém configuração atual (com secret mascarado).
  - `PUT /api/v1/settings/oidc`: Salva/atualiza configuração do provedor OIDC.
  - `POST /api/v1/settings/oidc/test`: Testa conexão e descoberta do Issuer URL informado.

---

### 4. Interface Web (Frontend React)

#### [NEW] [Login.tsx](file:///c:/Users/alexa/OneDrive/Documents/lnx-firewall-manager/web/src/components/Login.tsx)
- Tela de login de alto padrão estético (fundo preto `#000000`, detalhes em amarelo escuro `amber-500`/`amber-600`, logotipo com escudo, tipografia JetBrains Mono / Inter).
- Campos de usuário e senha.
- Campo condicional para código 2FA TOTP (6 dígitos) com suporte a autofoco e aviso visual se o usuário possuir 2FA ativado.
- Feedback amigável para bloqueios temporários por força bruta com contagem de tempo restante.
- Botão estilizado de login SSO via OpenID Connect (Keycloak / Google / Corporativo) quando ativado.

#### [NEW] [UserManagement.tsx](file:///c:/Users/alexa/OneDrive/Documents/lnx-firewall-manager/web/src/components/UserManagement.tsx)
- Painel com abas ou seções claras:
  - **Perfil do Usuário:** Nome, username, tipo de autenticação (local ou federado), papel RBAC (`admin`).
  - **Segurança & Senha:** Formulário de troca de senha com verificação de senha atual, nova senha e indicador de força.
  - **Segundo Fator (2FA TOTP):**
    - Status de ativação.
    - Assistente visual de setup: Chave Base32 formatada, QR Code vetorial e campo para validação imediata do código de 6 dígitos antes de habilitar.
    - Opção segura de desativação.
  - **Sessões Ativas:** Tabela de dispositivos/navegadores conectados com IP, data e botão de desconexão.
  - **Configuração de Autenticação Federada (OIDC):** (visível para administradores)
    - Toggle de ativação do OIDC.
    - Campos: Nome do Provedor, Issuer URL, Client ID, Client Secret, Scopes, Papel padrão atribuído.
    - Botão "Testar Descoberta de Provedor" que chama a API e valida o endpoint `.well-known`.
    - Botão "Salvar Configurações".

#### [MODIFY] [types.ts](file:///c:/Users/alexa/OneDrive/Documents/lnx-firewall-manager/web/src/types.ts)
- Adicionar tipos `UserSession`, `OIDCConfig`, `TOTPSetupData`.

#### [MODIFY] [client.ts](file:///c:/Users/alexa/OneDrive/Documents/lnx-firewall-manager/web/src/api/client.ts)
- Adicionar métodos de API para todas as novas rotas de usuário, TOTP e OIDC.
- Ajustar interceptor para redirecionar ou notificar `onUnauthorized`.

#### [MODIFY] [Navbar.tsx](file:///c:/Users/alexa/OneDrive/Documents/lnx-firewall-manager/web/src/components/Navbar.tsx)
- Adicionar indicador do usuário logado (`root`), papel (`ADMIN`), botão de acesso rápido às configurações de segurança/usuário e botão de Logout.
- Adicionar aba "Segurança & SSO" (ou ícone de usuário com menu dropdown).

#### [MODIFY] [App.tsx](file:///c:/Users/alexa/OneDrive/Documents/lnx-firewall-manager/web/src/App.tsx)
- Gerenciamento de estado de autenticação (`currentUser` / `isAuthenticated`).
- Renderização condicional: se não autenticado, renderiza `<Login />`; se autenticado, renderiza a aplicação com acesso ao `<UserManagement />`.
- Suporte a detecção de retorno de SSO via query params (`?sso=success` ou `?error=...`).

---

## Plano de Verificação

### Testes Automatizados no Backend (Go)
1. **Teste de Autenticação Local e TOTP:**
   ```bash
   go test -v ./internal/auth/...
   ```
   - Validação da geração e verificação de hashes Argon2id.
   - Validação de geração de segredo Base32 e cálculo do TOTP RFC 6238.
   - Validação de bloqueio após 5 tentativas incorretas.

2. **Teste dos Endpoints REST de Usuário e OIDC (`scripts/test_auth_oidc.sh`):**
   - Teste de login com senha incorreta e correta.
   - Teste de troca de senha e login com nova senha.
   - Teste de setup e validação do fluxo TOTP.
   - Teste de salvamento e validação de configuração OIDC.

### Verificação Manual
1. **Tela de Login:**
   - Acessar `http://localhost:8443` desautenticado.
   - Verificar visual preto puro com detalhes em amarelo escuro e feedback de validação.
2. **Painel do Usuário Local:**
   - Efetuar login como `root`.
   - Acessar o painel do usuário e testar alteração de senha e ativação do TOTP com Google Authenticator.
3. **OpenID Connect:**
   - Acessar a aba de OIDC, preencher configuração de teste e acionar o botão de teste de descoberta.
   - Validar a renderização do botão SSO na tela de login.
