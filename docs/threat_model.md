# Modelo de Ameaças (STRIDE) e Registro de Riscos — LFM

## 1. Superfície de Ataque e Suposições de Confiança

O Linux Firewall Manager opera em um domínio crítico de infraestrutura, com privilégios para alterar políticas de filtragem de pacotes do kernel Linux. A segurança foi arquitetada sob o princípio do menor privilégio, segregação de deveres e defesa em profundidade.

### Fronteiras de Confiança (Trust Boundaries)
1. **Fronteira 1 — Operador / Internet $\leftrightarrow$ Servidor de Controle (`fw-server`)**:
   - Navegadores web e administradores acessam a API/SPA através de HTTPS e WSS.
2. **Fronteira 2 — Provedor de Identidade Externo (IdP) $\leftrightarrow$ `fw-server`**:
   - Autenticação OIDC sobre canais TLS com validação de tokens JWT/JWKS e PKCE.
3. **Fronteira 3 — Servidor de Controle $\leftrightarrow$ Agente (`fw-agent`)**:
   - Túnel gRPC bidirecional mTLS (autenticação mútua estrita X.509).
4. **Fronteira 4 — Agente $\leftrightarrow$ Kernel Linux (`netfilter` / `iptables` / `ipset`)**:
   - Execução local via invocação direta de binários com argumentos em vetor (`os/exec`), sem shell intermediário.

---

## 2. Análise de Ameaças pelo Modelo STRIDE

| Categoria STRIDE | Vetor de Ameaça Identificado | Nível de Risco | Mitigação Implementada na Arquitetura |
| :--- | :--- | :---: | :--- |
| **Spoofing (Falsificação)** | Agente malicioso ou invasor tentando se passar por um servidor gerenciado legítimo para receber regras ou injetar falsas métricas. | **Alto** | **mTLS Obrigatório**: Cada agente possui um certificado X.509 exclusivo gerado durante o enrollment. O servidor valida a cadeia da CA interna e o número de série contra a lista de revogação (CRL). |
| **Spoofing (Falsificação)** | Atacante forjando sessão de operador ou tentando sequestro de sessão web. | **Alto** | Cookies de sessão com flags `HttpOnly`, `Secure` e `SameSite=Strict`. Proteção contra CSRF e validação estrita do `state` e `code_verifier` (PKCE) no OIDC. |
| **Tampering (Adulteração)** | Manipulação maliciosa de regras de firewall para abrir portas de invasão ou injetar comandos via shell. | **Crítico** | **Zero-Shell Execution**: Agente nunca invoca `sh` ou `bash`. Argumentos são sanitizados e validados contra expressões regulares estritas antes de serem passados para `iptables-restore`. |
| **Tampering (Adulteração)** | Alteração manual não autorizada das regras diretamente no servidor gerenciado (via SSH local). | **Médio** | **Detecção de Drift Automática**: Agente calcula periodicamente o hash criptográfico do ruleset ativo e compara com o estado desejado no banco central, disparando alertas imediatos. |
| **Repudiation (Repúdio)** | Operador aplica regras prejudiciais ou desativa o firewall e nega ter realizado a ação. | **Alto** | **Trilha de Auditoria Imutável**: Tabela de auditoria append-only registra o usuário, IP de origem, timestamp, diff unificado completo da regra e status do resultado. Sem API de exclusão. |
| **Information Disclosure (Vazamento)** | Interceptação de regras sensíveis, topologia de rede, tokens de enrollment ou dados de telemetria em trânsito. | **Alto** | Todo o tráfego externo e interno utiliza TLS 1.3/1.2 com cifras seguras. Tokens de enrollment são hasheados com SHA-256 no banco e exibidos apenas uma vez no momento da criação. |
| **Denial of Service (DoS)** | Aplicação acidental ou maliciosa de regra de firewall que bloqueia o SSH ou a conexão do próprio agente com o servidor (**Lockout**). | **Crítico** | **Safety Mechanism "Confirm or Revert"**: O agente aplica a regra com um timer local de segurança (ex: 30s). Se a conectividade com o servidor cair ou o operador não confirmar, o agente restaura automaticamente o snapshot anterior. |
| **Elevation of Privilege (Privilégios)** | Usuário com perfil `viewer` ou `operator` tentando executar ações administrativas ou alterar regras em servidores fora do seu escopo. | **Alto** | **RBAC Estrito e Escopo por Tags/Grupos**: Middleware de autorização no backend valida cada endpoint contra o papel do usuário e seu escopo permitido antes de repassar o comando. |
| **Elevation of Privilege (Privilégios)** | Comprometimento do binário `fw-agent` levando a escalonamento de privilégios root irrestritos na máquina host. | **Crítico** | **Hardening de Systemd e Mínimo Privilégio**: O daemon `fw-agent` opera com `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true` e limite estrito de Linux Capabilities: apenas `CAP_NET_ADMIN` e `CAP_NET_RAW`. |

---

## 3. Registro de Riscos Conhecidos e Limitações Operacionais

| ID | Risco Conhecido | Probabilidade | Impacto | Plano de Contingência / Ação Recomendada |
| :---: | :--- | :---: | :---: | :--- |
| **R-01** | Conflito com outros gerenciadores de firewall locais (ex.: `UFW`, `firewalld`). | Média | Alto | A documentação e o script de pré-instalação do agente alertam e recomendam a desativação do UFW/firewalld para evitar que dois daemons sobrescrevam as regras concorrentemente. |
| **R-02** | Esgotamento de memória do kernel por `ipset` excessivamente grande vindo de blocklist externa corrompida. | Baixa | Alto | O agente e o servidor impõem um limite máximo de entradas configurável (`maxelem`, padrão 65.536 ou 262.144) e validam sintaticamente cada linha antes de emitir `ipset restore`. |
| **R-03** | Expiração acidental da CA interna gerando desconexão em massa de todos os agentes. | Baixa | Crítico | O servidor monitora a validade dos certificados e emite alertas na interface quando a CA ou certificados estiverem a menos de 60 dias da expiração, além de suportar rotação transparente de chaves. |
| **R-04** | Reinicialização inesperada do servidor gerenciado durante o período de 30s de teste de lockout. | Muito Baixa | Médio | O agente persiste o lock de rollback em `/var/lib/fw-agent/rollback.lock`. Se a máquina reiniciar antes do commit, o agente restaura o estado seguro imediatamente na inicialização. |
