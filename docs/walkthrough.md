# Walkthrough: Sincronização em Tempo Real e Persistência de Regras de Firewall

Solução e diagnóstico completo do problema de sincronização de regras: quando o operador criava e confirmava uma regra de firewall no painel web, a regra não permanecia listada após a aplicação ou recarregamento da interface.

---

## 1. Análise da Causa Raiz (Root Cause Analysis)

A investigação revelou uma desconexão em três pontos do fluxo de dados:

1. **Estado Mock no Frontend (`RuleManager.tsx`)**:
   - O componente `RuleManager` inicializava sua lista de regras através de um estado estático (`useState<Rule[]>([ ...mock... ])`).
   - Não havia chamada automática para `loadLiveRules` no ciclo de vida do componente (`useEffect` no mount ou na troca de `selectedServerId`).
   - O botão "Sincronizar Kernel" existia apenas como acionador manual e emitia alertas intrusivos (`alert(...)`), além de falhar silenciosamente se o retorno tivesse 0 regras.
   - Sempre que o operador navegava entre abas ("Servidores" ↔ "Regras") ou recarregava a página (F5), o React remontava o componente, descartando as regras em memória e restaurando as 10 regras mockadas de exemplo.

2. **Desacoplamento do Fluxo de Commit no Frontend (`App.tsx`)**:
   - Quando o operador confirmava o lote no banner de proteção contra lockout (`handleConfirmCommit`), a API executava `/rules/batch/confirm`, mas o `App.tsx` não emitia qualquer gatilho de recarga para o `RuleManager`.

3. **Retorno do Agente e Hub sem Regras Atualizadas (`client.go` & `hub.go`)**:
   - Após executar `APPLY_RULES` ou `CONFIRM_COMMIT`, o agente enviava uma mensagem genérica de `CMD_RESULT` sem anexar o novo dump de regras do kernel.
   - O servidor de controle mantinha apenas o estado capturado no handshake inicial (`HELLO`) ou aguardava o ciclo de heartbeat periódico (10 segundos), resultando em leituras desatualizadas da API `/api/v1/servers/{id}/rules`.
   - O endpoint `/api/v1/rules/batch/apply` esperava campos `rules_v4`, enquanto o preview utilizava `new_rules_v4`, podendo descartar payloads caso houvesse divergência de nomenclatura.

---

## 2. Alterações Implementadas

### Backend (Go)

1. **Agente (`internal/agent/client.go`)**:
   - No `handleServerCommand`, imediatamente após processar qualquer comando (`APPLY_RULES`, `CONFIRM_COMMIT`, `RESTORE_BACKUP`, etc.), o agente executa `c.executor.DumpIptables` e anexa `current_rules_v4`, `current_rules_v6` e o hash canônico `rules_hash` na resposta `CMD_RESULT`.
   - Em caso de auto-rollback por expiração de timer (`onRollbackExecuted`), anexa também o estado revertido das regras em `ROLLBACK_REPORT`.

2. **Hub do Servidor (`internal/server/hub.go`)**:
   - No recebimento de `CMD_RESULT` e `ROLLBACK_REPORT`, atualiza atomicamente `s.LastRulesV4`, `s.LastRulesV6` e `s.LastRulesHash` na sessão do agente.
   - Persiste o hash no banco de dados SQLite (`srv.LastCanonicalHash`).
   - Realiza broadcast do evento WebSocket `rules_updated` para todos os clientes de frontend conectados:
     ```json
     { "event": "rules_updated", "server_id": "srv_..." }
     ```

3. **Rotas e API REST (`internal/api/routes.go`)**:
   - No `handleBatchApply`, passou a aceitar tanto `rules_v4` quanto `new_rules_v4` (e suas variantes v6), além de validar explicitamente que regras não vazias foram transmitidas, prevenindo aplicações vazias acidentais.

### Frontend (React + TypeScript)

1. **Gerenciador de Regras (`web/src/components/RuleManager.tsx`)**:
   - Implementação da função `loadLiveRules(targetId, silent = false)` com leitura integral de tabelas (`*filter`, `*nat`, `*raw`, etc.), chains, políticas padrão e contadores de pacotes/bytes.
   - Preservação do texto canônico de cada regra (`raw_rule_text`) para garantir 100% de compatibilidade na geração do `iptables-save`.
   - `useEffect` automático: sincroniza com o kernel sempre que o firewall alvo for selecionado (`selectedServerId`) ou quando um evento de atualização (`rulesUpdateKey`) for disparado.
   - Indicadores visuais na barra de título:
     - `🟡 Kernel Sincronizado (N regras)`: Confirmação visual de que as regras na tela batem com o kernel do host gerenciado.
     - `⚠️ Modificado Localmente`: Alerta de rascunho com alterações pendentes de aplicação.
   - Banner de orientação rápida no modo "Todos os Servidores", permitindo selecionar um firewall específico com 1 clique.

2. **Aplicação Principal (`web/src/App.tsx`)**:
   - Estado reativo `rulesUpdateKey` que é incrementado automaticamente:
     - Ao receber evento WebSocket `rules_updated` vindo do hub.
     - Ao concluir `handleConfirmCommit` (confirmação permanente da regra).
     - Ao disparar auto-rollback preventivo.
   - Seleção inteligente de servidor inicial: conecta diretamente ao primeiro firewall online detectado, evitando que o painel abra em modo rascunho genérico.

---

## 3. Verificação Automatizada End-to-End

Foi executado o script de validação de ciclo completo [`test_sync_flow.py`](file:///C:/Users/alexa/.gemini/antigravity/brain/ba6eeba7-e0e9-4c4c-a2fa-464d8125d3ef/scratch/test_sync_flow.py):

```
[1] Server target: LexandreePC (ID: srv_1789821530959092377, status: online)
[2] Initial raw rules size: 2364 bytes
[3] Applying batch rules with safety timeout 30s...
[4] Rules applied in test mode! Change ID: chg_1789845821875000050
[5] Confirming commit permanently...
[6] Confirm response: {'message': 'Regras confirmadas permanentemente em todos os nós alvo', 'success': True}
[7] Fetching updated rules from server API...
[SUCCESS] Test rule found in raw_rules_v4!
[SUCCESS] Test rule found in parsed_v4 rules list! Total filter rules: 11
[SUCCESS] Test rule confirmed live inside Linux kernel iptables -S:
   -> -A INPUT -p tcp -m multiport --dports 9443 -m comment --comment LFM_AUTO_SYNC_TEST_9443 -j ACCEPT

ALL RULE SYNC VERIFICATIONS PASSED 100%!
```

---

## 4. Como Validar no Navegador

1. Abra a aplicação em **`http://localhost:8443`** (Credenciais: `root` / `admin`).
2. Acesse a guia **Regras & Chains**.
3. Observe que o servidor **LexandreePC** já vem selecionado por padrão e o selo **"Kernel Sincronizado (9 regras)"** aparece no topo.
4. Clique em **"Nova Regra"**:
   - Porta de destino: `8080` (TCP).
   - Comentário: `Teste Producao 8080`.
   - Clique em **Salvar**. Note o badge **"Modificado Localmente"**.
5. Clique em **"Revisar & Aplicar"** e confirme no modal com proteção de 30s.
6. Clique no botão de confirmação definitiva no banner amarelo: **"Confirmar Permanência Agora"**.
7. Observe que:
   - A regra permanece na tabela imediatamente após o commit.
   - Pressionar **F5** ou alternar entre abas do sistema mantém a regra listada normalmente.
   - Clicar no botão **"Sincronizar Kernel"** atualiza os contadores em tempo real.
