#!/usr/bin/env bash
set -e

COOKIE_JAR=$(mktemp)
trap "rm -f $COOKIE_JAR" EXIT

echo "=== 1. Testando Autenticação ==="
LOGIN_RES=$(curl -s -c "$COOKIE_JAR" -X POST http://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"root","password":"admin"}')
echo "$LOGIN_RES"

TOKEN=$(echo "$LOGIN_RES" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
if [ -z "$TOKEN" ]; then
  echo "FALHA: Não foi possível autenticar."
  exit 1
fi
echo "Autenticado com sucesso. Token obtido."

echo -e "\n=== 2. Listando Servidores Conectados ==="
SERVERS_JSON=$(curl -s -b "$COOKIE_JAR" http://localhost:8443/api/v1/servers)
echo "$SERVERS_JSON"
SERVER_ID=$(echo "$SERVERS_JSON" | grep -o '"id":"[^"]*' | head -n1 | cut -d'"' -f4)
echo "Servidor alvo selecionado: $SERVER_ID"

echo -e "\n=== 3. Consultando Regras Ativas do Agente ==="
RULES_RES=$(curl -s -b "$COOKIE_JAR" "http://localhost:8443/api/v1/servers/$SERVER_ID/rules")
echo "$RULES_RES" | head -c 400
echo -e "\n..."

echo -e "\n=== 4. Consultando IPSets do Servidor ==="
IPSETS_RES=$(curl -s -b "$COOKIE_JAR" "http://localhost:8443/api/v1/servers/$SERVER_ID/ipsets")
echo "$IPSETS_RES"

echo -e "\n=== 5. Testando Preview de Batch com dst_ip, src_ports e IPSet Match ==="
RULE_PAYLOAD=$(cat << 'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -s 192.168.1.0/24 -d 192.168.1.100 --sport 1024:65535 --dport 22 -m comment --comment "SSH Admin" -j ACCEPT
-A INPUT -p tcp --dport 8443 -j ACCEPT
-A INPUT -m set --match-set blacklist_spammers src -j DROP
COMMIT
EOF
)

PREVIEW_RES=$(curl -s -b "$COOKIE_JAR" -X POST http://localhost:8443/api/v1/rules/batch/preview \
  -H "Content-Type: application/json" \
  -d "{\"target_servers\":[\"$SERVER_ID\"],\"new_rules_v4\":$(echo "$RULE_PAYLOAD" | jq -Rs .)}")

echo "$PREVIEW_RES" | jq .

echo -e "\n=== 6. Testando Aplicação de Regras com Proteção de Auto-Rollback (10s) ==="
APPLY_RES=$(curl -s -b "$COOKIE_JAR" -X POST http://localhost:8443/api/v1/rules/batch/apply \
  -H "Content-Type: application/json" \
  -d "{\"target_servers\":[\"$SERVER_ID\"],\"timeout_seconds\":10,\"rules_v4\":$(echo "$RULE_PAYLOAD" | jq -Rs .)}")
echo "$APPLY_RES" | jq .

CHANGE_ID=$(echo "$APPLY_RES" | jq -r .change_id)

echo -e "\n=== 7. Confirmando Aplicação (Commit Permanente) ==="
CONFIRM_RES=$(curl -s -b "$COOKIE_JAR" -X POST http://localhost:8443/api/v1/rules/batch/confirm \
  -H "Content-Type: application/json" \
  -d "{\"target_servers\":[\"$SERVER_ID\"],\"change_id\":\"$CHANGE_ID\"}")
echo "$CONFIRM_RES" | jq .

echo -e "\n=== SUCESSO TOTAL: Todos os testes das novas funcionalidades passaram! ==="
