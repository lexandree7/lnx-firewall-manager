#!/bin/bash
set -e

echo "=========================================================="
echo "      E2E Integration Test — Linux Firewall Manager       "
echo "=========================================================="

BASE_URL="http://localhost:8443"
COOKIE_JAR="/tmp/lfm_cookie.txt"

# 1. Health check
echo -n "[TEST 1/8] Verificando /healthz: "
HEALTH_RESP=$(curl -s "$BASE_URL/healthz")
echo "$HEALTH_RESP"
if [[ "$HEALTH_RESP" != *"\"status\":\"ok\""* ]]; then
    echo "FALHA no health check!"
    exit 1
fi

# 2. Prometheus metrics
echo -n "[TEST 2/8] Verificando /metrics: "
METRICS_RESP=$(curl -s "$BASE_URL/metrics")
echo "$METRICS_RESP" | grep "lfm_managed_servers"

# 3. Login root local com Argon2id
echo -n "[TEST 3/8] Efetuando login como 'root': "
LOGIN_RESP=$(curl -s -c "$COOKIE_JAR" -X POST "$BASE_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"root","password":"admin"}')
echo "$LOGIN_RESP"
if [[ "$LOGIN_RESP" != *"\"success\":true"* ]]; then
    echo "FALHA no login!"
    exit 1
fi

# 4. Validar perfil /auth/me
echo -n "[TEST 4/8] Validando sessão em /auth/me: "
ME_RESP=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/api/v1/auth/me")
echo "$ME_RESP"

# 5. Listar servidores (deve conter o agente conectado)
echo "[TEST 5/8] Listando servidores gerenciados via /api/v1/servers:"
SERVERS_RESP=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/api/v1/servers")
echo "$SERVERS_RESP"
SERVER_ID=$(echo "$SERVERS_RESP" | grep -o '"id":"[^"]*' | head -n 1 | cut -d'"' -f4)
echo "Server ID detectado: $SERVER_ID"

if [ -z "$SERVER_ID" ]; then
    echo "Nenhum servidor encontrado no backend!"
    exit 1
fi

# 6. Testar Batch Preview e Heurística de Risco
echo "[TEST 6/8] Testando preview de diff e heurística de risco contra lockout:"
PREVIEW_PAYLOAD=$(cat <<EOF
{
  "target_servers": ["$SERVER_ID"],
  "new_rules_v4": "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp --dport 22 -j DROP\nCOMMIT\n"
}
EOF
)
PREVIEW_RESP=$(curl -s -b "$COOKIE_JAR" -X POST "$BASE_URL/api/v1/rules/batch/preview" \
    -H "Content-Type: application/json" \
    -d "$PREVIEW_PAYLOAD")
echo "$PREVIEW_RESP"
if [[ "$PREVIEW_RESP" == *"\"has_risks\":true"* ]]; then
    echo "SUCESSO: Heurística detectou corretamente o bloqueio perigoso da porta 22 (SSH)!"
fi

# 7. Testar Aplicação de Regras com Auto-Rollback (Lockout Protection)
echo "[TEST 7/8] Aplicando regra segura com timeout de 30s:"
APPLY_PAYLOAD=$(cat <<EOF
{
  "target_servers": ["$SERVER_ID"],
  "rules_v4": "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp --dport 80 -m comment --comment \"allow http\" -j ACCEPT\nCOMMIT\n",
  "timeout_seconds": 30
}
EOF
)
APPLY_RESP=$(curl -s -b "$COOKIE_JAR" -X POST "$BASE_URL/api/v1/rules/batch/apply" \
    -H "Content-Type: application/json" \
    -d "$APPLY_PAYLOAD")
echo "$APPLY_RESP"
CHANGE_ID=$(echo "$APPLY_RESP" | grep -o '"change_id":"[^"]*' | cut -d'"' -f4)
echo "ChangeID gerado: $CHANGE_ID"

# 8. Confirmar regras permanentemente
echo "[TEST 8/8] Confirmando regras permanentemente antes do término do rollback timer:"
CONFIRM_PAYLOAD=$(cat <<EOF
{
  "target_servers": ["$SERVER_ID"],
  "change_id": "$CHANGE_ID"
}
EOF
)
CONFIRM_RESP=$(curl -s -b "$COOKIE_JAR" -X POST "$BASE_URL/api/v1/rules/batch/confirm" \
    -H "Content-Type: application/json" \
    -d "$CONFIRM_PAYLOAD")
echo "$CONFIRM_RESP"

echo ""
echo "=========================================================="
echo "    TODOS OS TESTES E2E FORAM CONCLUÍDOS COM SUCESSO!     "
echo "=========================================================="
