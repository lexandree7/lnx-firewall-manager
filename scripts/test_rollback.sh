#!/bin/bash
set -e

BASE_URL="http://localhost:8443"
COOKIE_JAR="/tmp/lfm_cookie.txt"

echo "[TEST AUTO-ROLLBACK] Obtendo Server ID..."
SERVERS_RESP=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/api/v1/servers")
SERVER_ID=$(echo "$SERVERS_RESP" | grep -o '"id":"[^"]*' | head -n 1 | cut -d'"' -f4)

echo "[TEST AUTO-ROLLBACK] Aplicando regra com timeout curto de 5 segundos e NÃO confirmando..."
APPLY_PAYLOAD=$(cat <<EOF
{
  "target_servers": ["$SERVER_ID"],
  "rules_v4": "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp --dport 9999 -j DROP\nCOMMIT\n",
  "timeout_seconds": 5
}
EOF
)

curl -s -b "$COOKIE_JAR" -X POST "$BASE_URL/api/v1/rules/batch/apply" \
    -H "Content-Type: application/json" \
    -d "$APPLY_PAYLOAD"
echo ""

echo "[TEST AUTO-ROLLBACK] Aguardando 7 segundos para o timer local do agente expirar..."
sleep 7

echo "[TEST AUTO-ROLLBACK] Verificando logs de auditoria para confirmar que o auto-rollback foi executado pelo agente:"
AUDIT_LOGS=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/api/v1/audit/logs")
echo "$AUDIT_LOGS" | grep -o '"action":"[^"]*"' | head -n 5

if [[ "$AUDIT_LOGS" == *"ROLLBACK_AUTO"* ]]; then
    echo "=========================================================="
    echo " SUCESSO: AUTO-ROLLBACK DISPARADO E REGISTRADO COM ÊXITO! "
    echo "=========================================================="
else
    echo "ATENÇÃO: Rollback não encontrado nos logs de auditoria!"
    exit 1
fi
