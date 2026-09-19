#!/bin/sh
set -e

# Cria diretórios de configuração e estado com permissões restritas
mkdir -p /etc/fw-agent/certs
chmod 700 /etc/fw-agent
chmod 700 /etc/fw-agent/certs

mkdir -p /var/lib/fw-agent
chmod 700 /var/lib/fw-agent

# Recarrega systemd se disponível
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable fw-agent || true
fi

echo "fw-agent instalado com sucesso!"
echo "Para registrar esta máquina: fw-agent enroll --server https://painel:8443 --token <TOKEN>"
