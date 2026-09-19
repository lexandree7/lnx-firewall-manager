#!/bin/sh
set -e

# Cria usuário e grupo de serviço 'lfm'
if ! getent group lfm >/dev/null; then
    groupadd --system lfm
fi
if ! getent passwd lfm >/dev/null; then
    useradd --system -g lfm --no-create-home --shell /usr/sbin/nologin lfm
fi

mkdir -p /var/lib/fw-server/certs
chown -R lfm:lfm /var/lib/fw-server
chmod 700 /var/lib/fw-server
chmod 700 /var/lib/fw-server/certs

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable fw-server || true
fi

echo "fw-server instalado com sucesso!"
echo "Para iniciar: systemctl start fw-server"
