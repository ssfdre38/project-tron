#!/usr/bin/env bash
# install.sh — Install Tron as a systemd service on Linux
# Usage: sudo bash build/linux/install.sh <path-to-Tron.Service-binary>
set -euo pipefail

BINARY="${1:?Usage: sudo bash install.sh <path-to-Tron.Service>}"
INSTALL_DIR="/opt/tron"
SERVICE_NAME="tron"
SERVICE_USER="tron"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Root of the extracted zip (two levels up from build/linux/)
ZIP_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [[ "$EUID" -ne 0 ]]; then
    echo "Error: This script must be run as root (sudo)."
    exit 1
fi

echo "=== Installing Tron to $INSTALL_DIR ==="

# Create dedicated service user
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    echo "  Created service user: $SERVICE_USER"
fi

# Install binary
install -d -m 755 "$INSTALL_DIR"
install -m 755 "$BINARY" "$INSTALL_DIR/tron"

# Install supporting files if present in zip root
for f in appsettings.json; do
    [[ -f "$ZIP_ROOT/$f" ]] && install -m 644 "$ZIP_ROOT/$f" "$INSTALL_DIR/$f"
done
[[ -d "$ZIP_ROOT/plugins" ]]     && cp -r "$ZIP_ROOT/plugins"     "$INSTALL_DIR/"
[[ -d "$ZIP_ROOT/Plugins" ]]     && cp -r "$ZIP_ROOT/Plugins"     "$INSTALL_DIR/plugins"

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

# Create systemd unit
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Tron System Guardian
After=network.target

[Service]
Type=notify
User=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/tron
Restart=always
RestartSec=10
KillSignal=SIGTERM
Environment=DOTNET_ROOT=/usr/share/dotnet

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

echo ""
echo "=== Tron installed and started ==="
echo "  Status:  systemctl status $SERVICE_NAME"
echo "  Logs:    journalctl -u $SERVICE_NAME -f"
echo "  Config:  $INSTALL_DIR/appsettings.json"
