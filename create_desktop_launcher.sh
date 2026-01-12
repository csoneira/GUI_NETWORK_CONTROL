#!/usr/bin/env bash
set -euo pipefail

APP_NAME="miniTRASGO Status"
REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPT_PATH="${REPO_DIR}/mingo_status_gui.py"
ICON_PATH="${REPO_DIR}/logo_mingo_network.png"
DESKTOP_DIR="${HOME}/.local/share/applications"
DESKTOP_FILE="${DESKTOP_DIR}/miniTRASGO-status.desktop"

mkdir -p "${DESKTOP_DIR}"

cat > "${DESKTOP_FILE}" <<EOF
[Desktop Entry]
Name=${APP_NAME}
Exec=/usr/bin/env python3 ${SCRIPT_PATH}
Icon=${ICON_PATH}
Terminal=false
Type=Application
Categories=Utility;
EOF

chmod +x "${BASH_SOURCE[0]}"

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "${DESKTOP_DIR}"
fi

echo "Created launcher: ${DESKTOP_FILE}"
