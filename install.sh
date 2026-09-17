#!/usr/bin/env bash
# Install the SSH Defense Gateway as a native systemd service.
#
# Copies the application tree under INSTALL_ROOT, renders ssh-gateway.service
# with the chosen prefix, installs it into SYSTEMD_DIR, builds the venv, and
# enables the service. Overrides (mainly for testing or user-level installs):
#   INSTALL_ROOT  - where the application lands   (default /opt/ssh-defense-gateway)
#   SYSTEMD_DIR   - systemd unit directory        (default /etc/systemd/system)
#   SKIP_VENV=1   - skip venv creation / pip install
#   SKIP_SYSTEMD=1 - skip daemon-reload / enable
set -euo pipefail

INSTALL_ROOT="${INSTALL_ROOT:-/opt/ssh-defense-gateway}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE_NAME="ssh-gateway.service"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKIP_VENV="${SKIP_VENV:-0}"
SKIP_SYSTEMD="${SKIP_SYSTEMD:-0}"

if [[ "${SYSTEMD_DIR}" == "/etc/systemd/system" && "$(id -u)" -ne 0 ]]; then
    echo "error: a system-level install into ${SYSTEMD_DIR} requires root;" >&2
    echo "       run with sudo or set SYSTEMD_DIR to a user-writable directory" >&2
    exit 1
fi

echo "Installing SSH Defense Gateway into ${INSTALL_ROOT}"

# 1. Application tree -----------------------------------------------------------------
mkdir -p "${INSTALL_ROOT}"
cp -r "${SOURCE_DIR}/ai" "${INSTALL_ROOT}/"
cp -r "${SOURCE_DIR}/core" "${INSTALL_ROOT}/"
cp -r "${SOURCE_DIR}/config" "${INSTALL_ROOT}/"
cp "${SOURCE_DIR}/main.py" "${INSTALL_ROOT}/"
cp "${SOURCE_DIR}/requirements.txt" "${INSTALL_ROOT}/"
mkdir -p "${INSTALL_ROOT}/logs"

# 2. Ownership and permissions --------------------------------------------------------
if [[ "$(id -u)" -eq 0 ]]; then
    chown -R root:root "${INSTALL_ROOT}"
fi
find "${INSTALL_ROOT}" -type d -exec chmod 755 {} \;
find "${INSTALL_ROOT}" -type f -exec chmod 644 {} \;

# 3. Virtualenv for the systemd unit's ExecStart --------------------------------------
if [[ "${SKIP_VENV}" -ne 1 ]]; then
    if [[ ! -x "${INSTALL_ROOT}/.venv/bin/python" ]]; then
        python3 -m venv "${INSTALL_ROOT}/.venv"
    fi
    "${INSTALL_ROOT}/.venv/bin/pip" install -r "${INSTALL_ROOT}/requirements.txt"
fi

# 4. Rendered systemd unit ------------------------------------------------------------
mkdir -p "${SYSTEMD_DIR}"
sed "s|@INSTALL_ROOT@|${INSTALL_ROOT}|g" \
    "${SOURCE_DIR}/${SERVICE_NAME}" > "${SYSTEMD_DIR}/${SERVICE_NAME}"
chmod 644 "${SYSTEMD_DIR}/${SERVICE_NAME}"
if [[ "$(id -u)" -eq 0 ]]; then
    chown root:root "${SYSTEMD_DIR}/${SERVICE_NAME}"
fi

# 5. Register and enable --------------------------------------------------------------
if [[ "${SKIP_SYSTEMD}" -ne 1 ]]; then
    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"
fi

echo "Done. Start the service with: systemctl start ${SERVICE_NAME}"