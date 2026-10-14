#!/usr/bin/env bash
# Post-provision configuration for the lab Linux servers (RHEL / Ubuntu / SLES).
# Entra login is handled by the AADSSHLoginForLinux extension; this script wires the AMA/syslog
# pipeline, enables auditd, and registers a light hydration generator for hunting telemetry.
set -uo pipefail

LOGFILE=/var/log/lab-configure.log
exec > >(tee -a "$LOGFILE") 2>&1
echo "=== lab configure-linux $(date -u) ==="

CLOUD_SUFFIX="${1:-us}"          # us = Azure Government, com = commercial
HYDRATION_B64="${2:-}"
HYDRATION_INTERVAL_MIN="${3:-60}"

detect_pkg() {
  if command -v dnf >/dev/null 2>&1; then echo dnf
  elif command -v apt-get >/dev/null 2>&1; then echo apt
  elif command -v zypper >/dev/null 2>&1; then echo zypper
  else echo unknown; fi
}
PKG=$(detect_pkg)
echo "package manager: $PKG"

install_pkg() {
  case "$PKG" in
    dnf)    dnf install -y "$@" ;;
    apt)    DEBIAN_FRONTEND=noninteractive apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
    zypper) zypper --non-interactive install -y "$@" ;;
  esac
}

# --- auditd: generate the Linux security events Sentinel's Syslog/CEF + MDE will pick up ---------
case "$PKG" in
  dnf)    install_pkg audit audit-libs ;;
  apt)    install_pkg auditd audispd-plugins ;;
  zypper) install_pkg audit ;;
esac
systemctl enable --now auditd 2>/dev/null || service auditd start 2>/dev/null || true

cat >/etc/audit/rules.d/lab.rules <<'RULES'
-D
-b 8192
-f 1
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k priv_esc
-w /etc/sudoers.d/ -p wa -k priv_esc
-w /var/log/lastlog -p wa -k logins
-w /etc/ssh/sshd_config -p wa -k sshd
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b64 -S connect -F a2=16 -k net_connect
-a always,exit -F arch=b64 -F euid=0 -S setuid -S setgid -k priv_change
RULES
augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/lab.rules 2>/dev/null || true
systemctl restart auditd 2>/dev/null || true

# --- rsyslog present so AMA Syslog DCR has a source --------------------------------------------
case "$PKG" in
  apt)    install_pkg rsyslog ;;
  dnf)    install_pkg rsyslog ;;
  zypper) install_pkg rsyslog ;;
esac
systemctl enable --now rsyslog 2>/dev/null || true

# --- hydration generator ------------------------------------------------------------------------
if [ -n "$HYDRATION_B64" ]; then
  echo "$HYDRATION_B64" | base64 -d > /usr/local/bin/lab-hydrate.sh
  chmod +x /usr/local/bin/lab-hydrate.sh
  cat >/etc/systemd/system/lab-hydrate.service <<SVC
[Unit]
Description=Lab hydration noise generator
[Service]
Type=oneshot
ExecStart=/usr/local/bin/lab-hydrate.sh
SVC
  cat >/etc/systemd/system/lab-hydrate.timer <<TMR
[Unit]
Description=Run lab hydration every ${HYDRATION_INTERVAL_MIN}m
[Timer]
OnBootSec=5min
OnUnitActiveSec=${HYDRATION_INTERVAL_MIN}min
[Install]
WantedBy=timers.target
TMR
  systemctl daemon-reload
  systemctl enable --now lab-hydrate.timer 2>/dev/null || true
  echo "hydration timer enabled"
fi

echo "CONFIGURE-STATUS: Success"
