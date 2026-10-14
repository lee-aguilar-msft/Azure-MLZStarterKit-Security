#!/bin/bash
# prep-linux.sh — runs first on every Linux lab VM, before any extension that installs packages.
# 1. Waits for cloud-init / first-boot package activity to finish so the AADSSHLoginForLinux and
#    AzureMonitorLinuxAgent installers do not race the package-manager lock (seen on Ubuntu 22.04).
# 2. Disables the unattended apt timers for the lab (they re-take the lock at random times).
# 3. Refreshes repo metadata once so an egress problem (e.g. Azure RHUI blocked by the firewall)
#    shows up here with a readable message instead of as an opaque extension failure.
set -u
log() { echo "[prep-linux] $*"; }

if command -v cloud-init >/dev/null 2>&1; then
  log "waiting for cloud-init"; timeout 600 cloud-init status --wait >/dev/null 2>&1 || true
fi

if command -v apt-get >/dev/null 2>&1; then
  systemctl disable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
  systemctl stop unattended-upgrades >/dev/null 2>&1 || true
  for i in $(seq 1 120); do
    fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1 || break
    sleep 5
  done
  log "apt lock free; refreshing metadata"
  DEBIAN_FRONTEND=noninteractive apt-get update -y -q >/dev/null 2>&1 || log "WARN: apt-get update failed — check firewall egress to *.ubuntu.com / packages.microsoft.com"
elif command -v dnf >/dev/null 2>&1; then
  for i in $(seq 1 120); do
    pgrep -x dnf >/dev/null 2>&1 || pgrep -x yum >/dev/null 2>&1 || break
    sleep 5
  done
  log "refreshing dnf metadata (Azure RHUI)"
  dnf -q -y makecache >/dev/null 2>&1 || log "WARN: dnf makecache failed — check firewall egress to rhui-*.microsoft.com / rhui4-*.microsoft.com (Azure RHUI)"
elif command -v zypper >/dev/null 2>&1; then
  for i in $(seq 1 120); do
    pgrep -x zypper >/dev/null 2>&1 || break
    sleep 5
  done
  zypper --non-interactive refresh >/dev/null 2>&1 || log "WARN: zypper refresh failed — check firewall egress to *.susecloud.net"
fi
log "done"
exit 0
