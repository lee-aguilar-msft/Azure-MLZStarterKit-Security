#!/bin/bash
# prep-linux.sh — runs first on every Linux lab VM, before any extension that installs packages.
# 1. Waits (bounded) for cloud-init / first-boot package activity so the AADSSHLoginForLinux and
#    AzureMonitorLinuxAgent installers do not race the package-manager lock (seen on Ubuntu 22.04).
# 2. Disables the unattended apt timers for the lab (they re-take the lock at random times).
# 3. Refreshes repo metadata once, with hard time limits, so an egress problem shows up here with a
#    readable message instead of as an opaque extension failure.
# 4. Never leaves the package lock held: a metadata refresh that hangs (seen on Ubuntu in run 4 — an
#    `apt-get update` stalled for 30+ minutes, the run command timed out and the next extension failed
#    on "Could not get lock /var/lib/apt/lists/lock") is killed before the script exits.
# Every step is time-boxed so the whole script finishes well inside the run command's 1500 s timeout.
set -u
LOG=/var/log/lab-prep-linux.log
log() { echo "[prep-linux $(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

# seconds a process has been running
age() { ps -o etimes= -p "$1" 2>/dev/null | tr -d ' '; }

# kill metadata/upgrade jobs (never a dpkg install in progress) that hold the apt lock for too long
release_apt_lock() {
  local max_age=$1 p a
  for p in $(pgrep -f 'apt-get update|apt.systemd.daily|unattended-upgr|/usr/lib/apt/methods/' 2>/dev/null); do
    a=$(age "$p"); [ -n "$a" ] || continue
    if [ "$a" -ge "$max_age" ]; then
      log "killing stuck package job pid $p (running ${a}s): $(ps -o args= -p "$p" | cut -c1-120)"
      kill "$p" 2>/dev/null; sleep 2; kill -9 "$p" 2>/dev/null
    fi
  done
}

APT_OPTS=(-y -q -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 -o Acquire::Retries=2
          -o DPkg::Lock::Timeout=60)

if command -v cloud-init >/dev/null 2>&1; then
  log "waiting for cloud-init (max 300 s)"; timeout 300 cloud-init status --wait >/dev/null 2>&1 || log "cloud-init still running - continuing"
fi

if command -v apt-get >/dev/null 2>&1; then
  systemctl disable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
  systemctl stop apt-daily.service apt-daily-upgrade.service unattended-upgrades >/dev/null 2>&1 || true
  for i in $(seq 1 60); do   # up to 300 s
    fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1 || break
    sleep 5
  done
  release_apt_lock 240
  dpkg --configure -a >/dev/null 2>&1 || true
  log "refreshing apt metadata (max 300 s)"
  if ! DEBIAN_FRONTEND=noninteractive timeout 300 apt-get update "${APT_OPTS[@]}" >>"$LOG" 2>&1; then
    log "WARN: apt-get update failed or timed out - check firewall egress to azure.archive.ubuntu.com / *.ubuntu.com / packages.microsoft.com (port 80 and 443)"
  fi
  release_apt_lock 0
  fuser /var/lib/apt/lists/lock >/dev/null 2>&1 && log "WARN: apt lists lock still held" || log "apt lock free"
elif command -v dnf >/dev/null 2>&1; then
  for i in $(seq 1 60); do
    pgrep -x dnf >/dev/null 2>&1 || pgrep -x yum >/dev/null 2>&1 || break
    sleep 5
  done
  log "refreshing dnf metadata (Azure RHUI, max 300 s)"
  timeout 300 dnf -q -y makecache >>"$LOG" 2>&1 || log "WARN: dnf makecache failed - check firewall egress to rhui-*.microsoft.com / rhui4-*.microsoft.com (Azure RHUI)"
elif command -v zypper >/dev/null 2>&1; then
  for i in $(seq 1 60); do
    pgrep -x zypper >/dev/null 2>&1 || break
    sleep 5
  done
  timeout 300 zypper --non-interactive refresh >>"$LOG" 2>&1 || log "WARN: zypper refresh failed - check firewall egress to *.susecloud.net"
fi
log "done"
exit 0
