#!/usr/bin/env bash
# Lab data hydration for Linux: ordinary admin/user activity so Syslog + MDE for Linux have material
# to hunt over. Benign noise against the lab's own box, not an attack simulation.
set -uo pipefail
TS=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
echo "[$TS] linux hydration tick on $(hostname)" | logger -t lab-hydrate

TMP=$(mktemp -d /tmp/lab.XXXXXX)
for i in 1 2 3 4 5; do echo "sample $i $RANDOM" > "$TMP/doc$i.txt"; done
ls -la /etc >/dev/null 2>&1
id >/dev/null 2>&1
ps aux >/dev/null 2>&1
ss -tunap >/dev/null 2>&1 || netstat -tunap >/dev/null 2>&1 || true
getent passwd >/dev/null 2>&1

# A sudo invocation (generates an auditd priv-esc event) and a benign outbound request
sudo -n true 2>/dev/null || true
curl -s -m 15 https://www.microsoft.com >/dev/null 2>&1 || true

# An SSH password attempt for a user that does not exist, against this machine's own sshd: sshd and PAM log
# "Failed password for invalid user" / "user unknown" to auth/authpriv (picked up by the Syslog DCR).
# (A non-interactive `su` never reaches PAM, so it logged nothing.) Every second hour only: 12 a day stays
# under the 15-attempt thresholds of the SSH brute-force / authpriv rules - this is noise, not a detection test
# (templates/scripts/Test-LabDetections.ps1 is the detection test).
if [ $(( $(date -u +%H | sed 's/^0//') % 2 )) -eq 0 ] && command -v ssh >/dev/null 2>&1; then
  AP=$(mktemp /tmp/lab-askpass.XXXXXX); printf '#!/bin/sh\necho wrong-password\n' > "$AP"; chmod 700 "$AP"
  SSH_ASKPASS="$AP" SSH_ASKPASS_REQUIRE=force timeout 20 ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 -o ConnectTimeout=10 \
    nonexistentlabuser@127.0.0.1 true >/dev/null 2>&1 || true
  rm -f "$AP"
fi

rm -rf "$TMP"
echo "[$TS] linux hydration done" | logger -t lab-hydrate
