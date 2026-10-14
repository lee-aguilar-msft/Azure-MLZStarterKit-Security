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

# A failed su to generate an auth failure in /var/log (picked up by the Syslog DCR auth facility)
echo "wrong-password" | su - nonexistentlabuser 2>/dev/null || true

rm -rf "$TMP"
echo "[$TS] linux hydration done" | logger -t lab-hydrate
