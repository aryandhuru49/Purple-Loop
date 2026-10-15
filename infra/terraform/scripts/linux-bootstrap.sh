#!/bin/bash
# Purple Loop lab: Linux bootstrap (Debian).
#
# Compute Engine runs this as root at every boot (metadata key startup-script).
# Each step is safe to re-run: packages are installed only if missing, and the
# audit rules and Ops Agent config are rewritten every boot.
#
# Log: /var/log/purple-loop-bootstrap.log

set -euo pipefail
exec >>/var/log/purple-loop-bootstrap.log 2>&1
echo "=== bootstrap $(date --iso-8601=seconds) ==="

# ---------------------------------------------------------------------------
# 1. auditd: process execution and changes to key security files
# ---------------------------------------------------------------------------
if ! dpkg -s auditd >/dev/null 2>&1; then
  apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q auditd
fi

cat >/etc/audit/rules.d/purple-loop.rules <<'EOF'
# Every program execution (Linux equivalent of Sysmon event 1 / 4688).
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec
# Writes to account, sudo and SSH configuration.
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
# Persistence locations.
-w /etc/crontab -p wa -k persistence
-w /etc/cron.d/ -p wa -k persistence
-w /etc/systemd/system/ -p wa -k persistence
EOF
augenrules --load
systemctl enable --now auditd

# ---------------------------------------------------------------------------
# 2. Google Cloud Ops Agent: ship audit log and systemd journal
# ---------------------------------------------------------------------------
if ! dpkg -s google-cloud-ops-agent >/dev/null 2>&1; then
  # Google's documented install method, pinned to major version 2.
  curl -sSfo /tmp/add-google-cloud-ops-agent-repo.sh     https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
  bash /tmp/add-google-cloud-ops-agent-repo.sh --also-install --version='2.*.*'
fi

# Receiver IDs become Cloud Logging log names (auditd, journald), which the
# BigQuery sink in logging.tf selects. Debian cloud images log to the journal
# rather than /var/log/syslog, so the journal is read directly.
new_config=$(cat <<'EOF'
logging:
  receivers:
    auditd:
      type: files
      include_paths: [/var/log/audit/audit.log]
    journald:
      type: systemd_journald
  service:
    pipelines:
      lab_pipeline:
        receivers: [auditd, journald]
EOF
)
config=/etc/google-cloud-ops-agent/config.yaml
if [[ "$(cat "$config" 2>/dev/null)" != "$new_config" ]]; then
  printf '%s\n' "$new_config" >"$config"
  systemctl restart google-cloud-ops-agent
  echo "Ops Agent: config updated, restarted."
fi

echo "Bootstrap: done."
