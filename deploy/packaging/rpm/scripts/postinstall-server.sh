#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
set -euo pipefail

ensure_safe_dir() {
  local d="$1" owner="$2" grp="$3" mode="$4"
  if [ -L "$d" ]; then
    echo "GRDR-PKG-0001: refusing to follow symlink directory $d" >&2
    exit 1
  fi
  install -d -o "$owner" -g "$grp" -m "$mode" "$d"
  chown "$owner:$grp" "$d"
  chmod "$mode" "$d"
}

if command -v systemd-sysusers >/dev/null 2>&1; then
  systemd-sysusers /usr/lib/sysusers.d/grdr-server.conf
fi

if id grdr-server >/dev/null 2>&1; then
  ensure_safe_dir /etc/grdr-server grdr-server grdr-server 0750
  ensure_safe_dir /var/lib/grdr-server grdr-server grdr-server 0750
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl preset grdr-server.service
  systemctl try-restart grdr-server.service || true
fi
