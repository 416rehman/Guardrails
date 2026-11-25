#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
set -euo pipefail

if command -v systemd-sysusers >/dev/null 2>&1; then
  systemd-sysusers /usr/lib/sysusers.d/grdr.conf
fi

if id grdr >/dev/null 2>&1; then
  install -d -o grdr -g grdr -m 0750 /etc/grdr /var/lib/grdr
  chown -R grdr:grdr /etc/grdr /var/lib/grdr
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable grdr-decide.socket grdr-local.socket grdr-daemon.service
  systemctl try-restart grdr-daemon.service
fi
