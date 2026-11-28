#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: The Guardrails ADR Authors
set -euo pipefail

case "${1:-}" in
  upgrade)
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
      systemctl stop grdr-daemon.service || true
    fi
    ;;
  remove|purge)
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
      systemctl disable --now grdr-daemon.service grdr-decide.socket grdr-local.socket || true
    fi
    ;;
esac
