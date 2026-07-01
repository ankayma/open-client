#!/bin/sh
# postinstall.sh — run by dpkg/rpm right after files are laid down. Idempotent:
# safe on both first install and upgrade (dpkg/rpm both call this on upgrade too).
set -e

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable --now ankayma-agent.service
fi
