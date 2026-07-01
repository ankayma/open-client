#!/bin/sh
# preremove.sh — run by dpkg/rpm before files are removed. Only stop+disable on
# a real removal, not on upgrade (dpkg passes an upgrade marker; rpm passes an
# argument count) — otherwise the service would flap during every version bump.
set -e

case "$1" in
  # dpkg: preremove runs with no args on removal, "upgrade" only on --purge/reinstall paths we don't use here.
  remove|purge|"")
    if command -v systemctl >/dev/null 2>&1; then
      systemctl stop ankayma-agent.service 2>/dev/null || true
      systemctl disable ankayma-agent.service 2>/dev/null || true
    fi
    ;;
  # rpm: $1 is the count of installed versions after this operation; 0 = final removal.
  0)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl stop ankayma-agent.service 2>/dev/null || true
      systemctl disable ankayma-agent.service 2>/dev/null || true
    fi
    ;;
  *)
    : # upgrade path — leave the running service alone
    ;;
esac
