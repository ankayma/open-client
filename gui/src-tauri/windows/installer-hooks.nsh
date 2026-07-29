; installer-hooks.nsh — NSIS install/uninstall hooks for the Windows bundle.
;
; Why this file exists, concretely: the mesh daemon runs as the LocalSystem
; Windows Service `Ankayma` (docs/windows-daemon-lifecycle-decision.md), whose
; process keeps `agent.exe` and the Wintun DLL it dlopens (crates/agent-daemon/
; src/tun.rs) open for the lifetime of the service. NSIS overwrites files in
; place, so running a freshly downloaded setup.exe over a live install aborts
; with `Error opening file for writing: C:\Program Files\Ankayma\wintun.dll`
; and leaves the install half-applied.
; `[T: reproduced end-to-end on a real Windows host 2026-07-29 — the direct
;  download-and-run upgrade path, not the in-app updater]`
;
; The in-app updater already handled this in Rust (`win_service_install::
; stop_service_verified` runs before the new binary is written), but that code
; is unreachable when the user upgrades by downloading setup.exe from the
; website — nothing in the NSIS package knew the service existed. These hooks
; close that gap at the packaging layer, so BOTH upgrade paths stop the daemon
; before touching its files. `[T:Tauri v2 bundle.windows.nsis.installerHooks —
;  NSIS_HOOK_PREINSTALL runs "before copying files"]`
;
; Elevation: the bundle is `installMode: perMachine`, so the installer process
; is already elevated and `sc`/`Stop-Service` need no further prompt. `[T:
;  gui/src-tauri/tauri.windows.conf.json]`

; Stop the service and wait for SCM to confirm STOPPED — a bare `sc stop`
; returns as soon as the control code is accepted, which is exactly the race
; that leaves the file still locked when NSIS starts copying.
; PowerShell rather than `sc query | find "STOPPED"`: `ServiceControllerStatus`
; is an enum comparison, so the wait does not depend on the Windows display
; language, whereas parsing `sc query` output does. NSIS needs `$` doubled to
; emit a literal `$` for PowerShell variables.
!macro ANKAYMA_STOP_SERVICE
  Push $0
    DetailPrint "Stopping the Ankayma Mesh service..."
    nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$s = Get-Service -Name Ankayma -ErrorAction SilentlyContinue; if ($$s) { Stop-Service -Name Ankayma -Force -ErrorAction SilentlyContinue; try { $$s.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30)) } catch { } }"'
    Pop $0
    DetailPrint "  stop Ankayma service -> $0"
    ; Belt and braces for two cases the service stop alone does not cover: an
    ; install predating the service migration (bare elevated `agent.exe up`,
    ; never registered with SCM — same case win_service_install::
    ; evict_pre_migration_agent_processes exists for), and a supervisor child
    ; that outlived its parent. "Nothing to kill" is a success here.
    nsExec::ExecToLog 'taskkill.exe /F /T /IM agent.exe'
    Pop $0
    DetailPrint "  taskkill agent.exe -> $0"
    ; Wintun's DLL handle is released as the process tears down, a moment after
    ; the exit code is reported.
    Sleep 1000
  Pop $0
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro ANKAYMA_STOP_SERVICE
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Restart only what is already registered. A first-ever install has no
  ; service yet — the GUI's own first-run flow (`win_service_install::
  ; ensure_installed`) creates it, and this hook must not pre-empt that
  ; (registering the service here would be a separate decision; see the
  ; decision doc's open item).
  Push $0
    nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$s = Get-Service -Name Ankayma -ErrorAction SilentlyContinue; if ($$s) { Start-Service -Name Ankayma -ErrorAction SilentlyContinue }"'
    Pop $0
    DetailPrint "  start Ankayma service -> $0"
  Pop $0
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; Same lock, other direction: the uninstaller cannot delete agent.exe or
  ; wintun.dll while the service holds them.
  !insertmacro ANKAYMA_STOP_SERVICE
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; TODO[A]: a real uninstall should also `sc delete Ankayma`, otherwise SCM
  ; keeps trying to auto-start a service whose binary is gone. Not done here
  ; because an *update* also runs this uninstaller (Tauri runs the previous
  ; uninstaller before installing the new files), and deleting the registration
  ; mid-update would leave the machine with no mesh service until the user next
  ; opens the GUI and clicks through a UAC prompt. Verify what Tauri passes to
  ; the uninstaller in the update path on a real Windows host, then either gate
  ; the delete on that flag or move service registration into the installer.
!macroend
