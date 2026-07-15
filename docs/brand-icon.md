# Brand icon — canonical source

The app icon is the **"An"** cursive wordmark on a teal gradient with a faint
network constellation. Full-bleed, opaque, no baked-in rounded corners (the OS
masks its own corners; App Store rejects transparency).

## Canonical source files (committed here — do not delete)

| File | Size | Use |
|------|------|-----|
| `ankayma-icon-1024.png` | 1024×1024, opaque | **master** — regen every platform icon from this |
| `ankayma-icon-512.png`  | 512×512, opaque  | reference / smaller embeds |
| `ankayma-logo-lockup.png` | wide | horizontal logo + wordmark lockup |

`gui/src-tauri/icons/icon_source.png` is a copy of `ankayma-icon-1024.png` and is
the source `cargo tauri icon` reads.

## Regenerate all platform icons

```
cd gui/src-tauri
cargo tauri icon icons/icon_source.png
```

This regenerates `icons/` (desktop), `gen/apple/…/AppIcon.appiconset` (iOS), and
`gen/android/…/mipmap-*` (Android) in one pass.

## History / gotcha

On 2026-06-30 the icon set was regenerated from the **wrong** source (a teal/yellow
interlocking-loop mark, not the "An" wordmark) — that shipped as the iOS home-screen
icon until 2026-07-15. Root cause: `cargo tauri icon` was run against a stray file.
Fix: keep the master in-repo (here) and always pass `icons/icon_source.png`. Never
regen from a file outside the repo.
