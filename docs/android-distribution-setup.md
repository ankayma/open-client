# Android direct-APK distribution (Path A — direct download) — keystore + verify setup

`.github/workflows/release-android.yml` builds a **release-signed APK** and publishes
it to `get.ankayma.com/android/` for direct download from the website — the same
authenticity model as the Linux `curl | sh` channel, and the Android analogue of the
macOS `.dmg` / Windows `.exe` lanes.

This is the **sovereignty / self-host lane**. It is independent of a Google Play
listing. Play (Play App Signing + Play Protect) is the *mainstream-trust* lane and is
set up separately — the same source ships to both, a common pattern for WireGuard
clients. Until a user verifies out-of-band (below), the APK is Trust-On-First-Use;
Play is what gives non-technical users an implicit trust anchor.

> The APK signature (Android v2/v3 scheme) is what Android checks on install and what
> it enforces on every update (updates must be signed by the **same** key — so a
> repackaged APK can never overwrite a real install). The Cosign signature over
> `SHA256SUMS` is the *host-independent* layer: it detects a swapped file on the
> download host, because `cosign.pub` lives in the git repo, not on R2.

---

## 1. Generate the release keystore (once)

Keep this file **offline and backed up** — losing it means you can never ship an
update that Android will accept over an existing install (and, if you later go to
Play without Play App Signing, you'd lose the app identity entirely).

```bash
keytool -genkey -v \
  -keystore ankayma-release.jks \
  -keyalg RSA -keysize 4096 -validity 10000 \
  -alias ankayma
# Answer the prompts (org name etc.); remember the store + key passwords.
```

## 2. Add the CI secrets

`ankayma/open-client` → Settings → Secrets and variables → Actions:

| Secret | Value |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | `openssl base64 -A -in ankayma-release.jks` |
| `ANDROID_KEYSTORE_PASSWORD` | store password |
| `ANDROID_KEY_ALIAS` | `ankayma` (the `-alias` above) |
| `ANDROID_KEY_PASSWORD` | key password (often same as the store password) |

`COSIGN_PRIVATE_KEY` / `COSIGN_PASSWORD` and the `R2_*` secrets are already present
(shared with the Linux/Windows release workflows).

## 3. Publish the signing-cert fingerprint out-of-band

This is what closes the Trust-On-First-Use gap for technical users. Print the
certificate SHA-256 and publish it somewhere an attacker who owns the download host
does **not** control (the website is fine as a start, but the strongest anchor is the
git repo / README):

```bash
keytool -list -v -keystore ankayma-release.jks -alias ankayma | grep 'SHA256:'
```

A user can then compare it against what they actually downloaded:

```bash
apksigner verify --print-certs Ankayma_<ver>_arm64.apk   # look at the SHA-256 line
```

## 4. Ship it

Push a release tag (or run the workflow manually):

```bash
git push origin vX.Y.Z          # triggers release-android/linux/macos/windows together
# or: Actions → release-android → Run workflow
```

Output on `get.ankayma.com/android/`:

- `Ankayma_<ver>_arm64.apk` — the release-signed APK (arm64-v8a)
- `SHA256SUMS`, `SHA256SUMS.sig`, `cosign.pub` — the Cosign verification set
- a **GitHub Artifact Attestation** (SLSA build provenance) tying the APK to this
  workflow run on Sigstore's transparency log

## 5. How a user verifies a download

```bash
# 1. Cosign — host-independent authenticity of the checksum manifest
cosign verify-blob --insecure-ignore-tlog \
  --key cosign.pub --signature SHA256SUMS.sig SHA256SUMS
# 2. Integrity — the APK matches the signed manifest
sha256sum -c SHA256SUMS
# 3. (strongest) build provenance on the immutable transparency log
gh attestation verify Ankayma_<ver>_arm64.apk -R ankayma/open-client
```

## 6. Notes / follow-ups

- **arm64-v8a only** for now (covers effectively every phone since ~2017). Multi-ABI
  (armeabi-v7a / x86_64) is a later change to `TAURI_ANDROID_TARGET` + the APK naming.
- The workflow is **unverified on its first CI run** (unlike macOS/Linux/Windows,
  which ran for real). Toolchain pins mirror the locally-verified Mac mini build
  (NDK 27.2.12479018, target aarch64). Bump the pins in the workflow `env:` if the
  first run fails.
- **Play Store lane** (separate): `$25` one-time developer account, upload an **AAB**
  (`cargo tauri android build --aab`), enroll in Play App Signing. Does not replace
  this lane — it complements it.

## References

- Tauri Android signing: <https://v2.tauri.app/distribute/sign/android/>
- apksigner: <https://developer.android.com/tools/apksigner>
- GitHub Artifact Attestations: <https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations>
