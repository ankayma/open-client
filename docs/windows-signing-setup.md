# Windows code signing — Azure Trusted Signing setup

The Windows release (`.github/workflows/release-windows.yml`) builds and publishes an
NSIS installer, but ships it **unsigned** until Authenticode signing is wired.
Unsigned installers still run, but Windows SmartScreen shows an *"unknown publisher"*
warning that scares users and can throttle downloads.

We sign with **Azure Trusted Signing** (formerly Azure Code Signing): ~$9.99/month,
Microsoft-managed. The private key never leaves Azure — CI authenticates and asks
Azure to sign, so there is no `.pfx`/private key to store in GitHub secrets (unlike a
traditional OV/EV cert). This is the Windows analogue of macOS notarization: identity
is validated once by Microsoft, then every build is signed against that identity.

> The Tauri *updater* signature (minisign, `TAURI_SIGNING_PRIVATE_KEY`) is a separate
> thing and already works. This doc only adds **Authenticode** (the OS trust /
> SmartScreen signature).

---

## 1. Prerequisites

- An **Azure subscription** (pay-as-you-go is fine; signing is ~$10/mo + tiny
  per-signature usage).
- Ability to complete **identity validation** — the name that appears as the app's
  "publisher" comes from here:
  - **Organization**: needs a legal business name + verifiable details (D-U-N-S or
    equivalent). Validation is manual on Microsoft's side, usually **1–5 business
    days**. Requires the business to have existed ≥ 90 days for *Public Trust*.
  - **Individual**: available in supported regions; validates a person's identity.
- Region availability: Trusted Signing is only in certain Azure regions (e.g.
  `eastus`, `westus3`, `westeurope`, `northeurope`). Create the account there.

## 2. Create the Trusted Signing account + certificate profile

Azure Portal → search **"Trusted Signing"**:

1. **Create a Trusted Signing account** — pick a resource group + a supported region,
   SKU **Basic** (or Premium). Note the **account name**.
2. **Identity validation** → start a request (Organization or Individual), fill in the
   details, submit. Wait for **Completed** (this is the gating step — see timelines
   above). The validated name becomes the certificate's *subject* (the publisher name
   users see).
3. Under the account → **Certificate profiles** → **Create** → type **Public Trust**
   (for shipping to end users) → link the completed identity validation. Note the
   **certificate profile name**.
4. Note the account's **endpoint URI**, shaped like
   `https://<region>.codesigning.azure.net` (shown on the account overview).

## 3. Create a CI identity (service principal) + grant it the signer role

CI signs headlessly, so create an app registration and give it *only* the signing
role:

1. **Microsoft Entra ID → App registrations → New registration** → name it e.g.
   `ankayma-trusted-signing-ci`. Note the **Application (client) ID** and **Directory
   (tenant) ID**.
2. That app → **Certificates & secrets → New client secret** → copy the **value**
   (shown once).
3. Trusted Signing account → **Access control (IAM) → Add role assignment** → role
   **"Trusted Signing Certificate Profile Signer"** → assign to the app registration
   above. (Scope it to the account/profile, not the whole subscription.)

## 4. Add GitHub Actions secrets

In `ankayma/open-client` → Settings → Secrets and variables → Actions, add:

| Secret | Value |
|---|---|
| `AZURE_TENANT_ID` | Directory (tenant) ID |
| `AZURE_CLIENT_ID` | Application (client) ID |
| `AZURE_CLIENT_SECRET` | the client secret value |
| `AZURE_TS_ENDPOINT` | `https://<region>.codesigning.azure.net` |
| `AZURE_TS_ACCOUNT` | Trusted Signing account name |
| `AZURE_TS_CERT_PROFILE` | certificate profile name |

`trusted-signing-cli` (below) reads the three `AZURE_*` credential vars via
`DefaultAzureCredential` — no extra login step needed.

## 5. Wire it into the release workflow

The correct place to sign is **inside** the Tauri bundle step, via Tauri's Windows
`signCommand`, so Tauri signs the installer **before** it computes the updater `.sig`
(signing afterwards would invalidate the minisign signature and break auto-update).

In `.github/workflows/release-windows.yml`:

1. Install the signer CLI (a small Rust tool that calls Azure Trusted Signing):

   ```yaml
   - name: Install trusted-signing-cli
     run: cargo install trusted-signing-cli --locked
   ```

2. Extend the bundle step's env with the Azure secrets and add a `signCommand` to the
   inline `--config`. Tauri passes the artifact path as the final argument:

   ```yaml
   - name: Build NSIS installer + updater artifacts (signed)
     working-directory: gui
     shell: pwsh
     env:
       TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}
       TAURI_SIGNING_PRIVATE_KEY_PASSWORD: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY_PASSWORD }}
       AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
       AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
       AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
     run: >
       cargo tauri build
       --config src-tauri/tauri.windows.conf.json
       --config '{
         "bundle": {
           "createUpdaterArtifacts": true,
           "windows": {
             "signCommand": {
               "cmd": "trusted-signing-cli",
               "args": ["-e","${{ secrets.AZURE_TS_ENDPOINT }}","-a","${{ secrets.AZURE_TS_ACCOUNT }}","-c","${{ secrets.AZURE_TS_CERT_PROFILE }}","%1"]
             }
           }
         },
         "plugins": { "updater": { "endpoints": ["https://get.ankayma.com/windows/latest.json"] } }
       }'
   ```

   `%1` is Tauri's placeholder for the file being signed. Tauri calls the command for
   the sidecar/app and the final NSIS installer; each is signed, then the `.sig` is
   generated on the signed installer.

3. Remove/replace the unsigned bundle step and the `TODO[cert]` note.

## 6. Verify

After a release run, on any Windows box:

```powershell
# Downloaded installer should show a valid signature + the validated publisher name.
Get-AuthenticodeSignature .\Ankayma_<ver>_x64-setup.exe | Format-List Status, SignerCertificate
# Status should be "Valid".
```

SmartScreen reputation builds over the first downloads; the "unknown publisher"
warning disappears once the signed publisher accrues reputation (immediate with an
EV-style validated Trusted Signing identity, faster than an unsigned build ever
gets).

## 7. Cost + notes

- ~**$9.99/month** for the Basic account + a small per-signature usage fee.
- Certificates rotate automatically (short-lived, 3-day certs re-issued per sign) —
  nothing to renew manually, unlike a 1–3 year OV/EV cert.
- Same pattern signs the `agent.exe` sidecar if you want it individually signed;
  Tauri's `signCommand` already covers bundled binaries.

## References

- Azure Trusted Signing docs: <https://learn.microsoft.com/azure/trusted-signing/>
- `trusted-signing-cli`: <https://crates.io/crates/trusted-signing-cli>
- Tauri Windows signing: <https://v2.tauri.app/distribute/sign/windows/>
