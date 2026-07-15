# ankayma open-client — Tool Documentation

**Black Hat MEA Arsenal 2026 · presented in conjunction with ToolsWatch**

`ankayma open-client` is an open-source, identity-aware zero-trust mesh agent written in Rust. It removes static credentials — passwords, SSH keys, API keys, and long-lived secrets — and replaces them with short-lived, cryptographically proven access. It also lets you **verify, rather than trust,** that the vendor was never on your data path.

- **Repository:** https://github.com/ankayma/open-client
- **License:** open source (see `LICENSE` / `NOTICE` in the repo)
- **Platforms:** Linux · macOS · Windows · iOS · Android
- **Contact:** hello@ankayma.com

---

## 1. The problem: static credentials never should have existed

Read almost any breach post-mortem and the root cause repeats: a static credential that outlived its purpose.

- SSH private keys copied onto laptops and forgotten.
- API keys pasted into CI logs and environment files.
- Service accounts holding standing secrets that never expire.
- VPN certificates that grant flat network access once presented.

The industry response has been to *rotate* these secrets. Rotation does not remove the credential — it just changes it on a schedule. As long as a long-lived secret exists somewhere, it can leak, and once it leaks it grants access until someone notices.

`ankayma open-client` takes a different position: **the credential should not exist in the first place.**

---

## 2. What the tool does

### Identity-bound mesh access, no static secret
Every node in the mesh holds a cryptographic identity. Access is granted **just-in-time, scoped, and short-lived**, gated by policy rather than by possession of a key. There is no public port to scan and no long-lived credential to steal. A revoked identity loses access immediately — the next resolution or connection simply fails.

### Private domains, no public exposure
You can attach a local service to a name and reach it **only from inside your mesh**. The name resolves for enrolled nodes and returns `NXDOMAIN` for everyone else. TLS certificates are issued automatically (via Let's Encrypt), and **no public port is ever opened** to the internet.

### Sovereign SSH, no bastion, no static key
`agent ssh <node>` opens a session to a production host without a bastion and without a static SSH key. The host exposes no public SSH port; access is identity-bound to your device key, and every session is written to an append-only ledger. Privilege elevation is time-boxed and logged, then automatically dropped.

### Non-human identities, no static API key
`agent enroll-identity` mints a scoped, time-limited identity for a script, CI job, or AI agent. The actor appears in the ledger like any other principal, and there is **zero static-secret residue** left behind after the run.

### Path-proof: verify the data path
After a connection, the agent can produce a **cryptographic attestation of the route the traffic actually took** — direct peer-to-peer versus relayed. This turns "the vendor cannot see your data" from a marketing claim into something you can check yourself.

### Tamper-evident receipts
Every access produces a **signed, append-only record**. The access log becomes an auditable artifact rather than a mutable database row — you can re-verify the chain after the fact.

---

## 3. How it works

`ankayma open-client` is the **open half** of the system. It follows an open-client / closed-control-plane split: everything that runs on your machine lives in this repository and is fully auditable. The control plane (identity issuance, policy, audit) runs separately and **never sits on your data path**.

**Data plane vs control plane.** The control plane decides *who may connect to what*. The data plane carries your actual traffic. These are strictly separated: your business data flows node-to-node and does **not** transit vendor infrastructure. This separation is structural, not a configuration toggle.

**Data-plane transport.** The agent runs a WireGuard-based data plane. It can use the kernel TUN device (`sudo agent up`) or a fully userspace network path where a privileged device is unavailable (for example, inside CI).

**Two binaries.**

| Binary | Role |
|---|---|
| `agent` | the daemon and command surface (`up`, `resolve`, `ssh`, `ci-deploy`, `enroll-identity`, …) |
| `mesh`  | a CLI whose key subcommands mirror the stock `wg(8)` tools, so output is interchangeable |

---

## 4. Install

### Linux (one line)
```sh
curl -fsSL https://get.ankayma.com/install.sh | sh
```
Prefer to read before you run? `curl -fsSL https://get.ankayma.com/install.sh | less` first.

### Linux (manual, with signature verification)
```sh
base=https://get.ankayma.com
curl -fLO $base/mesh-linux-amd64
curl -fLO $base/agent-linux-amd64
curl -fLO $base/SHA256SUMS
curl -fLO $base/SHA256SUMS.sig
curl -fLO $base/cosign.pub
# verify the Cosign signature over the checksums, then:
sudo install -m 0755 mesh-linux-amd64  /usr/local/bin/mesh
sudo install -m 0755 agent-linux-amd64 /usr/local/bin/agent
```

### macOS / Windows / mobile
Desktop GUI builds (Tauri 2) are available for macOS and Windows; the mobile agent runs on iOS and Android. See the download page and the in-repo `docs/user-guide/`.

### Build from source
```sh
cargo build --release
# produces the `agent` and `mesh` binaries
```
You do not have to trust our published binaries — the toolchain is reproducible and the source is here.

---

## 5. Quickstart

```sh
# 1. Generate a keypair (mesh mirrors wg tooling)
mesh genkey | tee priv.key | mesh pubkey

# 2. Enroll this node and bring up the data plane
sudo agent up --token <join-token> --control-plane <url>

# 3. Resolve and reach a private domain (enrolled nodes only)
agent resolve myservice.example

# 4. Open a Sovereign SSH session — no bastion, no static key
agent ssh <node>

# 5. Run in the background as a service (Linux)
sudo systemctl enable --now ankayma-agent
```

On a node that leaves the mesh, resolution returns `NXDOMAIN` and connections fail immediately — revocation takes effect at once, with nothing left to clean up.

---

## 6. What you will see at the Arsenal station

The demo runs on two machines — an admin laptop and a phone — so you can watch access appear and disappear live:

1. **Admin creates a private domain** pointing at a local service. Auto-TLS issues a valid certificate; no public port is opened.
2. **A second device enrolls** with no pre-shared secret — its identity is bound to the device key, and no static key is created.
3. **The admin grants access by policy**, and the device opens the private domain: it resolves only inside the mesh, over valid TLS, with no public exposure.
4. **The admin revokes access** — and the device is cut off instantly (`NXDOMAIN`).
5. **Prove-it** shows the connection went direct peer-to-peer, with the vendor never in the middle, and a **signed, tamper-evident receipt** for the access.

You are welcome to clone the repository and follow along on your own machine.

---

## 7. Security model and honest limits

We mark security claims as **[T]** (verified, with a source) or **[A]** (assumed, not yet independently verified). Shipping honestly is a design goal, so the limits below are stated plainly.

- **Open client — [T].** The agent running on your machine is fully open source. Client-side properties (the agent does not touch control-plane traffic; data-plane separation) are validated by an open test harness and hold for the open-source agent.
- **Server-side isolation — [A], not yet third-party audited.** The control-plane invariants have been validated by an internal harness with owner sign-off, but **not** by an independent auditor. Treat server-side claims as owner-accepted until external audit.
- **Path-proof scope.** Path-proof is **absolute for direct peer-to-peer** connections. Behind double-NAT, a relay may be required for connectivity; relay traffic remains encrypted but is relayed, and relay ownership/jurisdiction is a deliberate design decision. The demo shows exactly where that line sits.
- **Receipts are tamper-evident, not externally witnessed.** Receipts form a signed, append-only chain you can re-verify. External-witness co-signing is on the roadmap; do not read "tamper-evident" as "externally notarized."
- **Personal-tier key custody.** The Personal tier uses a single-custodian root key with a mnemonic backup — simpler operations, less resilience than a multi-party ceremony. Multi-party (Shamir 2-of-3) custody is an enterprise-tier capability.
- **Sybil / abuse.** Free-tier signup is gated by account age, repository count, and a phishing check — there is no ML behaviour baseline, so a determined attacker with aged accounts can create multiple tenants. Acknowledged.
- **No compliance mapping.** Controls are **not** mapped to any compliance framework (SOC 2, ISO 27001, regional banking guidance). Do not cite the tool as satisfying a framework without your own review.
- **Performance numbers are design goals — [A].** Latency, memory, and throughput targets are not yet measured benchmarks.

A living version of these limits is published at the project's Honest Limits page.

---

## 8. Verify it yourself

Sovereignty is only meaningful if you can check it. This tool is built to be checked:

- **Fully open source** — read the exact code that runs on your nodes.
- **Reproducible builds** with a pinned toolchain.
- **Cosign-signed** release artifacts (`SHA256SUMS.sig` + `cosign.pub`).
- **Path-proof and receipts** let you verify the data path and audit access after the fact — no need to take our word for it.

---

## 9. Links

- **Source:** https://github.com/ankayma/open-client
- **Install:** https://get.ankayma.com/install.sh
- **User guide:** `docs/user-guide/` in the repository
- **Honest limits:** the project's Honest Limits page
- **Contact:** hello@ankayma.com

*Verify it yourself.*
