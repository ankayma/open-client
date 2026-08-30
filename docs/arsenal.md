# ankayma open-client — Tool Documentation

**Black Hat MEA Arsenal 2026 · presented in conjunction with ToolsWatch**

`ankayma open-client` is an open-source, identity-aware zero-trust mesh agent written in Rust. It removes static credentials — passwords, SSH keys, API keys, and long-lived secrets — and replaces them with short-lived, cryptographically proven access, for human and non-human actors alike. It also lets you **verify, rather than trust,** that the vendor was never on your data path, and it ships the verifier for its own audit ledger.

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

The same question is now being asked about software that acts on its own. When a script or an AI agent needs to reach a production host, the common answer is to give it a copy of a human's credential, or a key of its own that never expires. Both are the original problem with a new actor attached.

---

## 2. What the tool does

### Identity-bound mesh access, no static secret
Every node in the mesh holds a cryptographic identity. Access is granted **just-in-time, scoped, and short-lived**, gated by policy rather than by possession of a key. There is no public port to scan and no long-lived credential to steal. A revoked identity loses access immediately — the next resolution or connection simply fails.

### Private domains, no public exposure
You can attach a local service to a name and reach it **only from inside your mesh**. The name resolves for enrolled nodes and returns `NXDOMAIN` for everyone else. TLS certificates are issued automatically (via Let's Encrypt), and **no public port is ever opened** to the internet.

### Sovereign SSH, no bastion, no static key
`agent ssh <node>` opens a session to a production host without a bastion and without a static SSH key. The host exposes no public SSH port; access is identity-bound to your device key, and every session is written to an append-only ledger. Privilege elevation is time-boxed and logged, then automatically dropped.

### Delegation to non-human identities, no shared credential
`agent enroll-identity` mints a scoped identity for a script, CI job, or AI agent, and `agent ssh --as <handle> <node>` connects as that identity instead of as you. Four properties make this a delegation model rather than a credential hand-off:

- **No bearer token on the agent path.** The identity proves itself by signature.
- **The agent cannot mint its own authority.** The control plane refuses to open an agent session unless a person currently holds a live delegation window for that identity, and there is no fallback path if one is not open. Command grants are minted only from a human-authenticated session — there is deliberately no `--as` variant of that command.
- **One command, once.** A command grant pins a digest of the exact argv. The control plane computes it when it decides; the node recomputes it from what it is about to run. These are separate implementations, and a disagreement stops the command instead of being reconciled at runtime. The node takes the argv **from the grant**, never from the SSH exec string, so a client cannot decide what runs.
- **Enforcement is declared, not assumed.** The control plane refuses to issue a grant to a node that has not declared it can enforce one — silence is not read as consent. And a node that can enforce but has no way to report the outcome does not enable the path at all: a ledger that says "authorised" and never says what happened is the half nobody can use.

Close the window, or let it expire, and the next connection is refused. There is no self-renewal path.

### Path-proof: verify the data path
After a connection, the agent shows **the route the traffic actually took** — direct peer-to-peer versus relayed — alongside the endpoint, the handshake age, and the matching ledger entry. This turns "the vendor cannot see your data" from a marketing claim into something you can check yourself.

### An audit ledger you can verify yourself
Every access produces a **signed, append-only record**. An audit log you can only check by asking the vendor is not evidence — it is a promise with extra steps. So the verifier ships here, in `crates/ledger-client`: given one event, one inclusion proof and one published checkpoint, the verification is arithmetic that runs on your machine.

It shares no code with the system that produces the ledger, deliberately. The algorithms are public standards — RFC 6962 for the tree, C2SP `tlog-checkpoint` and `signed-note` for the checkpoint — so re-deriving them here is not duplication but the independence that makes a disagreement between the two mean something. A verifier that called back into the prover's code could only ever agree with it.

| Check | Proves | Does **not** prove |
|---|---|---|
| inclusion | this event was in the tree at that size | the tree is the one you were shown before |
| consistency | the log only grew; no history was rewritten | anyone else has seen it |
| checkpoint signature | the named key signed these bytes | that key belongs to the vendor |

The third gap is what an independent witness closes. A checkpoint that no witness has co-signed is reported as **unwitnessed** — not as verified.

---

## 3. How it works

`ankayma open-client` is the **open half** of the system. It follows an open-client / closed-control-plane split: everything that runs on your machine lives in this repository and is fully auditable. The control plane (identity issuance, policy, audit) runs separately and **never sits on your data path**.

**Data plane vs control plane.** The control plane decides *who may connect to what*. The data plane carries your actual traffic. These are strictly separated: your business data flows node-to-node and does **not** transit vendor infrastructure. This separation is structural, not a configuration toggle.

**Data-plane transport.** The agent runs a WireGuard-based data plane. It can use the kernel TUN device (`sudo agent up`) or a fully userspace network path where a privileged device is unavailable (for example, inside CI). Peers behind NAT discover each other over STUN and attempt a direct connection; a relay carries the traffic, still encrypted, only when a direct path cannot be established.

**Grants are one shape.** Elevation grants, agent-session grants and command grants share a single signed wire format verified against the same control-plane key the node already fetches, domain-separated by a purpose field rather than by a second key. One shape, one parser.

**Two binaries and a verifier.**

| Component | Role |
|---|---|
| `agent` | the daemon and command surface (`up`, `resolve`, `ssh`, `ssh-exec`, `ci-deploy`, `enroll-identity`, …) |
| `mesh`  | a CLI whose key subcommands mirror the stock `wg(8)` tools, so output is interchangeable |
| `crates/ledger-client` | an independent verifier for the audit ledger — no dependency on the control plane |

---

## 4. Install

### Linux (one line)
```sh
curl -fsSL https://get.ankayma.com/install.sh | sh
```
Prefer to read before you run? `curl -fsSL https://get.ankayma.com/install.sh | less` first.

### Linux (manual, with signature verification)
```sh
base=https://get.ankayma.com/latest
curl -fLO $base/mesh-linux-amd64
curl -fLO $base/agent-linux-amd64
curl -fLO $base/SHA256SUMS
curl -fLO $base/SHA256SUMS.sig
curl -fLO $base/cosign.pub

# 1. the signature over the checksum file must verify against the published key
#    (the same key is committed at the root of this repository — compare them)
cosign verify-blob --key cosign.pub --signature SHA256SUMS.sig SHA256SUMS

# 2. the binaries must match the checksums that signature covers
sha256sum -c SHA256SUMS

sudo install -m 0755 mesh-linux-amd64  /usr/local/bin/mesh
sudo install -m 0755 agent-linux-amd64 /usr/local/bin/agent
```

Do step 1 before step 2, and step 2 before you run anything: a checksum you have not
verified the signature of only tells you the download was not corrupted, which is not the
question.

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

### Delegating to a non-human identity

```sh
# A person bootstraps the identity on the machine that will run the agent
agent enroll-identity --token <single-use-token> --name claude-1

# The agent connects as itself — only while a person holds an open window for it
agent ssh --as claude-1 <node>
agent ssh --as claude-1 <node> -- ls -la /var/log

# For one command, once: a PERSON mints the grant (no --as on this path)
agent ssh <node> --token <t> --for-actor <agent_actor_id> \
  --cmd <template-id> --param key=value --reason "why this is being asked"

# ...and hands the printed token to whoever runs it
agent ssh --as claude-1 <node> --cmd-grant <token>
```

The delegation window is bounded and revocable. Revoking it, or letting it expire, cuts off the next connection; nothing renews itself.

---

## 6. What you will see at the Arsenal station

The demo runs on two real devices — a phone and an admin laptop, on two different networks — so you can watch access appear, be proven, and be taken away:

1. **Sign in on the phone** with GitHub and a device biometric. The credential is the device key; no static secret is created.
2. **Connect**, then **open a private service by name**. It resolves only inside the mesh, over valid TLS, with no public port and no inbound rule.
3. **SSH into a production host from the phone** — no bastion, no static key. Elevation is a signed, time-boxed grant that drops itself.
4. **A CI deployment with no secret in the runner**, and the signed run-receipt it leaves behind: run id, repository, deploy-only scope.
5. **Prove-it** shows the route the connection actually took — direct peer-to-peer, vendor not in the path — next to the ledger entry for the access.
6. **Delegate to an agent**: mint a non-human identity, hand it a bounded window, watch it connect as itself, then close the window and watch the next connection be refused.

You are welcome to clone the repository and follow along on your own machine.

---

## 7. Security model and honest limits

We mark security claims as **[T]** (verified, with a source) or **[A]** (assumed, not yet independently verified). Shipping honestly is a design goal, so the limits below are stated plainly.

- **Open client — [T].** The agent running on your machine is fully open source. Client-side properties (the agent does not touch control-plane traffic; data-plane separation) are validated by an open test harness and hold for the open-source agent.
- **Server-side isolation — [A], not yet third-party audited.** The control-plane invariants have been validated by an internal harness with owner sign-off, but **not** by an independent auditor. Treat server-side claims as owner-accepted until external audit.
- **Path-proof scope.** Path-proof is **absolute for direct peer-to-peer** connections. Where a direct path cannot be established — symmetric or carrier-grade NAT on both ends — a relay carries the traffic. Relay traffic remains encrypted, the interface says so rather than hiding it, and relay ownership and jurisdiction remain a deliberate deployment decision. The demo shows exactly where that line sits.
- **Receipts are tamper-evident; witnessing is what closes the last gap.** Receipts form a signed, append-only chain you can re-verify with the verifier in this repository. Signature verification proves the named key signed those bytes — not that the key is ours. A checkpoint no independent witness has co-signed is reported as **unwitnessed**; do not read "tamper-evident" as "externally notarized".
- **Delegation is connection-level, not action-level.** A command grant pins one command and the node enforces it. Beyond that boundary, what a delegated agent does inside an interactive session is bounded by the identity and the window, not by per-action review.
- **Roaming security keys on iOS — [T], does not work.** FIDO2 roaming authenticators are not reachable through WebAuthn in an iOS web view, so hardware-key step-up is unavailable on that platform pending a native implementation. Platform authenticators and TOTP are unaffected.
- **Personal-tier key custody.** The Personal tier uses a single-custodian root key with a mnemonic backup — simpler operations, less resilience than a multi-party ceremony.
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
- **Path-proof** shows the route a connection actually took, not the route we say it took.
- **An independent ledger verifier** in `crates/ledger-client` — inclusion, consistency and checkpoint signature, computed on your machine, by code that shares nothing with the producer.

---

## 9. Links

- **Source:** https://github.com/ankayma/open-client
- **Install:** https://get.ankayma.com/install.sh
- **User guide:** `docs/user-guide/` in the repository
- **Honest limits:** the project's Honest Limits page
- **Contact:** hello@ankayma.com

*Verify it yourself.*
