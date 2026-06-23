# Deploy Rules (secretless CI/CD)

Deploy from GitHub Actions or GitLab CI **without putting a static secret in CI**. The
CI job proves its identity with a short-lived OIDC token; Ankayma verifies it and hands
out ephemeral mesh access for that one run. You get a **signed receipt** of every
deploy, anchored in a tamper-evident ledger.

## The idea

- No long-lived deploy key or password stored in CI.
- A **deploy rule** says *which repo, on which branch/environment, may reach which
  target* — and it's **safe-by-default**: a rule must pin a `ref` or an `environment`,
  so a leaked workflow on a random branch can't deploy to prod.

## Add a deploy rule

On **Deploy Rules**, create a rule with:

- **repo** — `owner/name` (e.g. `acme/api`).
- **issuer** — GitHub Actions or GitLab CI.
- exactly one of **ref** (e.g. `refs/heads/main`) or **environment** (e.g. `prod`).
- optionally a **target** — the node the deploy may reach.

F0 allows one repo (a free taste); higher tiers unlock more.

## Run a deploy from CI

In your pipeline, after requesting an OIDC token, run the bundled agent:

```
agent ci-deploy --exec <your deploy command>
```

It fetches the CI token, exchanges it for ephemeral access, brings up a direct tunnel
to the target, runs your command, and tears down. Add `--dry-run` to prove the
secretless path (token verified + access audited) without bringing a tunnel up — handy
on a hosted runner.

## The receipt

Each run prints a receipt and a `verify` command:

```
verify  curl https://cp.ankayma.com/api/v1/ci/receipt/<run-id>
```

Anyone holding the run id can re-derive it against the live ledger — the proof is the
*evidence you hold*, not the word "secretless" alone. At F0 the receipt is
tamper-evident (ledger hash-chain); customer-key signing is a higher tier.

## Path proof

The deploy data path is a **direct WireGuard tunnel** to your target. The vendor is the
control channel only — never on the data path.
