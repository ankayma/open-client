# SSH (Sovereign SSH)

SSH into your own machines from anywhere — **no bastion, no static key to manage, no
public port**. The mesh *is* the access boundary: you can only reach a machine because
your device is enrolled, not because of where you are on the network. Every session is
recorded in your audit ledger.

Today this runs from the command line (the `agent` CLI that ships with the app).

## Connect

```
agent ssh <node-id> --token <session-token>
```

- `<node-id>` is one of your own mesh nodes (see the Devices screen).
- The session token is the one the app uses; pass it with `--token`, or set
  `ANKAYMA_TOKEN` in your environment.
- Add `--login <user>` to choose the remote OS user (defaults to your local user).

The command resolves the node, prints a **receipt**, then drops you into a normal
`ssh` session straight over the overlay.

## The receipt

Before connecting you'll see something like:

```
── SSH session receipt ──
  session        ssh_…
  node           prod-vps
  identity-bound yes [A.1.3]
  bastion        none
  static key     none
  recording      none — session recording is F1 Growth
  verify         curl https://cp.ankayma.com/api/v1/ssh/receipt/ssh_…
```

It states honestly what F0 proves: the access was **identity-bound**, used **no
bastion and no static key**, and was **anchored in a tamper-evident ledger**. It does
*not* record the session contents at F0 — that's a higher tier. Run the `verify`
command to re-check the receipt against the live ledger yourself.

## Just print, don't connect

```
agent ssh <node-id> --print
```

shows the receipt and the exact `ssh` command without running it.

## Why no key to manage?

Reaching the node's address is only possible from inside your mesh, and mesh
membership is cryptographic. That network-layer identity *is* the gate — so there's no
separate SSH keypair or jump host to provision, rotate, or leak.
