# Subdomains

A **subdomain** gives a service a stable private name instead of a raw overlay IP —
for example `epos.yourteam.int.ankayma.com`. The name is **private by default**: it
resolves *only* on devices enrolled in your mesh, and the traffic goes straight over
the overlay. There is no public port and the vendor is never on the path.

## Create one

1. Go to **Subdomains → Add subdomain**.
2. Enter a **name** (lowercase letters, digits, hyphens — e.g. `epos`).
3. Pick the **target node** — the machine that runs the service.
4. Save. The full name becomes `name.<your-tenant>.int.ankayma.com`.

The control plane validates the name and enforces a per-tier cap (fair-use, to stop
abuse). You can register a few on F0; team tiers allow more.

## How it resolves

While a device is connected (`agent up`), the agent runs a small local DNS resolver
for your zone. When you open `epos.yourteam.int.ankayma.com`, it resolves to the
target node's overlay address and connects directly.

- **Not enrolled?** The name simply does not resolve (NXDOMAIN). That *is* the privacy
  guarantee — outsiders can't even discover it.
- **Target removed?** The name stops resolving instantly.

## Open a service

Click **Open** on a subdomain to launch it in your browser.

## What's not live yet

- **Automatic TLS** (a browser-trusted certificate for the name) is coming. Until then
  your browser may warn about the certificate, and transparent name resolution is
  desktop-first (macOS).
