// Open gating for branded privDomains (Services + Subdomains).
// HTTPS when TLS is issued; otherwise HTTP (browser may warn "Not Secure").
// Disabled when the mesh cannot serve the name.

export type OpenScheme = "https" | "http";

/** Prefer HTTPS only when auto-TLS reports issued. */
export function openScheme(certStatus?: string | null): OpenScheme {
  return certStatus === "issued" ? "https" : "http";
}

/** Mesh up and target reachable (self-device: pass reachable=true when connected). */
export function canOpen(connected: boolean, reachable: boolean): boolean {
  return connected && reachable;
}

export function openTitle(opts: {
  connected: boolean;
  reachable: boolean;
  certStatus?: string | null;
}): string {
  if (!opts.connected) return "Mesh disconnected — connect to open";
  if (!opts.reachable) return "Unreachable — no response over the mesh";
  if (openScheme(opts.certStatus) === "http") {
    return "Opens over HTTP (TLS not ready)";
  }
  return "";
}
