# F-3 iOS private DNS — forwarding resolver design (and the four root causes)

How the iOS Packet Tunnel resolves private mesh names (`*.int.ankayma.com`) while
keeping every other name working, and the four defects we fixed to get there. All
claims cite public sources or reproducible on-device observations; the full internal
test record lives outside this repo.

## Architecture (current, validated on device 2026-07-04)

- The tunnel advertises one in-tunnel IPv4 DNS server (`100.100.100.53`, RFC 6598
  CGNAT space) with `NEDNSSettings.matchDomains = [""]` — the pattern wireguard-apple
  ships unconditionally whenever DNS servers are set ("All DNS queries must first go
  through the tunnel's DNS", `PacketTunnelSettingsGenerator.swift`). iOS consults the
  tunnel resolver first and falls back to the system resolver.
- An IPv6 tunnel resolver is a dead end — iOS sends it no packets at all
  (Apple DevForums 757674/735005). The IPv4 side of the tunnel exists ONLY as DNS
  transport: interface `.2/24` in the same /24 as the server, route for that /24, so
  the server IP is on-link (DevForums 727012: the DNS server IP must be within the
  tunnel's routed subnet). The overlay itself stays IPv6-only.
- The pump answers queries arriving on the tun fd: names in the private resolve
  table → authoritative answer (AAAA = the peer's overlay address); anything else →
  forwarded upstream over a plain BSD UDP socket; on any failure → synthesized
  SERVFAIL. Never silence (see contract below).

## The always-answer contract (root cause #3)

iOS gives up on a tunnel DNS server that fails to answer and will not use it again
until the VPN reconnects. That behaviour is by design and unforceable — Apple DTS
(Quinn), DevForums thread 114097: "I don't think there's any way you can force iOS to
use a DNS server that's not responding … giving up on 'broken' DNS servers is just
one of those decisions."

Therefore the resolver must answer EVERY query:
- Private name, A/AAAA → answer (or NODATA for the missing family).
- Private name, any other type (Safari sends HTTPS/SVCB type-65 for every name) →
  NOERROR with zero answers, never silence — same as Tailscale's resolver
  ("always return NOERROR without any records whenever the requested record type is
  unknown", `net/dns/resolver/tsdns.go`).
- Forwarded name, upstream fails/times out → synthesized SERVFAIL, exactly like
  Tailscale ("All such errors map to SERVFAIL at the client level",
  `net/dns/resolver/forwarder.go`).

An earlier design here said "fail-open: on forward failure, drop and let iOS fall
back". That is backwards: the unanswered query IS what makes iOS drop the resolver.

## Forwarding (root causes #2 and part of #3)

- A plain BSD UDP socket egresses the real network from inside a Packet Tunnel
  Provider — the WireGuard data socket in this same process proves it, and Tailscale
  forwards DNS the same way on darwin (`net/netns/netns_darwin.go`, `IP_BOUND_IF`).
  An earlier NWUDPSession bridge built on the opposite assumption was deleted.
- Do NOT pin the forward socket to a guessed interface: the tunnel installs no
  default IPv4 route, so an unpinned socket egresses via the OS default route on its
  own. Tailscale binds to the default-route interface found via an AF_ROUTE lookup
  and, when that lookup fails, sends unbound rather than guessing. We send unpinned
  first, pinned only as fallback (a getifaddrs-guessed pin produced ENETUNREACH on
  device).
- All configured upstreams are raced from one socket, first reply with matching
  transaction id + source wins (RFC 5452 hygiene) — one dead public resolver must
  not take the forward path down (Tailscale races upstreams the same way; see also
  tailscale/tailscale#17537 for what happens on iOS when a sole upstream dies).
- Timeout 3s, between Tailscale's 2s UDP race window and 5s TCP budget; we have no
  TCP fallback yet.

## Root cause #1 — DNS server IP must be on-link

With interface `100.64.0.2/32` and a lone /32 route to a server in a different
subnet, iOS delivered zero DNS packets to the tun. Fix: interface and server share
one /24, route that /24 (DevForums 727012). After this, queries reach the pump.

## Root cause #4 — THE decisive one: the packetFlow fd is non-blocking

Symptom that masqueraded as "iOS stops routing DNS into the tunnel": the pump's
tun-read thread logged exactly one packet per connect, then nothing, while the OS
resolver kept retransmitting queries into the utun for minutes (visible in device
syslog as climbing retry counters).

Cause: the fd behind `NEPacketTunnelProvider.packetFlow` is managed by Apple's
dispatch machinery and is non-blocking. The moment the queued packets drain, read()
returns EAGAIN; the pump treated any read error as fatal and exited the loop — and
the error report went to stderr, which a Network Extension does not have, so the
thread died invisibly ~10ms after start. Sessions that briefly "worked" were ones
whose startup burst kept the queue non-empty a little longer.

Fix (matching wireguard-go, which keeps the same stolen fd non-blocking and waits
for readiness via the Go netpoller, `tun/tun_darwin.go`): `tundev.rs` handles
EAGAIN/EWOULDBLOCK with poll(2)-and-retry and EINTR with retry, for both read and
write; pump loops log fatal errors through the platform log hook (NSLog on iOS),
never stderr. A unit test pins the regression with a non-blocking pipe.

This is also why macOS never hit it: the desktop daemon opens its own utun via a
kernel-control socket, which is blocking by default.

## Validation summary (iPhone, on-device syslog, 2026-07-03/04)

- Clean connect → 114+ public-name forwards, every one answered (replies written to
  the tun; a handful of SERVFAILs where upstream failed — the contract working).
- Private name from the app → three authoritative answers (A NODATA + AAAA + type-65
  NODATA) → page loads over the overlay.
- Reconnect, WiFi→cellular switch, 6-minute lock, sustained browsing: one session
  stayed healthy 16+ minutes across all of it, >1300 queries relayed, zero silent
  drops. The old "works only in the first session" pattern is gone.
- Capture discipline that made the diagnosis possible: capture the WHOLE device
  syslog and filter when reading — a PID-bound capture goes blind when the extension
  restarts on reconnect.

## Still open

- Upstreams are the public resolvers handed in by the app; reading the device's own
  resolvers (res_ninit) is the documented refinement.
- No TCP fallback for truncated upstream answers (rare for phone browsing).
- Roaming hardening: rebind/re-pin on network change (Tailscale-style) — the WiFi→
  cellular test passed, but the recovery mechanism wasn't isolated.
- If `matchDomains=[""]` ever proves sticky again, the evidence-backed fallback is
  Tailscale's iOS default: split DNS with `matchDomains = [zone]` (+ equal
  searchDomains), now testable because the carrier is on-link.

## Sources

- wireguard-apple `PacketTunnelSettingsGenerator.swift` — unconditional
  `matchDomains=[""]`:
  https://github.com/WireGuard/wireguard-apple/blob/master/Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift
- Apple DevForums 114097 — iOS gives up on a non-answering tunnel resolver (by
  design, unforceable): https://developer.apple.com/forums/thread/114097
- Apple DevForums 35027 — `[""]` = tunnel resolver consulted first, system as
  fallback: https://developer.apple.com/forums/thread/35027
- Apple DevForums 727012 — DNS server IP must be within the tunnel's routed subnet:
  https://developer.apple.com/forums/thread/727012
- Apple DevForums 757674 / 735005 — IPv6 tunnel resolver receives no packets:
  https://developer.apple.com/forums/thread/757674
  https://developer.apple.com/forums/thread/735005
- Tailscale `net/dns/resolver/forwarder.go` — SERVFAIL on upstream failure, upstream
  racing, udpRaceTimeout=2s/tcpQueryTimeout=5s:
  https://github.com/tailscale/tailscale/blob/main/net/dns/resolver/forwarder.go
- Tailscale `net/dns/resolver/tsdns.go` — NOERROR-empty for unknown query types:
  https://github.com/tailscale/tailscale/blob/main/net/dns/resolver/tsdns.go
- Tailscale `net/netns/netns_darwin.go` — default-route interface bind, unbound on
  lookup failure:
  https://github.com/tailscale/tailscale/blob/main/net/netns/netns_darwin.go
- Tailscale `net/dns/manager.go` — iOS split-DNS default when no custom resolvers:
  https://github.com/tailscale/tailscale/blob/main/net/dns/manager.go
- Tailscale MagicDNS blog — quad-100 answered in-process, /32 routed into tunnel:
  https://tailscale.com/blog/2021-09-private-dns-with-magicdns
- tailscale/tailscale#17537 — iOS loses DNS when the sole upstream dies:
  https://github.com/tailscale/tailscale/issues/17537
- wireguard-go `tun/tun_darwin.go` — non-blocking tun fd + poller readiness:
  https://github.com/WireGuard/wireguard-go/blob/master/tun/tun_darwin.go
- RFC 5452 §4 — DNS reply source/transaction-id validation:
  https://datatracker.ietf.org/doc/html/rfc5452
