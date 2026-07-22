// PacketTunnelProvider — Ankayma's iOS Network Extension (Packet Tunnel Provider).
// OPEN. Intensity Critical (platform boundary + raw fd).
//
// iOS reserves tun creation to this extension. The flow on startTunnel:
//   1. load the resolved config the main app wrote to the App Group (this node's
//      key + overlay IP + peers — connection metadata only, [T:A.1.1]);
//   2. set NEPacketTunnelNetworkSettings so iOS programs the utun's overlay address
//      + the per-peer routes (the macOS/Linux daemon does this with ifconfig/route —
//      on iOS it MUST go through NetworkExtension);
//   3. hand the utun fd to the Rust pump (agent-ios-ptp's ankayma_ptp_start), which
//      runs the same agent_core::pump as the desktop daemon. [T:A.1.9]
//
// Enroll + peer-refresh stay in the main app (the extension's memory budget is
// tight); the app writes/updates the config file in the App Group.

import NetworkExtension
import os.log

final class PacketTunnelProvider: NEPacketTunnelProvider {
    /// Shared with the main app + the agent-ios-ptp Cargo bundle id. Must match the
    /// App Group registered in the Apple Developer portal.
    private static let appGroup = "group.com.ankayma.app"
    private static let configFile = "tunnel-config.json"

    private let log = OSLog(subsystem: "com.ankayma.app.tunnel", category: "ptp")
    /// Opaque `PtpHandle *` from ankayma_ptp_start; freed in stopTunnel.
    private var handle: OpaquePointer?

    // MARK: NEPacketTunnelProvider

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        NSLog("ankayma-ptp: startTunnel called")
        guard let loaded = loadConfig() else {
            os_log("no tunnel config in app group", log: log, type: .error)
            NSLog("ankayma-ptp: NO CONFIG in app group — tunnel cannot route")
            completionHandler(PtpError.missingConfig)
            return
        }
        // NSLog (unlike os_log .info) reaches idevicesyslog — surface what the
        // extension actually loaded so a peerless/zoneless config is diagnosable
        // on-device instead of by guesswork.
        NSLog(
            "ankayma-ptp: loaded config overlay=\(loaded.config.overlay_ip) "
                + "peers=\(loaded.config.peers?.count ?? 0) "
                + "zone=\(loaded.config.zone ?? "nil")"
        )

        // DNS forwarding of non-private names is done in Rust (the pump relays via a
        // BSD socket pinned to the physical interface — see agent-ios-ptp
        // `ios_dns_forward`), NOT via the provider's NWUDPSession. `matchDomains=[""]`
        // routes ALL DNS into the pump; the upstream resolver is passed to Rust in the
        // config (`upstream_dns`). Nothing to wire on the Swift side.
        let settings = makeNetworkSettings(from: loaded.config)
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                os_log(
                    "setTunnelNetworkSettings failed: %{public}@",
                    log: self.log, type: .error, String(describing: error)
                )
                completionHandler(error)
                return
            }

            guard let fd = self.tunnelFileDescriptor else {
                os_log("could not find the utun fd", log: self.log, type: .error)
                completionHandler(PtpError.noTunFd)
                return
            }

            // Drive the shared Rust pump over the utun fd. The full JSON (incl. the
            // private key) goes straight to Rust — Swift only read the overlay/peers
            // it needs for the routes above. `boundIf` pins the pump's UDP socket to
            // the physical interface so its packets egress instead of looping back
            // into our own tunnel (the extension-socket egress fix).
            let boundIf = self.physicalInterfaceIndex()
            NSLog("ankayma-ptp: pinning socket to physical if#%u", boundIf)
            self.handle = loaded.rawJSON.withCString { ankayma_ptp_start(fd, $0, boundIf) }
            if self.handle == nil {
                os_log("ankayma_ptp_start returned null", log: self.log, type: .error)
                completionHandler(PtpError.startFailed)
                return
            }
            os_log("tunnel up (fd=%d)", log: self.log, type: .info, fd)
            completionHandler(nil)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        os_log("stopTunnel (reason=%d)", log: log, type: .info, reason.rawValue)
        if let handle = handle {
            ankayma_ptp_stop(handle)
            self.handle = nil
        }
        completionHandler()
    }

    // MARK: Config (App Group)

    private struct TunnelConfig: Decodable {
        let overlay_ip: String
        let peers: [Peer]?
        /// F-3 private-DNS zone (e.g. "int.ankayma.com"), nil when the main app
        /// couldn't fetch the resolve table (private-default: no zone = no
        /// private names). The Rust pump answers queries under this zone itself
        /// (agent_core::dns) — Swift only needs it to scope `matchDomains`.
        let zone: String?
        /// Magic DNS address (same /64, host ::53) the pump answers on. Set as the
        /// DNS server AND added to includedRoutes so iOS routes queries into the
        /// tunnel — a query to this node's OWN overlay IP is not delivered to the
        /// packet flow. nil for an older app; falls back to overlay_ip.
        let dns_ip: String?
        // upstream_dns is present in the JSON but consumed by Rust (agent-ios-ptp),
        // which does the forwarding; Swift doesn't need to decode it.
        struct Peer: Decodable { let overlay_ip: String }
    }

    /// Read the config the main app wrote to the shared App Group container. Returns
    /// the decoded fields we need for routing plus the raw JSON to pass to Rust.
    private func loadConfig() -> (config: TunnelConfig, rawJSON: String)? {
        guard
            let container = FileManager.default.containerURL(
                forSecurityApplicationGroupIdentifier: Self.appGroup
            )
        else { return nil }
        let url = container.appendingPathComponent(Self.configFile)
        guard
            let data = try? Data(contentsOf: url),
            let config = try? JSONDecoder().decode(TunnelConfig.self, from: data),
            let rawJSON = String(data: data, encoding: .utf8)
        else { return nil }
        return (config, rawJSON)
    }

    /// Map the overlay address + peer list into iOS tunnel settings. iOS programs the
    /// utun interface address and the included routes from these; per-peer host routes
    /// (/32 v4, /128 v6) mirror the daemon's `add_peer_route`. `[T:A.1.3]`
    private func makeNetworkSettings(from config: TunnelConfig) -> NEPacketTunnelNetworkSettings {
        // The "remote address" is informational for a mesh (no single server); a
        // loopback placeholder is the conventional value. [T:Apple-NetworkExtension]
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let peerOverlays = (config.peers ?? []).map { $0.overlay_ip }

        if config.overlay_ip.contains(":") {
            let v6 = NEIPv6Settings(addresses: [config.overlay_ip], networkPrefixLengths: [128])
            v6.includedRoutes = peerOverlays.map {
                NEIPv6Route(destinationAddress: $0, networkPrefixLength: 128)
            }
            settings.ipv6Settings = v6
            // The IPv4 side exists ONLY to carry the magic-DNS query into the tunnel:
            // an IPv6 DNS server is a dead end — iOS sends NO packets at all for an
            // IPv6 tunnel resolver [T:Apple-DevForums-757674/735005]. So we hand iOS an
            // IPv4 resolver and must make its address land on the utun.
            //
            // The query only reaches packetFlow if the DNS server IP sits INSIDE a
            // subnet the tunnel actually routes AND the utun interface owns an address
            // in that same subnet (on-link). [T:Apple-DevForums-727012 "the DNS server
            // IP should be within your tunnel's routed subnet"]. Our earlier config —
            // interface 100.64.0.2/32 + a lone /32 route to 100.100.100.53 (a DIFFERENT
            // subnet) — did NOT: on-device capture showed zero packets to the DNS IP at
            // the tun (2026-07-03). Fix: put the dummy interface in the DNS server's own
            // /24 and route that /24, so 100.100.100.53 is on-link. Peer/data traffic
            // stays IPv6 over the routes above; the DNS answer is AAAA.
            if let dnsIP = config.dns_ip, dnsIP.contains(".") {
                // Interface address = DNS /24 base + host .2 (≠ the .53 DNS host).
                let octets = dnsIP.split(separator: ".")
                let base24 = octets.count == 4 ? "\(octets[0]).\(octets[1]).\(octets[2])" : "100.100.100"
                let v4 = NEIPv4Settings(addresses: ["\(base24).2"], subnetMasks: ["255.255.255.0"])
                v4.includedRoutes = [
                    NEIPv4Route(destinationAddress: "\(base24).0", subnetMask: "255.255.255.0")
                ]
                settings.ipv4Settings = v4
                NSLog("ankayma-ptp: IPv4 DNS carrier if=\(base24).2/24 route=\(base24).0/24 dns=\(dnsIP)")
            }
        } else {
            let v4 = NEIPv4Settings(addresses: [config.overlay_ip], subnetMasks: ["255.255.255.255"])
            v4.includedRoutes = peerOverlays.map {
                NEIPv4Route(destinationAddress: $0, subnetMask: "255.255.255.255")
            }
            settings.ipv4Settings = v4
        }
        settings.mtu = 1420  // [T:WireGuard] matches the pump's overlay MTU

        // F-3 private DNS: route ONLY this zone into the tunnel — everything else
        // keeps the device's normal resolver. The Rust pump (agent_core::dns,
        // wired in agent-ios-ptp's Config) answers matching queries itself from
        // `self_overlay_ip:53`; iOS has no split-DNS hook outside this setting,
        // unlike macOS's scoped `/etc/resolver/<zone>`. `[T: F-3 private-DNS]`
        if let zone = config.zone, !zone.isEmpty {
            // DNS server = the magic in-tunnel IPv4 address (routed above), NOT this
            // node's own overlay IP — iOS won't deliver a query to the interface's
            // own address to the packet flow.
            //
            // matchDomains = [""] (ALL domains) — the pattern wireguard-apple ships
            // unconditionally whenever DNS servers are set ("All DNS queries must
            // first go through the tunnel's DNS")
            // [T:wireguard-apple PacketTunnelSettingsGenerator.swift]. iOS consults
            // our in-tunnel resolver FIRST, system resolver as fallback
            // [T:Apple-DevForums-35027]. CONTRACT: the pump's resolver must answer
            // EVERY query — private → answer; other → forward upstream; forward
            // failure → SERVFAIL (pump::dns_fail). NEVER silence: iOS gives up on a
            // resolver that doesn't answer and won't use it again until reconnect
            // [T:Apple-DevForums-114097 — eskimo: giving up on "broken" DNS servers
            // is by design]. See docs/f3-ios-dns-forwarding-resolver.md.
            let dnsServer = config.dns_ip ?? config.overlay_ip
            let dns = NEDNSSettings(servers: [dnsServer])
            dns.matchDomains = [""]
            settings.dnsSettings = dns
            NSLog("ankayma-ptp: DNS server=\(dnsServer) matchDomains=[\"\"] (all; forward-or-fallback)")
        }
        return settings
    }

    // MARK: utun fd

    /// Find the utun file descriptor backing `packetFlow`. iOS doesn't expose it, so
    /// we scan the process fds for the one whose UTUN_OPT_IFNAME is a "utun*" name —
    /// the established approach from wireguard-apple. `[T:wireguard-apple]`
    private var tunnelFileDescriptor: Int32? {
        let sysprotoControl: Int32 = 2  // SYSPROTO_CONTROL [T:Apple-XNU sys/kern_control.h]
        let utunOptIfname: Int32 = 2    // UTUN_OPT_IFNAME  [T:Apple-XNU net/if_utun.h]
        var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        for fd: Int32 in 0...1024 {
            var len = socklen_t(name.count)
            if getsockopt(fd, sysprotoControl, utunOptIfname, &name, &len) == 0,
                String(cString: name).hasPrefix("utun")
            {
                return fd
            }
        }
        return nil
    }

    /// Index of the physical interface to pin the pump's UDP socket to (WiFi `en0`
    /// or cellular `pdp_ip0`), so its packets egress the device instead of looping
    /// into our own tunnel. Heuristic: the first UP, non-loopback interface that is
    /// NOT our own tun/ipsec, with an assigned address. Returns 0 if none found
    /// (Rust then skips pinning). `[T:wireguard-apple]`
    private func physicalInterfaceIndex() -> UInt32 {
        var result: UInt32 = 0
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0 else { return 0 }
        defer { freeifaddrs(ifap) }
        var ptr = ifap
        while let cur = ptr {
            defer { ptr = cur.pointee.ifa_next }
            let name = String(cString: cur.pointee.ifa_name)
            let flags = Int32(cur.pointee.ifa_flags)
            let isUp = (flags & Int32(IFF_UP)) != 0
            let isLoopback = (flags & Int32(IFF_LOOPBACK)) != 0
            let isOurTunnel =
                name.hasPrefix("utun") || name.hasPrefix("ipsec") || name.hasPrefix("lo")
            guard isUp, !isLoopback, !isOurTunnel, cur.pointee.ifa_addr != nil else { continue }
            // Prefer an IPv4-capable physical iface (our peers' endpoints are IPv4);
            // fall back to the first eligible one otherwise.
            let family = cur.pointee.ifa_addr.pointee.sa_family
            let idx = if_nametoindex(name)
            if idx != 0 {
                if family == UInt8(AF_INET) {
                    return idx  // best match — done
                }
                if result == 0 { result = idx }  // remember first eligible
            }
        }
        return result
    }
}

private enum PtpError: Error {
    case missingConfig
    case noTunFd
    case startFailed
}

// NOTE: DNS forwarding of non-private names is NOT done on the Swift side. An earlier
// version relayed via `NEPacketTunnelProvider.createUDPSession`/`NWUDPSession`, built on
// the (false) premise that a raw socket can't egress a Packet Tunnel Provider. It can:
// a plain BSD UDP socket pinned to the physical interface with `IP_BOUND_IF` egresses
// the real network — that's how our WG data socket already reaches peers, and how
// Tailscale forwards on darwin [T:Tailscale net/netns/netns_darwin.go]. The relay now
// lives in Rust (agent-ios-ptp `ios_dns_forward`), so the whole NWUDPSession bridge was
// removed. See docs/f3-ios-dns-forwarding-resolver.md.

/// Diagnostic sink the Rust pump calls (via `pump::set_log_hook`) so its send/recv
/// path shows up in the device log — the extension has no stdout. Reaches
/// idevicesyslog like the other `NSLog` lines.
@_cdecl("ankayma_ptp_log")
public func ankayma_ptp_log(_ msg: UnsafePointer<CChar>) {
    // Pass the whole line as a single %@ argument — NEVER as the format string
    // itself (the pump's messages contain no format specifiers, but a raw arg is
    // also redacted/garbled as "{public}@" when used as the format). `[T:NSLog]`
    NSLog("%@", "ankayma-pump: " + String(cString: msg))
}
