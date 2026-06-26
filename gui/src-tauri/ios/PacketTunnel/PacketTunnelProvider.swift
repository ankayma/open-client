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
        guard let loaded = loadConfig() else {
            os_log("no tunnel config in app group", log: log, type: .error)
            completionHandler(PtpError.missingConfig)
            return
        }

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
            // it needs for the routes above.
            self.handle = loaded.rawJSON.withCString { ankayma_ptp_start(fd, $0) }
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
        } else {
            let v4 = NEIPv4Settings(addresses: [config.overlay_ip], subnetMasks: ["255.255.255.255"])
            v4.includedRoutes = peerOverlays.map {
                NEIPv4Route(destinationAddress: $0, subnetMask: "255.255.255.255")
            }
            settings.ipv4Settings = v4
        }
        settings.mtu = 1420  // [T:WireGuard] matches the pump's overlay MTU
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
}

private enum PtpError: Error {
    case missingConfig
    case noTunFd
    case startFailed
}
