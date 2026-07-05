// TunnelManager — host-app side of the Ankayma VPN on iOS. OPEN.
//
// The app (not the extension) installs and controls the tunnel: it writes the
// resolved config (this node's key + overlay IP + peers — produced by the app's
// Rust agent-core: enroll + GET /peers) to the shared App Group, installs an
// NETunnelProviderManager bound to our Packet Tunnel extension, and starts/stops
// it. The extension then reads that config and runs the pump. [T:A.1.9]
//
// Exposed to the Tauri/JS layer through the app's mobile plugin bridge (connect /
// disconnect / status). Pure NetworkExtension here — no Rust symbols — so it
// type-checks against the iOS SDK on its own.

import Foundation
import NetworkExtension

@objc final class TunnelManager: NSObject {
    @objc static let shared = TunnelManager()

    /// Must match the extension's bundle id + the App Group registered in the portal.
    private let tunnelBundleId = "com.ankayma.app.tunnel"
    private static let appGroup = "group.com.ankayma.app"
    private static let configFile = "tunnel-config.json"

    /// Last known connection status as an NEVPNStatus rawValue (0=invalid, 1=disconnected,
    /// 2=connecting, 3=connected, 4=reasserting, 5=disconnecting). Updated by a status
    /// observer so the sync C bridge (`ankayma_vpn_status`) can read it without an async
    /// load. `@objc` + main-actor-free so the bridge reads it directly.
    @objc private(set) var cachedStatusCode: Int32 = 0
    private var statusObserver: NSObjectProtocol?

    /// Observe the manager's connection so `cachedStatusCode` tracks reality. Idempotent.
    private func beginMonitoring(_ manager: NETunnelProviderManager) {
        cachedStatusCode = Int32(manager.connection.status.rawValue)
        if let observer = statusObserver { NotificationCenter.default.removeObserver(observer) }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: manager.connection, queue: .main
        ) { [weak self] _ in
            self?.cachedStatusCode = Int32(manager.connection.status.rawValue)
        }
    }

    /// Load the installed manager (if any) and start tracking its status — call once on
    /// app launch so the UI shows the real state before the user taps connect.
    @objc func primeStatus() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, _ in
            if let manager = managers?.first { self?.beginMonitoring(manager) }
        }
    }

    // MARK: Config (App Group)

    /// Write the resolved tunnel config JSON to the shared App Group container, where
    /// the extension reads it on startTunnel. Connection metadata + this node's key
    /// only — no business payload. `[T:A.1.1]`
    func writeConfig(_ json: String) throws {
        guard
            let container = FileManager.default.containerURL(
                forSecurityApplicationGroupIdentifier: Self.appGroup
            )
        else { throw TunnelError.noAppGroup }
        let url = container.appendingPathComponent(Self.configFile)
        guard let data = json.data(using: .utf8) else { throw TunnelError.badConfig }
        try data.write(to: url, options: .atomic)
    }

    // MARK: Manager lifecycle

    /// Load the existing tunnel manager or create one bound to our extension, saving
    /// it to the system VPN preferences (this is what shows under Settings > VPN).
    private func loadOrCreateManager(
        _ completion: @escaping (Result<NETunnelProviderManager, Error>) -> Void
    ) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error = error { completion(.failure(error)); return }
            let manager = managers?.first ?? NETunnelProviderManager()

            let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol)
                ?? NETunnelProviderProtocol()
            proto.providerBundleIdentifier = self.tunnelBundleId
            proto.serverAddress = "Ankayma mesh"  // informational for a mesh
            manager.protocolConfiguration = proto
            manager.localizedDescription = "Ankayma"
            manager.isEnabled = true

            manager.saveToPreferences { error in
                if let error = error { completion(.failure(error)); return }
                // FRESH reload after save. On the FIRST install, loadFromPreferences
                // on the SAME manager object can hand back a connection that
                // startVPNTunnel() rejects (config not yet active system-side) — the
                // root of the "connect, then disconnect+connect again" dance. A full
                // loadAllFromPreferences returns the system-committed manager.
                // [known wireguard-apple first-install race]
                NETunnelProviderManager.loadAllFromPreferences { managers, error in
                    if let error = error { completion(.failure(error)); return }
                    let fresh = managers?.first(where: {
                        ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                            .providerBundleIdentifier == self.tunnelBundleId
                    }) ?? managers?.first ?? manager
                    completion(.success(fresh))
                }
            }
        }
    }

    // MARK: Public control (called from the Tauri plugin bridge)

    /// Write the config, then start the tunnel.
    @objc func connect(configJSON: String, completion: @escaping (Error?) -> Void) {
        do {
            try writeConfig(configJSON)
        } catch {
            completion(error)
            return
        }
        loadOrCreateManager { result in
            switch result {
            case .failure(let error):
                completion(error)
            case .success(let manager):
                self.beginMonitoring(manager)
                self.startTunnel(manager, retriesLeft: 1, completion: completion)
            }
        }
    }

    /// Start the tunnel, self-healing the first-install case. On a brand-new VPN
    /// install `startVPNTunnel()` can throw, or succeed but immediately fall back to
    /// .disconnected, because the freshly-saved config isn't active yet — that's why
    /// the very first connect needed a manual disconnect→connect. We retry once:
    ///  - if start THROWS → wait, reload, retry;
    ///  - if start succeeds but the status is still .disconnected/.invalid after a
    ///    short settle → reload a fresh manager + retry.
    private func startTunnel(
        _ manager: NETunnelProviderManager,
        retriesLeft: Int,
        completion: @escaping (Error?) -> Void
    ) {
        func retryFresh() {
            NETunnelProviderManager.loadAllFromPreferences { managers, _ in
                let m = managers?.first(where: {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                        .providerBundleIdentifier == self.tunnelBundleId
                }) ?? manager
                self.beginMonitoring(m)
                self.startTunnel(m, retriesLeft: retriesLeft - 1, completion: { _ in })
            }
        }
        do {
            try manager.connection.startVPNTunnel()
            // Report success to the UI now; the settle-check below silently fixes a
            // stuck first start without bothering the caller.
            completion(nil)
            if retriesLeft > 0 {
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                    let s = manager.connection.status
                    if s == .disconnected || s == .invalid { retryFresh() }
                }
            }
        } catch {
            if retriesLeft > 0 {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) {
                    self.startTunnel(manager, retriesLeft: retriesLeft - 1, completion: completion)
                }
            } else {
                completion(error)
            }
        }
    }

    /// Stop the tunnel (leaves the configuration installed).
    @objc func disconnect(completion: @escaping (Error?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error = error { completion(error); return }
            managers?.first?.connection.stopVPNTunnel()
            completion(nil)
        }
    }

    /// Current connection status, as a lowercase string for the UI.
    @objc func status(completion: @escaping (String) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { managers, _ in
            let status = managers?.first?.connection.status ?? .invalid
            completion(Self.statusString(status))
        }
    }

    private static func statusString(_ status: NEVPNStatus) -> String {
        switch status {
        case .invalid: return "invalid"
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .reasserting: return "reasserting"
        case .disconnecting: return "disconnecting"
        @unknown default: return "unknown"
        }
    }
}

enum TunnelError: Error {
    case noAppGroup
    case badConfig
}
