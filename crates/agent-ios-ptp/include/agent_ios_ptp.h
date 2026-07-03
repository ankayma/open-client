/*
 * agent_ios_ptp.h — C ABI for the iOS Packet Tunnel Provider FFI (agent-ios-ptp).
 *
 * Hand-written (no cbindgen) to keep the dependency/build surface minimal and
 * auditable [T:A.1.21]. The Swift NEPacketTunnelProvider imports this via a
 * bridging header and links libagent_ios_ptp.a.
 *
 * Contract:
 *   - Call ankayma_ptp_start() from startTunnel(), passing the utun fd from
 *     packetFlow (tunnelFileDescriptor) and a JSON config string. Routes + overlay
 *     IP are set on the Swift side via NEPacketTunnelNetworkSettings BEFORE this.
 *   - config_json shape:
 *       { "private_key_b64": "<base64 32-byte X25519 private key>",
 *         "overlay_ip":      "10.x.y.z" | "<IPv6>",
 *         "listen_port":     51820,                       // optional, default 51820
 *         "peers": [ { "node_id":"…", "public_key":"<b64>",
 *                      "overlay_ip":"…", "hostname":"…",
 *                      "endpoint":"host:port" (optional) } ] }
 *   - Pass the returned handle to ankayma_ptp_stop() from stopTunnel().
 */
#ifndef AGENT_IOS_PTP_H
#define AGENT_IOS_PTP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque tunnel handle owned by the caller. */
typedef struct PtpHandle PtpHandle;

/*
 * Start the WireGuard packet pump over `fd` using `config_json`.
 * Returns an opaque handle, or NULL on error (details go to the device console).
 * `fd` must stay open for the tunnel's lifetime; `config_json` is a NUL-terminated
 * UTF-8 string read only for the duration of the call.
 * `bound_if` is the index of the PHYSICAL interface (WiFi/cellular) to pin the pump's
 * UDP socket to (IP_BOUND_IF), so its packets egress the device instead of being
 * swallowed by our own tunnel. Pass 0 to skip pinning. Get it in the extension via
 * if_nametoindex on the primary non-loopback/non-utun interface.
 */
PtpHandle *ankayma_ptp_start(int32_t fd, const char *config_json, uint32_t bound_if);

/* Stop the tunnel and free `handle`. NULL is a no-op. */
void ankayma_ptp_stop(PtpHandle *handle);

/*
 * F-3 DNS forwarding is done entirely inside Rust (agent-ios-ptp `ios_dns_forward`):
 * a non-private query is relayed to the device's upstream over a BSD UDP socket pinned
 * to the physical interface (IP_BOUND_IF), which egresses the real network from the
 * Packet Tunnel Provider — same as the WG data socket, and how Tailscale does it on
 * darwin [T:Tailscale net/netns/netns_darwin.go]. No Swift/FFI DNS bridge is needed. */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AGENT_IOS_PTP_H */
