//! domain — entity types, policy, events (Part A §A.3.1).

use serde::{Deserialize, Serialize};

/// Enrollment request to the control-plane Agent API.
/// Mirrors the control-plane `EnrollReq` wire shape. `[T:B.5.1]`
#[derive(Debug, Clone, Serialize)]
pub struct EnrollRequest {
    /// This node's WireGuard public key (base64).
    pub public_key: String,
    /// Human-readable device name.
    pub hostname: String,
    /// Optional reachable "ip:port" the agent advertises to peers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// Control-plane response to a successful enrollment. `[T:B.5.1]`
#[derive(Debug, Clone, Deserialize)]
pub struct EnrollResponse {
    pub node_id: String,
    /// Assigned overlay IP from the 100.64.0.0/10 CGNAT pool (RFC 6598).
    pub overlay_ip: String,
    pub allowed_ips: Vec<String>,
    pub peers: Vec<PeerInfo>,
}

/// A peer in the mesh as returned by the control-plane. `[T:B.5.1]`
/// `[T:A.1.1]` metadata only — no business payload crosses the control plane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerInfo {
    pub node_id: String,
    pub public_key: String,
    pub overlay_ip: String,
    pub hostname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_request_serializes_expected_keys() {
        let req = EnrollRequest {
            public_key: "PUBKEY".into(),
            hostname: "laptop".into(),
            endpoint: None,
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["public_key"], "PUBKEY");
        assert_eq!(v["hostname"], "laptop");
        // endpoint omitted when None (matches control-plane #[serde(default)]).
        assert!(v.get("endpoint").is_none());
    }

    #[test]
    fn enroll_response_parses_control_plane_shape() {
        // Shape emitted by control-plane bin/control-plane (EnrollResp). [T:B.5.1]
        let json = r#"{
            "node_id": "n1",
            "overlay_ip": "100.64.0.2",
            "allowed_ips": ["100.64.0.2/32"],
            "peers": [
                {"node_id":"n2","public_key":"K2","overlay_ip":"100.64.0.3","hostname":"phone"}
            ]
        }"#;
        let resp: EnrollResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.overlay_ip, "100.64.0.2");
        assert_eq!(resp.peers.len(), 1);
        assert_eq!(resp.peers[0].hostname, "phone");
        assert_eq!(resp.peers[0].endpoint, None);
    }
}
