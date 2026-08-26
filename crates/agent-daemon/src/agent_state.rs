//! agent_state — local persistence for an enrolled AGENT identity's handle, so
//! `agent ssh --as <handle>` reuses ONE identity across every delegation window
//! instead of redeeming a fresh single-use token per connection. OPEN.
//!
//! Two files per handle, both under `~/.ankayma/`:
//!   - `agent-identities.json` — a map `{handle: {agent_actor_id, self_node_id}}`,
//!     everything the control plane already knows and safe to read back in plain
//!     text (no secret in this file).
//!   - `agent-<handle>-session.key` — the signing key this handle proves possession
//!     of on every call after enrollment. The type lives in
//!     `agent_core::session_grant::AgentSessionKey` (that crate already carries
//!     `ed25519-dalek`, this one does not — A.1.21); this module only owns the path
//!     it is persisted at.

use agent_core::session_grant::AgentSessionKey;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

fn state_dir() -> PathBuf {
    Path::new(&crate::up::home_root()).join(".ankayma")
}

fn identities_path() -> PathBuf {
    state_dir().join("agent-identities.json")
}

fn session_key_path(handle: &str) -> PathBuf {
    state_dir().join(format!("agent-{handle}-session.key"))
}

/// What the control plane told us when this handle was first enrolled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub agent_actor_id: String,
    pub self_node_id: String,
}

/// Look up a previously-enrolled handle. `Ok(None)` means the handle was never
/// bootstrapped on THIS machine — not an error, the caller decides what to do about it.
pub fn load(handle: &str) -> Result<Option<AgentIdentity>> {
    let path = identities_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow!("read {}: {e}", path.display())),
    };
    let map: HashMap<String, AgentIdentity> =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(map.get(handle).cloned())
}

/// Persist a handle's identity, adding to (never silently replacing) whatever other
/// handles this machine already knows about.
pub fn save(handle: &str, identity: &AgentIdentity) -> Result<()> {
    let path = identities_path();
    let mut map: HashMap<String, AgentIdentity> = match std::fs::read_to_string(&path) {
        Ok(t) => serde_json::from_str(&t).unwrap_or_default(),
        Err(_) => HashMap::new(),
    };
    map.insert(handle.to_string(), identity.clone());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(&map).context("encode agent identities")?;
    std::fs::write(&path, json).with_context(|| format!("write {}", path.display()))
}

/// This handle's own signing key, loaded from (or generated into) its persisted path.
pub fn session_key(handle: &str) -> Result<AgentSessionKey> {
    AgentSessionKey::load_or_create(&session_key_path(handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_round_trip_through_the_json_shape() {
        // `load`/`save` resolve their path via `crate::up::home_root()`, which is a
        // process-wide `$HOME`-derived value tests can't override per-case without a
        // shared mutable env var — so this exercises the JSON shape those functions
        // read/write directly, which is the part with anything to get wrong (the
        // paths themselves are one-line `Path::join` calls).
        let mut map = HashMap::new();
        map.insert(
            "claude-1".to_string(),
            AgentIdentity {
                agent_actor_id: "act_a_1".to_string(),
                self_node_id: "ci_1".to_string(),
            },
        );
        let json = serde_json::to_string_pretty(&map).unwrap();
        let back: HashMap<String, AgentIdentity> = serde_json::from_str(&json).unwrap();
        assert_eq!(back["claude-1"].agent_actor_id, "act_a_1");
        assert_eq!(back["claude-1"].self_node_id, "ci_1");
    }

    #[test]
    fn a_session_key_is_generated_once_and_reused() {
        let dir = std::env::temp_dir().join(format!("ankayma-agentstate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("k.key");
        let a = AgentSessionKey::load_or_create(&path).expect("first create");
        let b = AgentSessionKey::load_or_create(&path).expect("reload");
        assert_eq!(a.public_b64(), b.public_b64(), "same file, same key");
    }
}
