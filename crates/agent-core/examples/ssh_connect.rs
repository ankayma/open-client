//! ssh_connect — connect the F-2 russh client straight to a host:port (no control
//! plane), for VALIDATION only. Sends piped stdin to the remote shell and prints
//! its output. Not shipped.
//!
//!   printf 'id\nexit\n' | ssh_connect <host> [port]

use agent_core::ssh_client::{MeshSshKey, SshConnectOptions, SshEvent, SshSession};
use std::io::{Read, Write};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let host = args
        .get(1)
        .cloned()
        .expect("usage: ssh_connect <host> [port]");
    let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(22022);

    // Read the piped commands up front (this tool is for scripted validation).
    let mut input = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut input);

    let key = MeshSshKey::load_or_generate(std::path::Path::new("/tmp/f2-ssh-connect-key"))
        .expect("mesh key");
    let mut opts = SshConnectOptions::new(host, "ankayma");
    opts.port = port;
    opts.allow_unpinned = true; // test: no control-plane host-key pin available

    let mut sess = SshSession::connect(&opts, &key).await.expect("connect");
    if !input.is_empty() {
        let _ = sess.write(&input).await;
    }
    let _ = sess.send_eof().await;

    let mut out = std::io::stdout();
    while let Some(ev) = sess.recv().await {
        match ev {
            SshEvent::Data(d) => {
                let _ = out.write_all(&d);
                let _ = out.flush();
            }
            SshEvent::Exit(_) | SshEvent::Disconnected => break,
            SshEvent::Eof => {}
        }
    }
}
