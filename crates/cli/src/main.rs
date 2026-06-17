//! `mesh` CLI — advanced ops (Part A §A.2.1 management plane). OPEN.
//!
//! Key subcommands mirror the stock `wg(8)` tools so output is interchangeable:
//!   `mesh genkey`  → emit a fresh WireGuard private key (base64) on stdout
//!   `mesh pubkey`  → read a private key on stdin, emit its public key

use std::io::{self, Read, Write};
use std::process::ExitCode;

use agent_core::WgKeypair;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("genkey") => {
            // [T:wg(8)] `wg genkey` writes the private key to stdout, nothing else.
            println!("{}", WgKeypair::generate().private_b64);
            ExitCode::SUCCESS
        }
        Some("pubkey") => {
            // [T:wg(8)] `wg pubkey` reads a private key from stdin, writes the public key.
            let mut input = String::new();
            if io::stdin().read_to_string(&mut input).is_err() {
                eprintln!("mesh pubkey: failed to read stdin");
                return ExitCode::FAILURE;
            }
            match WgKeypair::public_from_private_b64(input.trim()) {
                Ok(pubkey) => {
                    println!("{pubkey}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("mesh pubkey: invalid private key ({e:?})");
                    ExitCode::FAILURE
                }
            }
        }
        Some(other) => {
            eprintln!("mesh: unknown command '{other}'");
            usage();
            ExitCode::FAILURE
        }
        None => {
            usage();
            ExitCode::SUCCESS
        }
    }
}

fn usage() {
    let _ = writeln!(
        io::stderr(),
        "mesh — Ankayma agent CLI\n\
         \n\
         USAGE:\n\
         \x20 mesh genkey          Generate a WireGuard private key (base64)\n\
         \x20 mesh pubkey          Read a private key on stdin, print its public key\n\
         \n\
         EXAMPLE:\n\
         \x20 mesh genkey | tee priv.key | mesh pubkey"
    );
}
