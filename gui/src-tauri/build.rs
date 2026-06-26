fn main() {
    tauri_build::build();

    // iOS: the app's Rust lib (cdylib) calls Swift @_cdecl functions (the VpnBridge —
    // ankayma_vpn_*) that live in the app *target* and are compiled by Xcode after
    // cargo links this dylib. Defer resolving those symbols to load time (they live in
    // the same app binary at runtime) instead of failing the cargo link. [T:A.1.9]
    // `[T:ld64 -undefined dynamic_lookup]`
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("ios") {
        println!("cargo:rustc-link-arg=-Wl,-undefined,dynamic_lookup");
    }
}
