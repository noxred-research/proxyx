fn main() {
    // Prefer an externally-provided protoc (PROTOC env, e.g. nixpkgs protobuf
    // in the Nix/CI build sandbox where the vendored binary can't run); fall
    // back to the bundled protoc for plain local dev.
    // SAFETY: build.rs runs single-threaded; no other thread reads PROTOC.
    if std::env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc binary");
        unsafe {
            std::env::set_var("PROTOC", protoc);
        }
    }
    let mut config = prost_build::Config::new();
    config.bytes(["."]);
    config
        .compile_protos(&["proto/proxyx.proto"], &["proto"])
        .expect("compile proxyx.proto");
    println!("cargo:rerun-if-changed=proto/proxyx.proto");
}
