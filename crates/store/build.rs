fn main() {
    // The embedded migrations are read at compile time.
    println!("cargo:rerun-if-changed=migrations");
}
