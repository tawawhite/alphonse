use std::env::var;

fn main() {
    let manifest_dir = var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-search={}/build/install/lib", manifest_dir);
    println!(
        "cargo:rustc-link-search={}/build/install/lib64",
        manifest_dir
    );
    println!(
        "cargo:rustc-link-search={}/build/install/lib/x86_64-linux-gnu",
        manifest_dir
    );
    println!(
        "cargo:rustc-link-search={}/build/install/lib64/x86_64-linux-gnu",
        manifest_dir
    );
}
