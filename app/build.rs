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

    #[cfg(all(target_os = "linux", feature = "dpdk"))]
    {
        println!("cargo:rustc-link-lib=rte_eal");
        // println!("cargo:rustc-link-lib=rte_ring");
        // println!("cargo:rustc-link-lib=rte_net_ring");
    };
}
