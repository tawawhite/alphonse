use std::env::var;

#[cfg(all(target_os = "linux", feature = "dpdk"))]
extern crate bindgen;
#[cfg(all(target_os = "linux", feature = "dpdk"))]
extern crate cpp_build;

#[cfg(all(target_os = "linux", feature = "dpdk"))]
fn build_dpdk() {
    let dpdk_bindings = bindgen::Builder::default()
        .header("src/ffi/dpdk.h")
        .clang_args(
            vec![
                "-I",
                "build/install/include/dpdk/generic",
                "-I",
                "build/install/include/dpdk",
            ]
            .iter(),
        )
        // rte_arp_ipv4 has some problems with the rustc compiler, it is only used by rte_qrp_hdr,
        // and rte_qrp_hdr is not used in any public api,
        // so we blacklist these two data struct to generate a valid DPDK binding
        .blacklist_type("rte_arp_hdr")
        .blacklist_type("rte_arp_ipv4")
        .generate_inline_functions(true)
        .rust_target(bindgen::LATEST_STABLE_RUST)
        .generate()
        .expect("Unable to generate dpdk bindings");
    dpdk_bindings
        .write_to_file("src/dpdk/raw.rs")
        .expect("Unable to generate dpdk bindings");

    cpp_build::Config::new()
        .include("src")
        .include("build/install/include/dpdk")
        .include("build/install/include/dpdk/generic/")
        // .flag("-mavx2")
        .build("src/dpdk/header.rs");
}

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

    #[cfg(all(target_os = "linux", feature = "dpdk"))]
    {
        build_dpdk();
        println!("cargo:rustc-link-lib=rte_eal");
        println!("cargo:rustc-link-lib=rte_kvargs");
    };
}
