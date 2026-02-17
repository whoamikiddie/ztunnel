fn main() {
    // Link libznet (built by CMake in workspace root)
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let libznet_path = std::path::Path::new(&manifest_dir).parent().unwrap().join("libznet/build");
    println!("cargo:rustc-link-search=native={}", libznet_path.display());
    println!("cargo:rustc-link-lib=static=znet");
    
    // Rerun if libznet changes
    println!("cargo:rerun-if-changed=../libznet/src");
    println!("cargo:rerun-if-changed=../libznet/include");
}
