fn main() {
    // Source directories
    let common_dir = "src/common";
    let mldsa44_dir = "src/mldsa44";
    
    // C source files from common directory
    let common_files = [
        "src/common/fips202.c",
        "src/common/randombytes.c", 
        "src/common/memory_cleanse.c",
    ];
    
    // C source files from mldsa44 directory
    let mldsa44_files = [
        "src/mldsa44/ntt.c",
        "src/mldsa44/packing.c", 
        "src/mldsa44/poly.c",
        "src/mldsa44/polyvec.c",
        "src/mldsa44/reduce.c",
        "src/mldsa44/rounding.c",
        "src/mldsa44/sign.c",
        "src/mldsa44/symmetric-shake.c",
    ];

    // Combine all files
    let mut all_files = Vec::new();
    all_files.extend_from_slice(&common_files);
    all_files.extend_from_slice(&mldsa44_files);

    // Build C library
    cc::Build::new()
        .files(&all_files)
        .include(common_dir)
        .include(mldsa44_dir)
        .flag("-O3")
        .flag("-std=c99")
        .compile("ml-dsa-44-clean");

    // Tell cargo to link the library
    println!("cargo:rustc-link-lib=static=ml-dsa-44-clean");

    // Tell cargo to rerun build script if C files change
    for file in &all_files {
        println!("cargo:rerun-if-changed={}", file);
    }
    
    // Watch header files too
    println!("cargo:rerun-if-changed=src/common");
    println!("cargo:rerun-if-changed=src/mldsa44");
}