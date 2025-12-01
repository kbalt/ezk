use cmake::Config;
use std::{env, path::PathBuf};

fn main() {
    build_and_link();

    // Generate bindings
    bindgen::Builder::default()
        .clang_args(&["-I./libsrtp/include"])
        .header("libsrtp/include/srtp.h")
        .allowlist_function("(srtp|SRTP|srtcp|SRTCP)_.*")
        .allowlist_type("(srtp|SRTP|srtcp|SRTCP)_.*")
        .allowlist_var("(srtp|SRTP|srtcp|SRTCP)_.*")
        .derive_partialeq(true)
        .derive_eq(true)
        .generate()
        .unwrap()
        .write_to_file(format!("{}/bindings.rs", env::var("OUT_DIR").unwrap()))
        .unwrap();
}

fn build_and_link() {
    let openssl_dir = env::var("DEP_OPENSSL_INCLUDE").unwrap();

    let dst = Config::new("libsrtp")
        .define("ENABLE_OPENSSL", "ON")
        .define("LIBSRTP_TEST_APPS", "OFF")
        .define("OPENSSL_ROOT_DIR", PathBuf::from(openssl_dir).join(".."))
        .build();

    println!(
        "cargo:rustc-link-search=native={}",
        dst.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=srtp2");
}
