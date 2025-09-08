use std::env;

fn main() {
    println!("cargo:rustc-link-lib=va");
    println!("cargo:rustc-link-lib=va-drm");

    bindgen::Builder::default()
        .header("/usr/include/va/va.h")
        .header("/usr/include/va/va_drm.h")
        .allowlist_function("(va|VA).*")
        .allowlist_type("(va|VA).*")
        .allowlist_var("(va|VA).*")
        .derive_partialeq(true)
        .derive_eq(true)
        .derive_debug(true)
        .generate()
        .unwrap()
        .write_to_file(format!("{}/bindings.rs", env::var("OUT_DIR").unwrap()))
        .unwrap();
}
