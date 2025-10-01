use std::env;

fn main() {
    if cfg!(not(target_os = "linux")) {
        return;
    }

    let libva = pkg_config::probe_library("libva").unwrap();
    let libva_drm = pkg_config::probe_library("libva-drm").unwrap();

    for lib in libva.libs.into_iter().chain(libva_drm.libs) {
        println!("cargo:rustc-link-lib={lib}");
    }

    let mut bindgen = bindgen::Builder::default();

    for include_path in libva
        .include_paths
        .into_iter()
        .chain(libva_drm.include_paths)
    {
        bindgen = bindgen.clang_arg(format!("-I{}", include_path.to_string_lossy()));
    }

    bindgen
        .header("wrapper.h")
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
