extern crate pkg_config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/management.proto")?;
    let library = pkg_config::Config::new().probe("nix-store-c")?;

    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("src/store_wrapper.h")
        .clang_args(
            library
                .include_paths
                .iter()
                .map(|path| format!("-I{}", path.to_string_lossy())),
        )
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
    Ok(())
}
