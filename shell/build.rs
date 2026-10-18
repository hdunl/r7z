//! rustc exports DllGetClassObject and DllCanUnloadNow through its own export list, so the
//! linker notes that COM entry points are usually PRIVATE (left out of the import library).
//! Nothing links against this DLL; only COM loads it, so the note does not apply.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-cdylib-link-arg=/IGNORE:4104");
    }
}
