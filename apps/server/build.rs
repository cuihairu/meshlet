// Embed the Windows exe icon (assets/icons/meshlet.ico, generated from
// logo-copper.svg) into the executable's resource section via winresource.
//
// Gate rules (mirrors the cargo-wix-packaging playbook):
// - The build-dependency is unconditional, but the resource compilation is
//   host/target gated: winresource needs an MSVC resource compiler (rc.exe),
//   which only exists on a Windows host.
// - On a Windows host targeting Windows (CI nightly), a failure is a hard
//   error: we never silently ship an icon-less exe.
// - On any other host/target combination (e.g. Linux CI checks, cross
//   builds), embedding is skipped with a warning so local non-Windows
//   development is unaffected.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    if !cfg!(windows) {
        println!("cargo:warning=skipping exe icon embedding: host is not Windows");
        return;
    }
    let icon = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../assets/icons/meshlet.ico");
    let mut res = winresource::WindowsResource::new();
    res.set_icon(icon.to_str().expect("icon path is valid UTF-8"));
    if let Err(e) = res.compile() {
        panic!("failed to embed Windows icon resource ({icon:?}): {e}");
    }
}
