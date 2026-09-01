fn main() {
    // 用 Tauri 内置 WindowsAttributes 注入我们自己的 manifest(含 requireAdministrator)。
    let manifest = include_str!("app.manifest");
    let attrs = tauri_build::WindowsAttributes::new().app_manifest(manifest);
    let cfg = tauri_build::Attributes::new().windows_attributes(attrs);
    if let Err(e) = tauri_build::try_build(cfg) {
        panic!("tauri-build error: {e:#}");
    }
}
