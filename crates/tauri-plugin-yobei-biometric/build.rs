// Build wiring for the yobei-biometric plugin: no JS commands (the vault
// key must never enter the webview), only the Android module.
fn main() {
    tauri_plugin::Builder::new(&[] as &[&str])
        .android_path("android")
        .build();

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let mobile = target_os == "ios" || target_os == "android";
    alias("desktop", !mobile);
    alias("mobile", mobile);
}

fn alias(alias: &str, has_feature: bool) {
    println!("cargo:rustc-check-cfg=cfg({alias})");
    if has_feature {
        println!("cargo:rustc-cfg={alias}");
    }
}
