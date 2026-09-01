// Tauri v2 入口 — 调 lib::run()
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    guardmeta_vsp_lib::run()
}
