//! 反汇编标注 (P93) — labels / comments / functions
//!
//! 内存 store (per-session). 同时通过 project_io ProjectDoc 持久化到 .gmproj.
//!
//! 数据形式 (前端 + 项目文件):
//!   labels: { "0x140001000": "MyFunc" }
//!   comments: { "0x140001020": "decrypt the buffer here" }
//!   functions: { "0x140001000": { name: "MyFunc", size: 256 } }
//!
//! disasm 工具结果里自动附 attached_label / attached_comment / function 信息.
//! resolve_symbol 在自定义 label 存在时优先用 label.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::util::error::AppResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDef {
    pub name: String,
    pub size: u32,
}

#[derive(Debug, Default)]
pub struct AnnotationStore {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Inner {
    pub labels: HashMap<String, String>,           // "0x..." → name
    pub comments: HashMap<String, String>,         // "0x..." → text
    pub functions: HashMap<String, FunctionDef>,   // "0x..." → {name, size}
}

impl AnnotationStore {
    pub fn new() -> Self { Self::default() }

    pub fn snapshot(&self) -> Inner { self.inner.lock().unwrap().clone() }

    pub fn replace(&self, data: Inner) {
        *self.inner.lock().unwrap() = data;
    }

    pub fn label_for(&self, addr: u64) -> Option<String> {
        let key = format!("0x{:x}", addr);
        self.inner.lock().unwrap().labels.get(&key).cloned()
    }

    pub fn comment_for(&self, addr: u64) -> Option<String> {
        let key = format!("0x{:x}", addr);
        self.inner.lock().unwrap().comments.get(&key).cloned()
    }

    pub fn function_at(&self, addr: u64) -> Option<(u64, FunctionDef)> {
        // 找 addr 所在的函数 (start <= addr < start+size)
        let i = self.inner.lock().unwrap();
        for (k, def) in i.functions.iter() {
            if let Some(start) = parse_hex_key(k) {
                if addr >= start && addr < start + def.size as u64 {
                    return Some((start, def.clone()));
                }
            }
        }
        None
    }
}

fn parse_hex_key(k: &str) -> Option<u64> {
    let s = k.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).ok()
}

// ===== Tauri commands =====

#[derive(Debug, Deserialize)]
pub struct SetLabelReq { pub address: String, pub name: String }
#[derive(Debug, Deserialize)]
pub struct GetReq { pub address: String }
#[derive(Debug, Deserialize)]
pub struct DefineFunctionReq { pub address: String, pub name: String, pub size: u32 }

fn norm_key(s: &str) -> String {
    match parse_hex_key(s) {
        Some(n) => format!("0x{:x}", n),
        None => s.to_string(),
    }
}

#[tauri::command]
pub fn anno_set_label(store: tauri::State<'_, std::sync::Arc<AnnotationStore>>, req: SetLabelReq) -> AppResult<()> {
    let key = norm_key(&req.address);
    let mut i = store.inner.lock().unwrap();
    if req.name.trim().is_empty() { i.labels.remove(&key); }
    else { i.labels.insert(key, req.name.trim().to_string()); }
    Ok(())
}

#[tauri::command]
pub fn anno_get_label(store: tauri::State<'_, std::sync::Arc<AnnotationStore>>, address: String) -> AppResult<Option<String>> {
    let key = norm_key(&address);
    Ok(store.inner.lock().unwrap().labels.get(&key).cloned())
}

#[tauri::command]
pub fn anno_set_comment(store: tauri::State<'_, std::sync::Arc<AnnotationStore>>, req: SetLabelReq) -> AppResult<()> {
    let key = norm_key(&req.address);
    let mut i = store.inner.lock().unwrap();
    if req.name.trim().is_empty() { i.comments.remove(&key); }
    else { i.comments.insert(key, req.name.clone()); }
    Ok(())
}

#[tauri::command]
pub fn anno_get_comment(store: tauri::State<'_, std::sync::Arc<AnnotationStore>>, address: String) -> AppResult<Option<String>> {
    let key = norm_key(&address);
    Ok(store.inner.lock().unwrap().comments.get(&key).cloned())
}

#[tauri::command]
pub fn anno_define_function(store: tauri::State<'_, std::sync::Arc<AnnotationStore>>, req: DefineFunctionReq) -> AppResult<()> {
    let key = norm_key(&req.address);
    let mut i = store.inner.lock().unwrap();
    if req.size == 0 || req.name.trim().is_empty() { i.functions.remove(&key); }
    else { i.functions.insert(key, FunctionDef { name: req.name.trim().to_string(), size: req.size }); }
    Ok(())
}

#[tauri::command]
pub fn anno_get_function(store: tauri::State<'_, std::sync::Arc<AnnotationStore>>, address: String) -> AppResult<Option<FunctionDef>> {
    let key = norm_key(&address);
    Ok(store.inner.lock().unwrap().functions.get(&key).cloned())
}

#[tauri::command]
pub fn anno_snapshot(store: tauri::State<'_, std::sync::Arc<AnnotationStore>>) -> AppResult<Inner> {
    Ok(store.snapshot())
}

#[tauri::command]
pub fn anno_replace(store: tauri::State<'_, std::sync::Arc<AnnotationStore>>, data: Inner) -> AppResult<()> {
    store.replace(data);
    Ok(())
}

#[tauri::command]
pub fn anno_list_labels(store: tauri::State<'_, std::sync::Arc<AnnotationStore>>) -> AppResult<Vec<(String, String)>> {
    let i = store.inner.lock().unwrap();
    let mut v: Vec<_> = i.labels.iter().map(|(k, n)| (k.clone(), n.clone())).collect();
    v.sort();
    Ok(v)
}
