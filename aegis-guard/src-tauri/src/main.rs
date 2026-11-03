#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod engine; mod monitor; mod quarantine;
use quarantine::{Entry, Vault};
use serde::Serialize;
use std::{path::PathBuf, sync::{Arc, Mutex}, time::Instant};
use tauri::{AppHandle, Manager, State};

struct AppState { vault: Arc<Vault>, sys: Mutex<sysinfo::System>, watcher: Mutex<Option<notify::RecommendedWatcher>> }

#[derive(Serialize)]
struct Report { scanned: usize, ms: u128, findings: Vec<engine::Finding> }

#[tauri::command]
async fn scan(path: String, auto_quarantine: bool, st: State<'_, AppState>) -> Result<Report, String> {
    let vault = st.vault.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let t = Instant::now();
        let (scanned, findings) = engine::scan_tree(&PathBuf::from(path));
        if auto_quarantine {
            for f in findings.iter().filter(|f| f.score >= engine::MALICIOUS) { let _ = vault.quarantine(f); }
        }
        Report { scanned, ms: t.elapsed().as_millis(), findings }
    }).await.map_err(|e| e.to_string())
}
#[tauri::command] fn system_stats(st: State<AppState>) -> monitor::Stats { monitor::sample(&mut st.sys.lock().unwrap()) }
#[tauri::command] fn list_quarantine(st: State<AppState>) -> Vec<Entry> { st.vault.list() }
#[tauri::command] fn restore(id: String, st: State<AppState>) -> Result<(), String> { st.vault.restore(&id) }
#[tauri::command] fn delete_item(id: String, st: State<AppState>) -> Result<(), String> { st.vault.delete(&id) }
#[tauri::command]
fn set_realtime(enabled: bool, app: AppHandle, st: State<AppState>) -> Result<bool, String> {
    let mut w = st.watcher.lock().unwrap();
    *w = if enabled { Some(monitor::start_watcher(app, st.vault.clone())?) } else { None };
    Ok(enabled)
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let vault = Arc::new(Vault::open(app.path().app_data_dir()?.join("vault"))?);
            app.manage(AppState { vault, sys: Mutex::new(sysinfo::System::new()), watcher: Mutex::new(None) });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![scan, system_stats, list_quarantine, restore, delete_item, set_realtime])
        .run(tauri::generate_context!())
        .expect("failed to run Aegis Guard");
}
