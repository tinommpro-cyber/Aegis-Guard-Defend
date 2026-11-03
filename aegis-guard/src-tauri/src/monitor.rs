//! Live system stats and real-time file-system protection (user-space watcher; kernel minifilter is a later module).
use crate::{engine, quarantine::Vault};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Serialize;
use std::sync::Arc;
use tauri::{AppHandle, Emitter};

#[derive(Serialize)]
pub struct Stats { pub cpu: f32, pub ram_used: u64, pub ram_total: u64 }

pub fn sample(sys: &mut sysinfo::System) -> Stats {
    sys.refresh_cpu_usage(); sys.refresh_memory();
    Stats { cpu: sys.global_cpu_info().cpu_usage(), ram_used: sys.used_memory(), ram_total: sys.total_memory() }
}

/// Watch user-writable hot spots. Every created/modified file is scanned; malicious ones are vaulted at once.
pub fn start_watcher(app: AppHandle, vault: Arc<Vault>) -> Result<RecommendedWatcher, String> {
    let mut w = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        let Ok(ev) = res else { return };
        if !matches!(ev.kind, EventKind::Create(_) | EventKind::Modify(_)) { return; }
        for p in ev.paths.iter().filter(|p| p.is_file()) {
            if let Some(f) = engine::scan_file(p) {
                if f.score < engine::SUSPICIOUS { continue; }
                if f.score >= engine::MALICIOUS { let _ = vault.quarantine(&f); }
                let _ = app.emit("threat", &f);
            }
        }
    }).map_err(|e| e.to_string())?;
    for d in [dirs::download_dir(), dirs::desktop_dir(), dirs::document_dir(), Some(std::env::temp_dir())].into_iter().flatten() {
        let _ = w.watch(&d, RecursiveMode::Recursive);
    }
    Ok(w)
}
