//! Detection engine: hash blocklist + weighted byte-pattern rules + entropy/PE/filename heuristics.
use memchr::memmem;
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::{Path, PathBuf}};
use walkdir::WalkDir;

const MAX_READ: u64 = 64 * 1024 * 1024;
pub const MALICIOUS: u32 = 70;
pub const SUSPICIOUS: u32 = 40;

const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
/// SHA-256 blocklist (extended later by the threat-intel sync module).
const BAD_HASHES: &[(&str, &str)] =
    &[("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR test file")];
/// (pattern, weight, description)
const RULES: &[(&[u8], u32, &str)] = &[
    (b"VirtualAllocEx", 15, "remote memory allocation API"),
    (b"WriteProcessMemory", 20, "writes into other process memory"),
    (b"CreateRemoteThread", 20, "remote thread injection API"),
    (b"NtUnmapViewOfSection", 20, "process hollowing API"),
    (b"powershell -enc", 25, "encoded PowerShell command"),
    (b"mimikatz", 50, "credential dumper string"),
    (b"vssadmin delete shadows", 40, "shadow copy deletion (ransomware behaviour)"),
    (b"Your files have been encrypted", 40, "ransom note text"),
    (b"IsDebuggerPresent", 5, "anti-debug check"),
];
const RISKY_EXT: &[&str] = &["exe", "scr", "pif", "com", "bat", "cmd", "vbs", "js", "ps1", "jar"];
const DECOY_EXT: &[&str] = &["pdf", "doc", "docx", "jpg", "png", "txt", "xls", "xlsx"];

#[derive(Serialize, Clone, Debug)]
pub struct Finding {
    pub path: String,
    pub sha256: String,
    pub score: u32,
    pub verdict: &'static str,
    pub reasons: Vec<String>,
}

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut c = [0u64; 256];
    for &b in data { c[b as usize] += 1; }
    let n = data.len() as f64;
    c.iter().filter(|&&x| x > 0).map(|&x| { let p = x as f64 / n; -p * p.log2() }).sum()
}

/// Scan one file. Returns None if it cannot be read (locked, permission, directory).
pub fn scan_file(path: &Path) -> Option<Finding> {
    let mut data = Vec::new();
    File::open(path).ok()?.take(MAX_READ).read_to_end(&mut data).ok()?;
    let sha256 = hex::encode(Sha256::digest(&data));
    let mut score = 0u32;
    let mut reasons = Vec::new();

    if let Some((_, name)) = BAD_HASHES.iter().find(|(h, _)| *h == sha256) {
        score += 100; reasons.push(format!("known-bad hash: {name}"));
    }
    if memmem::find(&data, EICAR).is_some() {
        score += 100; reasons.push("EICAR test signature".into());
    }
    for (pat, w, desc) in RULES {
        if memmem::find(&data, pat).is_some() { score += w; reasons.push((*desc).to_string()); }
    }
    if data.starts_with(b"MZ") && entropy(&data) > 7.2 {
        score += 25; reasons.push("high-entropy PE (likely packed)".into());
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() >= 3 && DECOY_EXT.contains(&parts[parts.len() - 2]) && RISKY_EXT.contains(&parts[parts.len() - 1]) {
        score += 30; reasons.push("double extension disguise".into());
    } else if RISKY_EXT.contains(&parts[parts.len() - 1]) && !reasons.is_empty() {
        score += 5;
    }
    let score = score.min(100);
    let verdict = if score >= MALICIOUS { "malicious" } else if score >= SUSPICIOUS { "suspicious" } else { "clean" };
    Some(Finding { path: path.display().to_string(), sha256, score, verdict, reasons })
}

/// Scan a file or whole directory tree in parallel. Returns (files scanned, non-clean findings).
pub fn scan_tree(root: &Path) -> (usize, Vec<Finding>) {
    let files: Vec<PathBuf> = WalkDir::new(root).into_iter().filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file()).map(|e| e.into_path()).collect();
    let findings = files.par_iter().filter_map(|p| scan_file(p)).filter(|f| f.score >= SUSPICIOUS).collect();
    (files.len(), findings)
}
