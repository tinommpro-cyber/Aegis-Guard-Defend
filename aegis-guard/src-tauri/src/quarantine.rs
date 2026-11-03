//! Quarantine vault: AES-256-GCM encrypted blobs + JSON index. Restore and overwrite-delete supported.
use crate::engine::Finding;
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::{Path, PathBuf}, sync::Mutex, time::{SystemTime, UNIX_EPOCH}};

#[derive(Serialize, Deserialize, Clone)]
pub struct Entry {
    pub id: String, pub orig_path: String, pub sha256: String,
    pub score: u32, pub reasons: Vec<String>, pub time: u64,
}

pub struct Vault { dir: PathBuf, key: [u8; 32], index: Mutex<Vec<Entry>> }

impl Vault {
    pub fn open(dir: PathBuf) -> Result<Self, String> {
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let kp = dir.join(".key");
        // NOTE: key sits beside the vault; wrap with DPAPI/Keychain in the tamper-protection module.
        let key: [u8; 32] = match fs::read(&kp) {
            Ok(k) if k.len() == 32 => k.try_into().unwrap(),
            _ => { let k: [u8; 32] = rand::random(); fs::write(&kp, k).map_err(|e| e.to_string())?; k }
        };
        let index = fs::read(dir.join("index.json")).ok()
            .and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        Ok(Self { dir, key, index: Mutex::new(index) })
    }
    fn save(&self, idx: &[Entry]) -> Result<(), String> {
        fs::write(self.dir.join("index.json"), serde_json::to_vec_pretty(idx).unwrap()).map_err(|e| e.to_string())
    }
    fn cipher(&self) -> Aes256Gcm { Aes256Gcm::new_from_slice(&self.key).unwrap() }

    /// Encrypt the file into the vault, then remove the original.
    pub fn quarantine(&self, f: &Finding) -> Result<Entry, String> {
        let data = fs::read(&f.path).map_err(|e| e.to_string())?;
        let nonce: [u8; 12] = rand::random();
        let mut blob = nonce.to_vec();
        blob.extend(self.cipher().encrypt(Nonce::from_slice(&nonce), data.as_ref()).map_err(|e| e.to_string())?);
        let id = hex::encode(rand::random::<[u8; 8]>());
        fs::write(self.dir.join(format!("{id}.aegis")), blob).map_err(|e| e.to_string())?;
        fs::remove_file(&f.path).map_err(|e| e.to_string())?;
        let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let e = Entry { id, orig_path: f.path.clone(), sha256: f.sha256.clone(), score: f.score, reasons: f.reasons.clone(), time };
        let mut idx = self.index.lock().unwrap();
        idx.push(e.clone());
        self.save(&idx)?;
        Ok(e)
    }
    pub fn list(&self) -> Vec<Entry> { self.index.lock().unwrap().clone() }

    /// Decrypt and write back to the original path (false-positive recovery).
    pub fn restore(&self, id: &str) -> Result<(), String> {
        let mut idx = self.index.lock().unwrap();
        let pos = idx.iter().position(|e| e.id == id).ok_or("unknown id")?;
        let blob = fs::read(self.dir.join(format!("{id}.aegis"))).map_err(|e| e.to_string())?;
        let plain = self.cipher().decrypt(Nonce::from_slice(&blob[..12]), &blob[12..]).map_err(|_| "decrypt failed (tampered?)")?;
        let target = Path::new(&idx[pos].orig_path);
        if let Some(p) = target.parent() { let _ = fs::create_dir_all(p); }
        fs::write(target, plain).map_err(|e| e.to_string())?;
        fs::remove_file(self.dir.join(format!("{id}.aegis"))).ok();
        idx.remove(pos);
        self.save(&idx)
    }
    /// Overwrite the blob with random data, then delete it.
    pub fn delete(&self, id: &str) -> Result<(), String> {
        let mut idx = self.index.lock().unwrap();
        let pos = idx.iter().position(|e| e.id == id).ok_or("unknown id")?;
        let p = self.dir.join(format!("{id}.aegis"));
        if let Ok(len) = fs::metadata(&p).map(|m| m.len() as usize) {
            if let Ok(mut f) = fs::OpenOptions::new().write(true).open(&p) {
                let junk: Vec<u8> = (0..len).map(|_| rand::random()).collect();
                let _ = f.write_all(&junk); let _ = f.sync_all();
            }
        }
        fs::remove_file(&p).ok();
        idx.remove(pos);
        self.save(&idx)
    }
}
