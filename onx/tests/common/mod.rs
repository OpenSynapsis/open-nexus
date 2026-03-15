use fs4::FileExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct TestMetadata {
    pub packet_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct PcapFileManifest {
    pub filename: String,
    pub url: String,
    pub sha256: String,
    pub metadata: TestMetadata,
}

pub fn load_manifest() -> Result<Vec<PcapFileManifest>, io::Error> {
    let manifest_path = PathBuf::from("../tests/data/manifest.json");
    let content = fs::read_to_string(manifest_path)?;
    serde_json::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn ensure_test_file(manifest: &PcapFileManifest) -> Result<PathBuf, io::Error> {
    let data_dir = PathBuf::from("../tests/data");
    fs::create_dir_all(&data_dir)?;

    let target_path = data_dir.join(&manifest.filename);
    let lock_path = target_path.with_extension("lock");
    let lock_file = File::create(&lock_path)?;

    lock_file.lock_exclusive()?;

    let result = (|| -> Result<PathBuf, io::Error> {
        if target_path.exists() {
            if verify_sha256(&target_path, &manifest.sha256) {
                return Ok(target_path);
            } else {
                eprintln!(
                    "Existing file {} has invalid hash. Re-downloading...",
                    manifest.filename
                );
                fs::remove_file(&target_path)?;
            }
        }

        eprintln!("Downloading test file: {}", manifest.filename);
        let response = ureq::get(&manifest.url)
            .call()
            .map_err(|e| io::Error::other(format!("Download failed: {}", e)))?;

        let mut reader = response.into_reader();
        let temp_path = target_path.with_extension("tmp");
        let mut temp_file = File::create(&temp_path)?;
        io::copy(&mut reader, &mut temp_file)?;

        if !verify_sha256(&temp_path, &manifest.sha256) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Downloaded file {} failed SHA256 verification",
                    manifest.filename,
                ),
            ));
        }

        fs::rename(&temp_path, &target_path)?;
        Ok(target_path)
    })();

    lock_file.unlock()?;
    result
}

fn verify_sha256(path: &Path, expected_hash: &str) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut hasher = Sha256::new();
    if io::copy(&mut file, &mut hasher).is_err() {
        return false;
    }
    let hash_result = hasher.finalize();
    let hex_hash = format!("{:x}", hash_result);
    hex_hash == expected_hash
}
