use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::engine::Features;

const STORAGE_DIR: &str = "/var/lib/open-fprintd/sil6250";
const MAX_ENROLLMENT_BYTES: u64 = 2 * 1024 * 1024;

fn checked_end(offset: usize, len: usize, total: usize) -> Option<usize> {
    offset.checked_add(len).filter(|&end| end <= total)
}

/// Ensure the storage root directory exists and is only accessible to root.
pub fn init_storage() -> io::Result<()> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(STORAGE_DIR)?;

    let mut perms = fs::metadata(STORAGE_DIR)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(STORAGE_DIR, perms)?;
    Ok(())
}

/// Reject any name that could escape the storage root when used as a path
/// component. Defense-in-depth: callers come in over D-Bus via open-fprintd,
/// but a `..`, `/`, empty, or NUL-bearing username/finger must never be turned
/// into a path that walks outside STORAGE_DIR.
fn check_component(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\0')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid path component: {name:?}"),
        ));
    }
    Ok(())
}

fn finger_path(username: &str, finger: &str) -> io::Result<PathBuf> {
    check_component(username)?;
    check_component(finger)?;
    Ok(Path::new(STORAGE_DIR)
        .join(username)
        .join(finger)
        .join("features.bin"))
}

/// Persist extracted feature sets to disk.
///
/// Each enrolled frame is stored as a length-prefixed serialized `Features`
/// blob so verification can load them directly without re-extracting from
/// raw sensor images.
pub fn save_features(username: &str, finger: &str, features: &[Features]) -> io::Result<()> {
    let path = finger_path(username, finger)?;
    let parent = path.parent().unwrap();
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp = parent.join(format!(".features.bin.{}.{}.tmp", std::process::id(), nonce));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        for feat in features {
            let bytes = feat.serialize();
            f.write_all(&(bytes.len() as u32).to_le_bytes())?;
            f.write_all(&bytes)?;
        }
        if f.metadata()?.len() > MAX_ENROLLMENT_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "enrollment file too large"));
        }
        f.sync_all()?;
        fs::rename(&tmp, &path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Load stored extracted feature sets. Returns an empty vec if nothing stored.
pub fn load_features(username: &str, finger: &str) -> io::Result<Vec<Features>> {
    let path = finger_path(username, finger)?;
    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e),
    };
    let metadata = f.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a regular feature file"));
    }
    if metadata.len() > MAX_ENROLLMENT_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "enrollment file too large"));
    }
    let mut buf = Vec::new();
    f.take(MAX_ENROLLMENT_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_ENROLLMENT_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "enrollment file too large"));
    }

    let mut features = Vec::new();
    let mut off = 0usize;
    while off < buf.len() {
        let prefix_end = checked_end(off, 4, buf.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated length"))?;
        let len = u32::from_le_bytes(buf[off..prefix_end].try_into().unwrap()) as usize;
        off = prefix_end;
        let record_end = checked_end(off, len, buf.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated features"))?;
        let feat = Features::deserialize(&buf[off..record_end]).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid feature data")
        })?;
        features.push(feat);
        off = record_end;
    }
    Ok(features)
}

/// List finger names with stored data for `username`.
pub fn list_enrolled(username: &str) -> Vec<String> {
    if check_component(username).is_err() {
        return vec![];
    }
    let user_dir = Path::new(STORAGE_DIR).join(username);
    let Ok(rd) = std::fs::read_dir(&user_dir) else {
        return vec![];
    };
    rd.filter_map(|entry| {
        let entry = entry.ok()?;
        let name = entry.file_name().into_string().ok()?;
        if !entry.file_type().ok()?.is_dir() {
            return None;
        }
        let metadata = fs::symlink_metadata(entry.path().join("features.bin")).ok()?;
        metadata.file_type().is_file().then_some(name)
    })
    .collect()
}

/// Delete all enrolled fingers for `username`.
pub fn delete_enrolled(username: &str) -> io::Result<()> {
    check_component(username)?;
    let user_dir = Path::new(STORAGE_DIR).join(username);
    if user_dir.exists() {
        std::fs::remove_dir_all(&user_dir)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_components_cannot_escape_storage() {
        for invalid in ["", ".", "..", "a/b", "a\0b"] {
            assert!(check_component(invalid).is_err());
        }
        assert!(check_component("right-index-finger").is_ok());
    }

    #[test]
    fn record_offsets_cannot_overflow() {
        assert_eq!(checked_end(4, 8, 12), Some(12));
        assert_eq!(checked_end(usize::MAX, 1, usize::MAX), None);
        assert_eq!(checked_end(8, 8, 12), None);
    }
}
