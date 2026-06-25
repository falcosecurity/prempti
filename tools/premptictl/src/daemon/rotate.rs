use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Rotate a log file using the same scheme Windows used to do in PowerShell:
///
/// ```text
///   .{keep} → drop
///   .{keep-1} → .{keep}
///   ...
///   .1 → .2
///   <path> → .1
/// ```
///
/// Only rotates if the current file is at or above `max_bytes`. Caller opens
/// a fresh writer at `path` afterwards. Idempotent for missing files.
pub fn rotate_if_needed(path: &Path, max_bytes: u64, keep: u32) -> io::Result<bool> {
    let size = match fs::metadata(path) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if size < max_bytes {
        return Ok(false);
    }
    rotate_now(path, keep)?;
    Ok(true)
}

fn archive_path(path: &Path, n: u32) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

fn rotate_now(path: &Path, keep: u32) -> io::Result<()> {
    if keep == 0 {
        // No archives kept — just truncate.
        let _ = fs::remove_file(path);
        return Ok(());
    }
    // Drop the oldest archive (.{keep}) if present.
    let oldest = archive_path(path, keep);
    if oldest.exists() {
        fs::remove_file(&oldest)?;
    }
    // Shift .{keep-1} → .{keep}, .{keep-2} → .{keep-1}, ... down to .1 → .2.
    for n in (1..keep).rev() {
        let src = archive_path(path, n);
        let dst = archive_path(path, n + 1);
        if src.exists() {
            fs::rename(&src, &dst)?;
        }
    }
    // path → .1
    fs::rename(path, archive_path(path, 1))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    fn tmpdir(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("prempti-rotate-{}-{}", std::process::id(), label));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(path: &Path, bytes: &[u8]) {
        let mut f = File::create(path).unwrap();
        f.write_all(bytes).unwrap();
    }

    fn read(path: &Path) -> Option<Vec<u8>> {
        fs::read(path).ok()
    }

    #[test]
    fn no_rotation_when_under_threshold() {
        let dir = tmpdir("under");
        let log = dir.join("falco.log");
        write(&log, b"hello");
        let did = rotate_if_needed(&log, 100, 3).unwrap();
        assert!(!did);
        assert_eq!(read(&log).unwrap(), b"hello");
    }

    #[test]
    fn no_rotation_when_missing() {
        let dir = tmpdir("missing");
        let log = dir.join("falco.log");
        let did = rotate_if_needed(&log, 100, 3).unwrap();
        assert!(!did);
    }

    #[test]
    fn rotates_at_threshold() {
        let dir = tmpdir("hit");
        let log = dir.join("falco.log");
        write(&log, &vec![b'x'; 100]);
        let did = rotate_if_needed(&log, 100, 3).unwrap();
        assert!(did);
        assert!(!log.exists(), "current log should be moved away");
        assert_eq!(read(&dir.join("falco.log.1")).unwrap().len(), 100);
    }

    #[test]
    fn shifts_existing_archives_down() {
        let dir = tmpdir("shift");
        let log = dir.join("falco.log");
        write(&log, &vec![b'D'; 50]);
        write(&dir.join("falco.log.1"), b"older1");
        write(&dir.join("falco.log.2"), b"older2");
        rotate_if_needed(&log, 50, 3).unwrap();
        assert_eq!(read(&dir.join("falco.log.1")).unwrap().len(), 50);
        assert_eq!(read(&dir.join("falco.log.2")).unwrap(), b"older1");
        assert_eq!(read(&dir.join("falco.log.3")).unwrap(), b"older2");
    }

    #[test]
    fn drops_oldest_archive_past_keep() {
        let dir = tmpdir("drop");
        let log = dir.join("falco.log");
        write(&log, &vec![b'D'; 50]);
        write(&dir.join("falco.log.1"), b"a");
        write(&dir.join("falco.log.2"), b"b");
        write(&dir.join("falco.log.3"), b"c"); // would-be-dropped
        rotate_if_needed(&log, 50, 3).unwrap();
        assert!(read(&dir.join("falco.log.4")).is_none());
        // .3 used to hold "c"; after rotate, .3 holds the previous "b".
        assert_eq!(read(&dir.join("falco.log.3")).unwrap(), b"b");
    }

    #[test]
    fn keep_zero_truncates() {
        let dir = tmpdir("zero");
        let log = dir.join("falco.log");
        write(&log, &vec![b'x'; 100]);
        rotate_if_needed(&log, 100, 0).unwrap();
        assert!(!log.exists());
        assert!(!dir.join("falco.log.1").exists());
    }
}
