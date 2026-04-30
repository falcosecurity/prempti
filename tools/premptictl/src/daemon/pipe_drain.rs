use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use super::rotate;

/// Drain a child's pipe (stdout or stderr) into a log file, rotating when the
/// file crosses the configured size cap. Lines are appended in order; the
/// caller's writer is reopened after each rotation.
///
/// Returns when the pipe reaches EOF (i.e., the child closed it). Any
/// I/O error on the source pipe propagates; errors writing to the log file
/// are swallowed after a single stderr report so a transient log-disk
/// problem doesn't crash the supervisor.
pub fn drain<R: Read>(
    source: R,
    log_path: PathBuf,
    max_bytes: u64,
    keep: u32,
    rotated: Arc<AtomicU32>,
) -> io::Result<()> {
    let mut writer = open_append(&log_path)?;
    let mut reader = BufReader::new(source);
    let mut line = String::new();
    let mut warned_write_error = false;

    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            // EOF: child closed the pipe. Flush whatever we have.
            let _ = writer.flush();
            break;
        }

        // Rotate before write if the existing file is at or above the cap.
        // Lazy rotation: the oversize line lands in the new file, not the old.
        match rotate::rotate_if_needed(&log_path, max_bytes, keep) {
            Ok(true) => {
                rotated.fetch_add(1, Ordering::Relaxed);
                writer = match open_append(&log_path) {
                    Ok(w) => w,
                    Err(e) => {
                        if !warned_write_error {
                            eprintln!(
                                "supervisor: failed to reopen log {} after rotation: {e}",
                                log_path.display()
                            );
                            warned_write_error = true;
                        }
                        continue;
                    }
                };
            }
            Ok(false) => {}
            Err(e) => {
                if !warned_write_error {
                    eprintln!(
                        "supervisor: rotation check failed for {}: {e}",
                        log_path.display()
                    );
                    warned_write_error = true;
                }
            }
        }

        if let Err(e) = writer.write_all(line.as_bytes()) {
            if !warned_write_error {
                eprintln!("supervisor: failed to write to {}: {e}", log_path.display());
                warned_write_error = true;
            }
        }
    }
    Ok(())
}

fn open_append(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    OpenOptions::new().create(true).append(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn tmp(label: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "prempti-drain-{}-{label}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn writes_lines_to_log() {
        let dir = tmp("simple");
        let log = dir.join("falco.log");
        let input = "line one\nline two\nline three\n";
        let rotated = Arc::new(AtomicU32::new(0));
        drain(
            Cursor::new(input),
            log.clone(),
            1024 * 1024,
            3,
            rotated.clone(),
        )
        .unwrap();
        assert_eq!(std::fs::read_to_string(&log).unwrap(), input);
        assert_eq!(rotated.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rotates_when_existing_file_over_cap() {
        let dir = tmp("rot");
        let log = dir.join("falco.log");
        // Pre-populate over the cap.
        std::fs::write(&log, vec![b'X'; 200]).unwrap();
        let input = "after rotation\n";
        let rotated = Arc::new(AtomicU32::new(0));
        drain(Cursor::new(input), log.clone(), 100, 3, rotated.clone()).unwrap();
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "after rotation\n");
        assert_eq!(rotated.load(Ordering::Relaxed), 1);
        let archive = std::fs::read(dir.join("falco.log.1")).unwrap();
        assert_eq!(archive.len(), 200);
    }

    #[test]
    fn flushes_at_eof_with_partial_line() {
        // No trailing newline: read_line still returns the buffered bytes.
        let dir = tmp("partial");
        let log = dir.join("falco.log");
        let rotated = Arc::new(AtomicU32::new(0));
        drain(Cursor::new("no-newline"), log.clone(), 1024, 3, rotated).unwrap();
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "no-newline");
    }

    #[test]
    fn appends_to_existing_under_cap() {
        let dir = tmp("append");
        let log = dir.join("falco.log");
        std::fs::write(&log, "old\n").unwrap();
        let rotated = Arc::new(AtomicU32::new(0));
        drain(Cursor::new("new\n"), log.clone(), 1024, 3, rotated).unwrap();
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "old\nnew\n");
    }
}
