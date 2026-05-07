use std::fs;
use std::path::Path;

pub const DEFAULT_LOG_ROTATE_BYTES: u64 = 10 * 1024 * 1024;
pub const DEFAULT_LOG_ROTATE_KEEP: u32 = 3;
pub const DEFAULT_STOP_TIMEOUT_SECS: u64 = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorConfig {
    pub log_rotate_bytes: u64,
    pub log_rotate_keep: u32,
    pub stop_timeout_secs: u64,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            log_rotate_bytes: DEFAULT_LOG_ROTATE_BYTES,
            log_rotate_keep: DEFAULT_LOG_ROTATE_KEEP,
            stop_timeout_secs: DEFAULT_STOP_TIMEOUT_SECS,
        }
    }
}

impl SupervisorConfig {
    /// Load from a flat-keys YAML file. Missing file yields defaults.
    /// Syntax errors and bad values are fatal (refuse to start).
    /// Unknown keys produce a warning to stderr but do not fail.
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = fs::read_to_string(path)
            .map_err(|e| format!("error reading {}: {e}", path.display()))?;
        Self::parse_with_warnings(&data, path)
    }

    fn parse_with_warnings(data: &str, source: &Path) -> Result<Self, String> {
        let data = data.strip_prefix('\u{FEFF}').unwrap_or(data);
        let mut cfg = Self::default();
        for (idx, raw) in data.lines().enumerate() {
            let line_num = idx + 1;
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, val)) = line.split_once(':') else {
                return Err(format!(
                    "{}:{line_num}: expected 'key: value', got: {raw}",
                    source.display()
                ));
            };
            let key = key.trim();
            let val = val.trim();
            match key {
                "log_rotate_bytes" => {
                    cfg.log_rotate_bytes = val.parse().map_err(|_| {
                        format!(
                            "{}:{line_num}: invalid log_rotate_bytes: {val}",
                            source.display()
                        )
                    })?;
                }
                "log_rotate_keep" => {
                    cfg.log_rotate_keep = val.parse().map_err(|_| {
                        format!(
                            "{}:{line_num}: invalid log_rotate_keep: {val}",
                            source.display()
                        )
                    })?;
                }
                "stop_timeout_secs" => {
                    cfg.stop_timeout_secs = val.parse().map_err(|_| {
                        format!(
                            "{}:{line_num}: invalid stop_timeout_secs: {val}",
                            source.display()
                        )
                    })?;
                }
                _ => {
                    eprintln!(
                        "warning: {}:{line_num}: unknown key '{key}' (ignored)",
                        source.display()
                    );
                }
            }
        }
        Ok(cfg)
    }
}

fn strip_comment(line: &str) -> &str {
    line.split_once('#').map(|(head, _)| head).unwrap_or(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fake_path() -> PathBuf {
        PathBuf::from("/tmp/supervisor.yaml")
    }

    #[test]
    fn defaults_when_no_overrides() {
        let cfg = SupervisorConfig::parse_with_warnings("", &fake_path()).unwrap();
        assert_eq!(cfg, SupervisorConfig::default());
    }

    #[test]
    fn parses_all_three_keys() {
        let yaml = "
log_rotate_bytes: 5242880
log_rotate_keep: 5
stop_timeout_secs: 30
";
        let cfg = SupervisorConfig::parse_with_warnings(yaml, &fake_path()).unwrap();
        assert_eq!(cfg.log_rotate_bytes, 5_242_880);
        assert_eq!(cfg.log_rotate_keep, 5);
        assert_eq!(cfg.stop_timeout_secs, 30);
    }

    #[test]
    fn skips_blank_lines_and_comments() {
        let yaml = "
# top comment
log_rotate_bytes: 1024  # inline comment

# blank line above
log_rotate_keep: 7
";
        let cfg = SupervisorConfig::parse_with_warnings(yaml, &fake_path()).unwrap();
        assert_eq!(cfg.log_rotate_bytes, 1024);
        assert_eq!(cfg.log_rotate_keep, 7);
        assert_eq!(cfg.stop_timeout_secs, DEFAULT_STOP_TIMEOUT_SECS);
    }

    #[test]
    fn unknown_key_warns_but_continues() {
        let yaml = "
unknown_thing: 42
log_rotate_bytes: 9999
";
        let cfg = SupervisorConfig::parse_with_warnings(yaml, &fake_path()).unwrap();
        assert_eq!(cfg.log_rotate_bytes, 9999);
    }

    #[test]
    fn invalid_number_is_fatal() {
        let yaml = "log_rotate_bytes: not-a-number\n";
        let err = SupervisorConfig::parse_with_warnings(yaml, &fake_path()).unwrap_err();
        assert!(err.contains("invalid log_rotate_bytes"), "got: {err}");
    }

    #[test]
    fn missing_colon_is_fatal() {
        let yaml = "log_rotate_bytes 42\n";
        let err = SupervisorConfig::parse_with_warnings(yaml, &fake_path()).unwrap_err();
        assert!(err.contains("expected 'key: value'"), "got: {err}");
    }

    #[test]
    fn missing_file_yields_defaults() {
        let path = PathBuf::from("/nonexistent/supervisor.yaml");
        let cfg = SupervisorConfig::load(&path).unwrap();
        assert_eq!(cfg, SupervisorConfig::default());
    }

    #[test]
    fn tolerates_utf8_bom() {
        let yaml = "\u{FEFF}log_rotate_bytes: 4096\n";
        let cfg = SupervisorConfig::parse_with_warnings(yaml, &fake_path()).unwrap();
        assert_eq!(cfg.log_rotate_bytes, 4096);
    }
}
