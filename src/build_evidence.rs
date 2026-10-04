//! Validates build-time Git evidence before it becomes provenance input.

use std::path::Path;
use std::process::Command;

/// Parse `git status --porcelain=v1` output into a trustworthy dirty state.
///
/// An empty, valid status is clean; any valid status record is dirty. Invalid
/// UTF-8 or malformed status output cannot establish either state.
pub fn parse_porcelain_status(bytes: &[u8]) -> Option<bool> {
    let text = std::str::from_utf8(bytes).ok()?;
    if text.is_empty() {
        return Some(false);
    }

    for line in text.lines() {
        let bytes = line.as_bytes();
        if bytes.len() <= 3 || bytes[2] != b' ' || !valid_status_pair(bytes[0], bytes[1]) {
            return None;
        }
    }

    Some(true)
}

/// Read full nonignored worktree status; command errors are unknown.
pub fn git_dirty_status(repo_root: &Path) -> Option<bool> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args([
            "status",
            "--porcelain=v1",
            "--untracked-files=normal",
            "--ignore-submodules=none",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_porcelain_status(&output.stdout)
}

/// Combine optional explicit build input without allowing it to claim clean.
pub fn resolve_dirty_status(status: Option<bool>, override_value: Option<&str>) -> Option<bool> {
    match status {
        Some(true) => Some(true),
        Some(false) if parse_override(override_value) == Some(true) => Some(true),
        Some(false) => Some(false),
        None => None,
    }
}

fn valid_status_pair(index: u8, worktree: u8) -> bool {
    if index == b'?' || worktree == b'?' {
        return index == b'?' && worktree == b'?';
    }
    if index == b'!' || worktree == b'!' {
        return index == b'!' && worktree == b'!';
    }
    let valid = |value| matches!(value, b' ' | b'M' | b'T' | b'A' | b'D' | b'R' | b'C' | b'U');
    valid(index) && valid(worktree) && (index != b' ' || worktree != b' ')
}

fn parse_override(value: Option<&str>) -> Option<bool> {
    match value?.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_porcelain_status, resolve_dirty_status};

    #[test]
    fn status_parser_distinguishes_clean_dirty_and_untrusted_output() {
        assert_eq!(parse_porcelain_status(b""), Some(false));
        assert_eq!(parse_porcelain_status(b" M tracked.rs\n"), Some(true));
        assert_eq!(parse_porcelain_status(b"?? new.rs\n"), Some(true));
        assert_eq!(parse_porcelain_status(b"\xff"), None);
        assert_eq!(parse_porcelain_status(b"??\n"), None);
        assert_eq!(parse_porcelain_status(b"?? \n"), None);
        assert_eq!(parse_porcelain_status(b"  clean.rs\n"), None);
        assert_eq!(parse_porcelain_status(b"?M invalid.rs\n"), None);
    }

    #[test]
    fn environment_cannot_override_dirty_or_failed_status_as_clean() {
        assert_eq!(resolve_dirty_status(Some(true), Some("false")), Some(true));
        assert_eq!(resolve_dirty_status(Some(false), Some("true")), Some(true));
        assert_eq!(
            resolve_dirty_status(Some(false), Some("false")),
            Some(false)
        );
        assert_eq!(
            resolve_dirty_status(Some(false), Some("unknown")),
            Some(false)
        );
        assert_eq!(resolve_dirty_status(None, Some("false")), None);
        assert_eq!(resolve_dirty_status(None, Some("true")), None);
    }
}
