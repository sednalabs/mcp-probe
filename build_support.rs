use std::fs;
use std::path::{Path, PathBuf};

/// Collect the git files whose changes should force build provenance refresh.
pub fn collect_git_watch_paths(repo_root: &Path) -> Vec<PathBuf> {
    let Some(git_dir) = resolve_git_dir(repo_root) else {
        return Vec::new();
    };

    let mut paths = vec![
        git_dir.join("HEAD"),
        git_dir.join("packed-refs"),
        git_dir.join("index"),
        git_dir.join("logs").join("HEAD"),
    ];

    if let Some(reference) = read_head_reference(&git_dir) {
        paths.push(git_dir.join(&reference));
        paths.push(git_dir.join("logs").join(reference));
    }

    paths
}

fn resolve_git_dir(repo_root: &Path) -> Option<PathBuf> {
    let dot_git = repo_root.join(".git");
    if dot_git.is_dir() {
        return Some(dot_git);
    }

    let text = fs::read_to_string(dot_git).ok()?;
    let prefix = "gitdir:";
    let gitdir = text.trim().strip_prefix(prefix)?.trim();
    let path = PathBuf::from(gitdir);
    if path.is_absolute() {
        Some(path)
    } else {
        Some(repo_root.join(path))
    }
}

fn read_head_reference(git_dir: &Path) -> Option<String> {
    let head = fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let prefix = "ref:";
    let reference = head.trim().strip_prefix(prefix)?.trim();
    if reference.is_empty() {
        None
    } else {
        Some(reference.to_string())
    }
}
