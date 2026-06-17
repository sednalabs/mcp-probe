#[path = "../build_support.rs"]
mod build_support;

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "mcp-probe-build-support-{label}-{}-{nanos}",
        std::process::id()
    ))
}

fn write_file(path: &PathBuf, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent");
    }
    fs::write(path, contents).expect("write file");
}

#[test]
fn collect_git_watch_paths_tracks_ref_and_index_inputs() {
    let repo_root = unique_temp_dir("direct-gitdir");
    let git_dir = repo_root.join(".git");
    write_file(&git_dir.join("HEAD"), "ref: refs/heads/main\n");
    write_file(&git_dir.join("packed-refs"), "");
    write_file(&git_dir.join("index"), "");
    write_file(&git_dir.join("logs/HEAD"), "");
    write_file(&git_dir.join("refs/heads/main"), "abc123\n");
    write_file(&git_dir.join("logs/refs/heads/main"), "");

    let mut actual = build_support::collect_git_watch_paths(&repo_root)
        .into_iter()
        .map(|path| path.strip_prefix(&repo_root).unwrap().to_path_buf())
        .collect::<Vec<_>>();
    actual.sort();

    let mut expected = vec![
        PathBuf::from(".git/HEAD"),
        PathBuf::from(".git/index"),
        PathBuf::from(".git/logs/HEAD"),
        PathBuf::from(".git/logs/refs/heads/main"),
        PathBuf::from(".git/packed-refs"),
        PathBuf::from(".git/refs/heads/main"),
    ];
    expected.sort();

    assert_eq!(actual, expected);
    fs::remove_dir_all(repo_root).expect("cleanup temp repo");
}

#[test]
fn collect_git_watch_paths_resolves_gitdir_files() {
    let repo_root = unique_temp_dir("gitdir-file");
    let actual_git_dir = repo_root.join("git-storage");
    write_file(&repo_root.join(".git"), "gitdir: git-storage\n");
    write_file(&actual_git_dir.join("HEAD"), "ref: refs/heads/work\n");
    write_file(&actual_git_dir.join("packed-refs"), "");
    write_file(&actual_git_dir.join("index"), "");
    write_file(&actual_git_dir.join("logs/HEAD"), "");
    write_file(&actual_git_dir.join("refs/heads/work"), "def456\n");
    write_file(&actual_git_dir.join("logs/refs/heads/work"), "");

    let mut actual = build_support::collect_git_watch_paths(&repo_root)
        .into_iter()
        .map(|path| path.strip_prefix(&repo_root).unwrap().to_path_buf())
        .collect::<Vec<_>>();
    actual.sort();

    let mut expected = vec![
        PathBuf::from("git-storage/HEAD"),
        PathBuf::from("git-storage/index"),
        PathBuf::from("git-storage/logs/HEAD"),
        PathBuf::from("git-storage/logs/refs/heads/work"),
        PathBuf::from("git-storage/packed-refs"),
        PathBuf::from("git-storage/refs/heads/work"),
    ];
    expected.sort();

    assert_eq!(actual, expected);
    fs::remove_dir_all(repo_root).expect("cleanup temp repo");
}
