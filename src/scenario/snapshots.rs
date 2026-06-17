//! Snapshot persistence for scripted scenarios.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

/// Snapshot file stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct SnapshotFile {
    pub version: u32,
    pub snapshots: BTreeMap<String, Value>,
}

/// Load snapshots from disk, defaulting to an empty set.
pub async fn load_snapshots(path: &Path) -> SnapshotFile {
    match tokio::fs::read_to_string(path).await {
        Ok(raw) => {
            let parsed: SnapshotFile = serde_json::from_str(&raw).unwrap_or(SnapshotFile {
                version: 1,
                snapshots: BTreeMap::new(),
            });
            SnapshotFile {
                version: parsed.version,
                snapshots: parsed.snapshots,
            }
        }
        Err(_) => SnapshotFile {
            version: 1,
            snapshots: BTreeMap::new(),
        },
    }
}

/// Persist snapshots to disk in deterministic order.
pub async fn save_snapshots(path: &Path, snapshots: &SnapshotFile) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let payload = serde_json::to_string_pretty(snapshots)?;
    let output = format!("{payload}\n");
    tokio::fs::write(path, output).await?;
    Ok(())
}
