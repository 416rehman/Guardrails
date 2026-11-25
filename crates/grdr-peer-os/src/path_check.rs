// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::PeerError;

const MODE_OTHER_WRITE: u32 = 0o002;
const MODE_GROUP_WRITE: u32 = 0o020;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathNodeKind {
    Root,
    Ancestor(u16),
    Socket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathEntryType {
    Directory,
    Socket,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathWalkNode {
    pub kind: PathNodeKind,
    pub entry_type: PathEntryType,
    pub owner_uid: u32,
    pub group_gid: u32,
    pub posix_mode: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PathCheckOutcome {
    Safe,
    NoPath,
    Foreign { node: PathNodeKind, owner_uid: u32 },
    Unsafe { node: PathNodeKind, reason: String },
}

pub fn verify_unix_path_nodes(
    nodes: &[PathWalkNode],
    expected_uid: u32,
    caller_primary_gid: Option<u32>,
    trusted_groups: &[u32],
) -> PathCheckOutcome {
    let Some(first) = nodes.first() else {
        return PathCheckOutcome::Unsafe {
            node: PathNodeKind::Root,
            reason: "empty path walk".into(),
        };
    };
    if first.kind != PathNodeKind::Root {
        return PathCheckOutcome::Unsafe {
            node: PathNodeKind::Root,
            reason: "path walk must start at /".into(),
        };
    }
    if nodes.last().is_none_or(|n| n.kind != PathNodeKind::Socket) {
        return PathCheckOutcome::Unsafe {
            node: PathNodeKind::Root,
            reason: "endpoint path walk missing trailing socket leaf".into(),
        };
    }

    for (idx, node) in nodes.iter().enumerate() {
        if node.entry_type == PathEntryType::Symlink {
            return PathCheckOutcome::Unsafe {
                node: node.kind,
                reason: "symbolic link in endpoint hierarchy".into(),
            };
        }
        // RFC 0003: socket mode is unchecked because connect(2) on Protected sockets may use 0666.
        if node.kind == PathNodeKind::Socket {
            if idx.saturating_add(1) != nodes.len() {
                return PathCheckOutcome::Unsafe {
                    node: node.kind,
                    reason: "socket node must be final leaf".into(),
                };
            }
            if node.entry_type != PathEntryType::Socket {
                return PathCheckOutcome::Unsafe {
                    node: node.kind,
                    reason: "endpoint leaf must be a Unix domain socket".into(),
                };
            }
            if node.owner_uid != 0 && node.owner_uid != expected_uid {
                return PathCheckOutcome::Foreign {
                    node: node.kind,
                    owner_uid: node.owner_uid,
                };
            }
            continue;
        }
        if node.entry_type != PathEntryType::Directory {
            return PathCheckOutcome::Unsafe {
                node: node.kind,
                reason: "ancestor is not a directory".into(),
            };
        }
        if node.owner_uid != 0 && node.owner_uid != expected_uid {
            return PathCheckOutcome::Foreign {
                node: node.kind,
                owner_uid: node.owner_uid,
            };
        }
        if (node.posix_mode & MODE_OTHER_WRITE) != 0 {
            return PathCheckOutcome::Unsafe {
                node: node.kind,
                reason: "directory is world-writable".into(),
            };
        }
        if (node.posix_mode & MODE_GROUP_WRITE) != 0 {
            let allowed_group = trusted_groups.contains(&node.group_gid)
                || caller_primary_gid == Some(node.group_gid);
            if !allowed_group {
                return PathCheckOutcome::Unsafe {
                    node: node.kind,
                    reason: "directory is writable by untrusted group".into(),
                };
            }
        }
    }
    PathCheckOutcome::Safe
}

#[cfg(unix)]
pub fn inspect_filesystem_ancestors(socket_path: &Path) -> Result<Vec<PathWalkNode>, PeerError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    if !socket_path.is_absolute() {
        return Err(PeerError::PathUnsafe(
            "endpoint path must be absolute".into(),
        ));
    }
    if socket_path
        .components()
        .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return Err(PeerError::PathUnsafe(
            "endpoint path must not contain relative `.` or `..` segments".into(),
        ));
    }
    let mut ancestors: Vec<&Path> = socket_path.ancestors().collect();
    ancestors.reverse();

    let total = ancestors.len();
    let mut nodes = Vec::with_capacity(total);
    for (idx, path) in ancestors.into_iter().enumerate() {
        let meta = std::fs::symlink_metadata(path).map_err(|e| {
            PeerError::PathUnsafe(format!("lstat failed at `{}`: {e}", path.display()))
        })?;
        let ft = meta.file_type();
        let entry_type = if ft.is_symlink() {
            PathEntryType::Symlink
        } else if ft.is_dir() {
            PathEntryType::Directory
        } else if ft.is_socket() {
            PathEntryType::Socket
        } else {
            PathEntryType::Other
        };
        let kind = if idx == 0 {
            PathNodeKind::Root
        } else if idx.saturating_add(1) == total {
            PathNodeKind::Socket
        } else {
            let depth = u16::try_from(idx).map_err(|_| {
                PeerError::PathUnsafe("endpoint ancestor depth exceeds u16::MAX".into())
            })?;
            PathNodeKind::Ancestor(depth)
        };
        nodes.push(PathWalkNode {
            kind,
            entry_type,
            owner_uid: meta.uid(),
            group_gid: meta.gid(),
            posix_mode: meta.mode(),
        });
    }
    Ok(nodes)
}

#[cfg(not(unix))]
pub fn inspect_filesystem_ancestors(socket_path: &Path) -> Result<Vec<PathWalkNode>, PeerError> {
    if socket_path
        .components()
        .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return Err(PeerError::PathUnsafe(
            "endpoint path must not contain relative `.` or `..` segments".into(),
        ));
    }
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_node(
        kind: PathNodeKind,
        owner_uid: u32,
        group_gid: u32,
        posix_mode: u32,
    ) -> PathWalkNode {
        PathWalkNode {
            kind,
            entry_type: PathEntryType::Directory,
            owner_uid,
            group_gid,
            posix_mode,
        }
    }

    fn sock_node(owner_uid: u32) -> PathWalkNode {
        PathWalkNode {
            kind: PathNodeKind::Socket,
            entry_type: PathEntryType::Socket,
            owner_uid,
            group_gid: 0,
            posix_mode: 0o666,
        }
    }

    #[test]
    fn accepts_root_owned_ancestors_and_world_writable_socket() {
        let nodes = vec![
            dir_node(PathNodeKind::Root, 0, 0, 0o755),
            dir_node(PathNodeKind::Ancestor(1), 0, 0, 0o755),
            sock_node(0),
        ];
        assert_eq!(
            verify_unix_path_nodes(&nodes, 0, Some(1000), &[]),
            PathCheckOutcome::Safe
        );
    }

    #[test]
    fn rejects_foreign_socket_leaf_and_directory_leaf() {
        let foreign_sock = vec![
            dir_node(PathNodeKind::Root, 0, 0, 0o755),
            dir_node(PathNodeKind::Ancestor(1), 0, 80, 0o775),
            sock_node(1001),
        ];
        assert_eq!(
            verify_unix_path_nodes(&foreign_sock, 0, None, &[80]),
            PathCheckOutcome::Foreign {
                node: PathNodeKind::Socket,
                owner_uid: 1001
            }
        );

        let dir_leaf = vec![
            dir_node(PathNodeKind::Root, 0, 0, 0o755),
            dir_node(PathNodeKind::Socket, 0, 0, 0o755),
        ];
        assert!(matches!(
            verify_unix_path_nodes(&dir_leaf, 0, None, &[]),
            PathCheckOutcome::Unsafe {
                node: PathNodeKind::Socket,
                ..
            }
        ));

        let regular_file_leaf = vec![
            dir_node(PathNodeKind::Root, 0, 0, 0o755),
            PathWalkNode {
                kind: PathNodeKind::Socket,
                entry_type: PathEntryType::Other,
                owner_uid: 0,
                group_gid: 0,
                posix_mode: 0o644,
            },
        ];
        assert!(matches!(
            verify_unix_path_nodes(&regular_file_leaf, 0, None, &[]),
            PathCheckOutcome::Unsafe {
                node: PathNodeKind::Socket,
                ..
            }
        ));

        assert!(matches!(
            verify_unix_path_nodes(&[dir_node(PathNodeKind::Root, 0, 0, 0o755)], 0, None, &[]),
            PathCheckOutcome::Unsafe {
                node: PathNodeKind::Root,
                ..
            }
        ));
    }

    #[test]
    fn rejects_symlink_ancestor_and_foreign_owner() {
        let mut sym_nodes = vec![
            dir_node(PathNodeKind::Root, 0, 0, 0o755),
            dir_node(PathNodeKind::Ancestor(1), 0, 0, 0o755),
            sock_node(0),
        ];
        sym_nodes[1].entry_type = PathEntryType::Symlink;
        assert!(matches!(
            verify_unix_path_nodes(&sym_nodes, 0, None, &[]),
            PathCheckOutcome::Unsafe {
                node: PathNodeKind::Ancestor(1),
                ..
            }
        ));

        let foreign_nodes = vec![
            dir_node(PathNodeKind::Root, 0, 0, 0o755),
            dir_node(PathNodeKind::Ancestor(1), 1337, 1337, 0o755),
            sock_node(0),
        ];
        assert_eq!(
            verify_unix_path_nodes(&foreign_nodes, 0, None, &[]),
            PathCheckOutcome::Foreign {
                node: PathNodeKind::Ancestor(1),
                owner_uid: 1337
            }
        );

        for mode in [0o777, 0o1777] {
            let world_writable = vec![
                dir_node(PathNodeKind::Root, 0, 0, 0o755),
                dir_node(PathNodeKind::Ancestor(1), 0, 0, mode),
                sock_node(0),
            ];
            assert!(matches!(
                verify_unix_path_nodes(&world_writable, 0, None, &[]),
                PathCheckOutcome::Unsafe {
                    node: PathNodeKind::Ancestor(1),
                    ..
                }
            ));
        }
    }

    #[test]
    fn enforces_trusted_groups_on_group_writable_dirs() {
        let nodes = vec![
            dir_node(PathNodeKind::Root, 0, 0, 0o755),
            dir_node(PathNodeKind::Ancestor(1), 0, 80, 0o775),
            sock_node(0),
        ];
        assert!(matches!(
            verify_unix_path_nodes(&nodes, 0, Some(20), &[]),
            PathCheckOutcome::Unsafe { .. }
        ));
        assert_eq!(
            verify_unix_path_nodes(&nodes, 0, Some(20), &[80]),
            PathCheckOutcome::Safe
        );
    }
}
