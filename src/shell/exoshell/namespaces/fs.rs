// ============================================================================
// src/shell/exoshell/namespaces/fs.rs - Filesystem Namespace
// ============================================================================

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::shell::exoshell::types::*;

/// ファイルシステム名前空間
pub struct FsNamespace;

impl FsNamespace {
    /// ディレクトリのエントリを取得（イテレータとして）
    /// async版: I/O操作中に他のタスクに譲る
    pub async fn entries(path: &str) -> ExoValue {
        // Yield point: 他のタスクに実行機会を与える
        crate::task::yield_now().await;
        
        match crate::fs::list_directory(path, "/") {
            Ok(entries) => {
                let values: Vec<ExoValue> = entries
                    .into_iter()
                    .map(|e| {
                        ExoValue::FileEntry(FileEntry {
                            name: e.name.clone(),
                            path: if path == "/" {
                                format!("/{}", e.name)
                            } else {
                                format!("{}/{}", path, e.name)
                            },
                            file_type: match e.file_type {
                                crate::fs::FileType::Directory => FileType::Directory,
                                crate::fs::FileType::Symlink => FileType::Symlink,
                                crate::fs::FileType::CharDevice => FileType::Device,
                                crate::fs::FileType::BlockDevice => FileType::Device,
                                crate::fs::FileType::Socket => FileType::Socket,
                                crate::fs::FileType::Fifo => FileType::Pipe,
                                _ => FileType::Regular,
                            },
                            size: 0, // DirEntry doesn't have size, need stat for that
                            owner: String::from("root"),
                            permissions: Permissions {
                                read: true,
                                write: true,
                                execute: e.file_type == crate::fs::FileType::Directory,
                                delete: true,
                                grant: false,
                            },
                            created: 0,
                            modified: 0,
                            inode: e.ino,
                        })
                    })
                    .collect();
                ExoValue::Array(values)
            }
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }

    /// ファイルを読み取り（ゼロコピー対応）
    pub async fn read(path: &str) -> ExoValue {
        crate::task::yield_now().await;
        
        match crate::fs::read_file_content(path, "/") {
            Ok(content) => ExoValue::Bytes(content),
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }

    /// ファイルに書き込み
    pub async fn write(path: &str, data: &[u8]) -> ExoValue {
        crate::task::yield_now().await;
        
        match crate::fs::write_file_content(path, "/", data) {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }

    /// ファイル/ディレクトリの詳細情報
    pub async fn stat(path: &str) -> ExoValue {
        crate::task::yield_now().await;
        
        match crate::fs::stat_file(path, "/") {
            Ok(attr) => {
                let mut map = BTreeMap::new();
                map.insert(String::from("path"), ExoValue::String(path.to_string()));
                map.insert(String::from("size"), ExoValue::Int(attr.size as i64));
                map.insert(String::from("inode"), ExoValue::Int(attr.ino as i64));
                map.insert(String::from("links"), ExoValue::Int(attr.nlink as i64));
                map.insert(String::from("type"), ExoValue::String(format!("{:?}", attr.file_type)));
                ExoValue::Map(map)
            }
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }

    /// ディレクトリ作成
    pub async fn mkdir(path: &str) -> ExoValue {
        crate::task::yield_now().await;
        
        match crate::fs::make_directory(path, "/") {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }

    /// 削除
    pub async fn remove(path: &str) -> ExoValue {
        crate::task::yield_now().await;
        
        // まずファイルとして削除を試行
        match crate::fs::remove_file(path, "/") {
            Ok(()) => ExoValue::Bool(true),
            Err(crate::fs::FsError::IsDirectory) => {
                // ディレクトリとして削除
                match crate::fs::remove_directory(path, "/") {
                    Ok(()) => ExoValue::Bool(true),
                    Err(e) => ExoValue::Error(format!("{:?}", e)),
                }
            }
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }
}
