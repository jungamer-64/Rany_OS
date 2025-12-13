// ============================================================================
// src/shell/exoshell/namespaces/fs.rs - Filesystem Namespace
// ============================================================================

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{BoxFuture, ShellNamespace};
use crate::shell::exoshell::types::*;
use alloc::boxed::Box;

/// ファイルシステム名前空間
pub struct FsNamespace;

impl FsNamespace {
    /// ディレクトリのエントリを取得（イテレータとして）
    /// async版: I/O操作中に他のタスクに譲る
    pub async fn entries(path: &str) -> ExoValue<'static> {
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
    /// 
    /// KernelBufferView を使用し、データは Arc でラップ。
    /// 複数回参照してもコピーは発生せず、参照カウントのみ増加。
    pub async fn read(path: &str) -> ExoValue<'static> {
        use crate::shell::exoshell::buffer_view::KernelBufferView;
        
        crate::task::yield_now().await;

        match crate::fs::read_file_content(path, "/") {
            Ok(content) => {
                // ゼロコピービューとしてラップ
                // NOTE: read_file_content は Vec<u8> を返すため、一度だけコピーが発生。
                // 将来的にはカーネルのページキャッシュから直接参照を取得する。
                ExoValue::BufferRef(KernelBufferView::new(content))
            }
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }

    /// ファイルに書き込み
    pub async fn write(path: &str, data: &[u8]) -> ExoValue<'static> {
        crate::task::yield_now().await;

        match crate::fs::write_file_content(path, "/", data) {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }

    /// ファイル/ディレクトリの詳細情報
    pub async fn stat(path: &str) -> ExoValue<'static> {
        crate::task::yield_now().await;

        match crate::fs::stat_file(path, "/") {
            Ok(attr) => {
                let mut map = BTreeMap::new();
                map.insert(
                    String::from("path"),
                    ExoValue::String(Cow::Owned(path.to_string())),
                );
                map.insert(String::from("size"), ExoValue::Int(attr.size as i64));
                map.insert(String::from("inode"), ExoValue::Int(attr.ino as i64));
                map.insert(String::from("links"), ExoValue::Int(attr.nlink as i64));
                map.insert(
                    String::from("type"),
                    ExoValue::String(Cow::Owned(format!("{:?}", attr.file_type))),
                );
                ExoValue::Map(map)
            }
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }

    /// ディレクトリ作成
    pub async fn mkdir(path: &str) -> ExoValue<'static> {
        crate::task::yield_now().await;

        match crate::fs::make_directory(path, "/") {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(format!("{:?}", e)),
        }
    }

    /// 削除
    pub async fn remove(path: &str) -> ExoValue<'static> {
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

impl ShellNamespace for FsNamespace {
    fn name(&self) -> &str {
        "fs"
    }

    fn call<'a>(
        &'a self,
        method: &'a str,
        args: &'a [ExoValue<'static>],
        _caps: &'a crate::security::CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "entries" | "ls" => {
                    let path = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::String(s) => Some(s.as_ref()),
                            _ => None,
                        })
                        .unwrap_or(".");
                    // Note: "." handling usually requires cwd from shell.
                    // But here we only receive args. Shell should resolve relative paths BEFORE calling,
                    // or we need to pass CWD.
                    // For now, assume shell resolves it, OR default to root if not provided matching existing behavior logic (mostly).
                    // Actually existing shell passed shell.cwd if arg missing.
                    // We'll rely on shell to pass the absolute path if possible, or handle "." if we can.
                    // But FsNamespace doesn't know CWD.
                    // FIX: Shell.rs currently resolves path using CWD before calling or passes CWD default.
                    // If we move logic here, we miss CWD.
                    // We'll assume args[0] IS the path to list. If missing, it's an error or root?
                    // Existing code: path = args.first()...unwrap_or_else(|| self.cwd.clone());
                    // So we MUST have the path passed.
                    Self::entries(path).await
                }
                "read" | "cat" => {
                    let path = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::String(s) => Some(s.as_ref()),
                            _ => None,
                        })
                        .unwrap_or("");
                    Self::read(path).await
                }
                "stat" => {
                    let path = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::String(s) => Some(s.as_ref()),
                            _ => None,
                        })
                        .unwrap_or("");
                    Self::stat(path).await
                }
                "mkdir" => {
                    let path = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::String(s) => Some(s.as_ref()),
                            _ => None,
                        })
                        .unwrap_or("");
                    Self::mkdir(path).await
                }
                "remove" | "rm" => {
                    let path = args
                        .first()
                        .and_then(|v| match v {
                            ExoValue::String(s) => Some(s.as_ref()),
                            _ => None,
                        })
                        .unwrap_or("");
                    Self::remove(path).await
                }
                // 'cd' is handled by shell built-in logic generally, but if called here it does nothing stateful
                "cd" => ExoValue::Error(String::from("cd is a shell built-in")),
                "pwd" => ExoValue::Error(String::from("pwd is a shell built-in")),
                _ => ExoValue::Error(format!(
                    "Unknown method 'fs.{}'\nValid methods: entries, read, stat, mkdir, remove",
                    method
                )),
            }
        })
    }
}
