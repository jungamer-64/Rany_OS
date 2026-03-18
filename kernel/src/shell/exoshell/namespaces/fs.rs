// ============================================================================
// src/shell/exoshell/namespaces/fs.rs - Filesystem Namespace
// ============================================================================

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{BoxFuture, ShellNamespace};
use crate::security::capability::CAP_DAC_OVERRIDE;
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

        let shell = match kernel_api::service::kernel::instance().shell() {
            Some(s) => s,
            None => return ExoValue::Error(String::from("Shell services unavailable")),
        };

        match shell.list_directory(path) {
            Ok(entries) => {
                let values: Vec<ExoValue> = entries
                    .into_iter()
                    .map(|e| {
                        let file_type = match e.file_type {
                            kernel_api::service::shell::FileType::Directory => FileType::Directory,
                            kernel_api::service::shell::FileType::Symlink => FileType::Symlink,
                            kernel_api::service::shell::FileType::CharDevice
                            | kernel_api::service::shell::FileType::BlockDevice => FileType::Device,
                            _ => FileType::Regular,
                        };
                        ExoValue::FileEntry(FileEntry {
                            name: e.name.clone(),
                            path: if path == "/" {
                                format!("/{}", e.name)
                            } else {
                                format!("{}/{}", path, e.name)
                            },
                            file_type,
                            size: e.size,
                            owner: String::from("root"),
                            permissions: Permissions {
                                read: true,
                                write: true,
                                execute: e.file_type
                                    == kernel_api::service::shell::FileType::Directory,
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
            Err(e) => ExoValue::Error(String::from(e)),
        }
    }

    /// ファイルを読み取り（ゼロコピー対応）
    pub async fn read(path: &str) -> ExoValue<'static> {
        use crate::shell::exoshell::buffer_view::KernelBufferView;

        crate::task::yield_now().await;

        let shell = match kernel_api::service::kernel::instance().shell() {
            Some(s) => s,
            None => return ExoValue::Error(String::from("Shell services unavailable")),
        };

        // ゼロコピー読み取りを使用（Arc<Vec<u8>>を直接受け取る）
        match shell.read_file_zero_copy(path) {
            Ok(content) => ExoValue::BufferRef(KernelBufferView::from_arc(content)),
            Err(e) => ExoValue::Error(String::from(e)),
        }
    }

    /// ファイルに書き込み
    pub async fn write(path: &str, data: &[u8]) -> ExoValue<'static> {
        crate::task::yield_now().await;

        let shell = match kernel_api::service::kernel::instance().shell() {
            Some(s) => s,
            None => return ExoValue::Error(String::from("Shell services unavailable")),
        };

        match shell.write_file(path, data) {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(String::from(e)),
        }
    }

    /// ファイル/ディレクトリの詳細情報
    pub async fn stat(path: &str) -> ExoValue<'static> {
        crate::task::yield_now().await;

        let shell = match kernel_api::service::kernel::instance().shell() {
            Some(s) => s,
            None => return ExoValue::Error(String::from("Shell services unavailable")),
        };

        match shell.stat_file(path) {
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
            Err(e) => ExoValue::Error(String::from(e)),
        }
    }

    /// ディレクトリ作成
    pub async fn mkdir(path: &str) -> ExoValue<'static> {
        crate::task::yield_now().await;

        let shell = match kernel_api::service::kernel::instance().shell() {
            Some(s) => s,
            None => return ExoValue::Error(String::from("Shell services unavailable")),
        };

        match shell.make_directory(path) {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(String::from(e)),
        }
    }

    /// 削除
    pub async fn remove(path: &str) -> ExoValue<'static> {
        crate::task::yield_now().await;

        let shell = match kernel_api::service::kernel::instance().shell() {
            Some(s) => s,
            None => return ExoValue::Error(String::from("Shell services unavailable")),
        };

        // まずファイルとして削除を試行
        match shell.remove_file(path) {
            Ok(()) => ExoValue::Bool(true),
            Err(_) => {
                // ディレクトリとして削除
                match shell.remove_directory(path) {
                    Ok(()) => ExoValue::Bool(true),
                    Err(e) => ExoValue::Error(String::from(e)),
                }
            }
        }
    }

    /// ファイルコピー（ゼロコピー読み取り → 書き込み）
    pub async fn copy(src: &str, dst: &str) -> ExoValue<'static> {
        crate::task::yield_now().await;

        let shell = match kernel_api::service::kernel::instance().shell() {
            Some(s) => s,
            None => return ExoValue::Error(String::from("Shell services unavailable")),
        };

        // ゼロコピーで読み取り
        let content = match shell.read_file_zero_copy(src) {
            Ok(c) => c,
            Err(e) => return ExoValue::Error(String::from(e)),
        };

        // 書き込み (コピーは write_file 呼び出し時に発生)
        match shell.write_file(dst, &content) {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(String::from(e)),
        }
    }

    /// 空ファイル作成（touch）
    pub async fn touch(path: &str) -> ExoValue<'static> {
        crate::task::yield_now().await;

        let shell = match kernel_api::service::kernel::instance().shell() {
            Some(s) => s,
            None => return ExoValue::Error(String::from("Shell services unavailable")),
        };

        // ファイルが存在するか確認
        if shell.stat_file(path).is_ok() {
            // 既存ファイルは成功扱い（タイムスタンプ更新は未実装）
            return ExoValue::Bool(true);
        }

        // 存在しない場合は空ファイル作成
        match shell.write_file(path, &[]) {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => ExoValue::Error(String::from(e)),
        }
    }

    /// ファイル移動（コピー + 元ファイル削除）
    pub async fn mv(src: &str, dst: &str) -> ExoValue<'static> {
        crate::task::yield_now().await;

        let shell = match kernel_api::service::kernel::instance().shell() {
            Some(s) => s,
            None => return ExoValue::Error(String::from("Shell services unavailable")),
        };

        // まずコピー（ゼロコピー読み取り）
        let content = match shell.read_file_zero_copy(src) {
            Ok(c) => c,
            Err(e) => return ExoValue::Error(String::from(e)),
        };

        if let Err(e) = shell.write_file(dst, &content) {
            return ExoValue::Error(String::from(e));
        }

        // 成功後に元ファイルを削除
        match shell.remove_file(src) {
            Ok(()) => ExoValue::Bool(true),
            Err(e) => {
                // 注意: 宛先ファイルは作成済み、アトミックではない
                ExoValue::Error(format!("Move incomplete: source deletion failed: {}", e))
            }
        }
    }

    fn extract_str_arg<'a>(
        args: &'a [ExoValue<'static>],
        index: usize,
        default: &'a str,
    ) -> &'a str {
        args.get(index)
            .and_then(|v| match v {
                ExoValue::String(s) => Some(s.as_ref()),
                _ => None,
            })
            .unwrap_or(default)
    }

    fn check_write_cap(
        caps: &crate::security::CapabilitySet,
        operation: &str,
    ) -> Result<(), ExoValue<'static>> {
        if caps.has_capability(CAP_DAC_OVERRIDE) {
            Ok(())
        } else {
            Err(ExoValue::Error(format!(
                "Permission denied: CAP_DAC_OVERRIDE required for {}",
                operation
            )))
        }
    }

    fn extract_write_data(args: &[ExoValue<'static>]) -> Vec<u8> {
        args.get(1)
            .map(|v| match v {
                ExoValue::String(s) => s.as_bytes().to_vec(),
                ExoValue::BufferRef(buf) => buf.to_vec(),
                _ => Vec::new(),
            })
            .unwrap_or_default()
    }

    async fn call_read_op(method: &str, args: &[ExoValue<'static>]) -> ExoValue<'static> {
        match method {
            "entries" | "ls" => Self::entries(Self::extract_str_arg(args, 0, ".")).await,
            "read" | "cat" => Self::read(Self::extract_str_arg(args, 0, "")).await,
            "stat" => Self::stat(Self::extract_str_arg(args, 0, "")).await,
            _ => ExoValue::Error(format!("Unknown read method 'fs.{}'", method)),
        }
    }

    async fn call_write_single_arg_op(
        method: &str,
        args: &[ExoValue<'static>],
    ) -> ExoValue<'static> {
        let path = Self::extract_str_arg(args, 0, "");
        match method {
            "mkdir" => Self::mkdir(path).await,
            "remove" | "rm" => Self::remove(path).await,
            "touch" => Self::touch(path).await,
            "write" => {
                let data = Self::extract_write_data(args);
                Self::write(path, &data).await
            }
            _ => ExoValue::Error(format!("Unknown write method 'fs.{}'", method)),
        }
    }

    async fn call_write_two_arg_op(method: &str, args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let src = Self::extract_str_arg(args, 0, "");
        let dst = Self::extract_str_arg(args, 1, "");
        if dst.is_empty() {
            return ExoValue::Error(format!("Usage: fs.{}(src, dst)", method));
        }
        match method {
            "copy" | "cp" => Self::copy(src, dst).await,
            "move" | "mv" => Self::mv(src, dst).await,
            _ => ExoValue::Error(format!("Unknown method 'fs.{}'", method)),
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
        caps: &'a crate::security::CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "entries" | "ls" | "read" | "cat" | "stat" => {
                    Self::call_read_op(method, args).await
                }
                "mkdir" | "remove" | "rm" | "touch" | "write" => {
                    if let Err(e) = Self::check_write_cap(caps, method) {
                        return e;
                    }
                    Self::call_write_single_arg_op(method, args).await
                }
                "copy" | "cp" | "move" | "mv" => {
                    if let Err(e) = Self::check_write_cap(caps, method) {
                        return e;
                    }
                    Self::call_write_two_arg_op(method, args).await
                }
                // 'cd' is handled by shell built-in logic generally, but if called here it does nothing stateful
                "cd" => ExoValue::Error(String::from("cd is a shell built-in")),
                "pwd" => ExoValue::Error(String::from("pwd is a shell built-in")),
                _ => ExoValue::Error(format!(
                    "Unknown method 'fs.{}'\nValid methods: entries, read, write, stat, mkdir, remove, copy, touch, move",
                    method
                )),
            }
        })
    }
}
