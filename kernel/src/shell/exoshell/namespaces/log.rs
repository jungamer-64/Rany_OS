// ============================================================================
// src/shell/exoshell/namespaces/log.rs - Log Control Namespace
// ============================================================================
//!
//! ExoShell の log 名前空間。
//! ランタイムのログ設定（レベル変更、出力先トグル）を提供する。
//!
//! ## 使用例 (ExoShell)
//! ```text
//! log.level()               → { current: "Info" }
//! log.set_level("debug")    → "Log level set to Debug"
//! log.console(true)         → コンソールミラー有効化
//! log.serial(false)         → シリアル出力無効化
//! log.info("message")       → log::info! 出力
//! log.warn("message")       → log::warn! 出力
//! log.error("message")      → log::error! 出力
//! ```

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::boxed::Box;

use super::{BoxFuture, ShellNamespace};
use crate::shell::exoshell::types::ExoValue;

/// ログ制御名前空間
pub struct LogNamespace;

/// BTreeMapキー生成ヘルパー
#[inline]
fn s(v: &str) -> String {
    String::from(v)
}

impl LogNamespace {
    /// 現在のログレベルを取得
    pub fn level() -> ExoValue<'static> {
        let level = crate::io::log::current_log_level();
        let mut map = BTreeMap::new();
        map.insert(s("current"), ExoValue::String(Cow::Owned(format!("{}", level))));
        map.insert(
            s("console_mirror"),
            ExoValue::Bool(crate::io::log::console_mirror_enabled()),
        );
        map.insert(
            s("serial_output"),
            ExoValue::Bool(crate::io::log::serial_output_enabled()),
        );
        ExoValue::Map(map)
    }

    /// ログレベルを設定
    pub fn set_level(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let level_str = match args.first() {
            Some(ExoValue::String(s)) => s.as_ref(),
            _ => return ExoValue::Error(String::from("Usage: log.set_level(\"debug\")")),
        };

        match crate::io::log::set_log_level_from_str(level_str) {
            Ok(level) => ExoValue::String(Cow::Owned(format!(
                "Log level set to {}", level
            ))),
            Err(e) => ExoValue::Error(format!(
                "Invalid log level '{}': {}. Valid: off, error, warn, info, debug, trace",
                level_str, e
            )),
        }
    }

    /// コンソールミラーリング設定
    pub fn set_console_mirror(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        match args.first() {
            Some(ExoValue::Bool(enabled)) => {
                crate::io::log::set_console_mirror_enabled(*enabled);
                ExoValue::String(Cow::Owned(format!(
                    "Console mirror {}",
                    if *enabled { "enabled" } else { "disabled" }
                )))
            }
            _ => ExoValue::Error(String::from(
                "Usage: log.console(true) or log.console(false)",
            )),
        }
    }

    /// シリアル出力設定
    pub fn set_serial_output(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        match args.first() {
            Some(ExoValue::Bool(enabled)) => {
                crate::io::log::set_serial_output_enabled(*enabled);
                ExoValue::String(Cow::Owned(format!(
                    "Serial output {}",
                    if *enabled { "enabled" } else { "disabled" }
                )))
            }
            _ => ExoValue::Error(String::from(
                "Usage: log.serial(true) or log.serial(false)",
            )),
        }
    }

    /// シェルからのログ出力ヘルパー
    pub fn emit_log(level: &str, args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let message = match args.first() {
            Some(ExoValue::String(s)) => s.as_ref().to_string(),
            Some(other) => format!("{}", other),
            None => return ExoValue::Error(String::from("Usage: log.info(\"message\")")),
        };

        match level {
            "trace" => log::trace!("[ExoShell] {}", message),
            "debug" => log::debug!("[ExoShell] {}", message),
            "info" => log::info!("[ExoShell] {}", message),
            "warn" => log::warn!("[ExoShell] {}", message),
            "error" => log::error!("[ExoShell] {}", message),
            _ => return ExoValue::Error(format!("Unknown log level: {}", level)),
        }

        ExoValue::Bool(true)
    }
}

impl ShellNamespace for LogNamespace {
    fn name(&self) -> &str {
        "log"
    }

    fn call<'a>(
        &'a self,
        method: &'a str,
        args: &'a [ExoValue<'static>],
        caps: &'a crate::security::CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "level" | "status" => Self::level(),
                "set_level" => {
                    if !caps.has_capability(crate::security::capability::CAP_SYS_ADMIN) {
                        return ExoValue::Error(String::from(
                            "CAP_SYS_ADMIN required to change log level",
                        ));
                    }
                    Self::set_level(args)
                }
                "console" => {
                    if !caps.has_capability(crate::security::capability::CAP_SYS_ADMIN) {
                        return ExoValue::Error(String::from(
                            "CAP_SYS_ADMIN required to change console mirror",
                        ));
                    }
                    Self::set_console_mirror(args)
                }
                "serial" => {
                    if !caps.has_capability(crate::security::capability::CAP_SYS_ADMIN) {
                        return ExoValue::Error(String::from(
                            "CAP_SYS_ADMIN required to change serial output",
                        ));
                    }
                    Self::set_serial_output(args)
                }
                "trace" => Self::emit_log("trace", args),
                "debug" => Self::emit_log("debug", args),
                "info" => Self::emit_log("info", args),
                "warn" => Self::emit_log("warn", args),
                "error" => Self::emit_log("error", args),
                _ => ExoValue::Error(format!(
                    "Unknown method 'log.{}'\nValid methods: level, set_level, console, serial, trace, debug, info, warn, error",
                    method
                )),
            }
        })
    }
}
