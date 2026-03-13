//! 環境変数 (Environment Variables)
//!
//! プロセス環境の管理

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use crate::sync::PoisonRwLock;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 環境変数名 (Newtype)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct EnvKey(String);

impl EnvKey {
    pub fn new(key: &str) -> Self {
        Self(String::from(key))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 有効な環境変数名かチェック
    pub fn is_valid(&self) -> bool {
        let bytes = self.0.as_bytes();
        if bytes.is_empty() {
            return false;
        }

        // 最初の文字は英字またはアンダースコア
        let first = bytes[0];
        if !(first.is_ascii_alphabetic() || first == b'_') {
            return false;
        }

        // 残りの文字は英数字またはアンダースコア
        self.0
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    }
}

impl From<&str> for EnvKey {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

/// 環境変数値 (Newtype)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvValue(String);

impl EnvValue {
    pub fn new(value: &str) -> Self {
        Self(String::from(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn parse_int(&self) -> Option<i64> {
        self.0.parse().ok()
    }

    pub fn parse_bool(&self) -> Option<bool> {
        match self.0.to_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" | "" => Some(false),
            _ => None,
        }
    }

    pub fn parse_path_list(&self) -> Vec<&str> {
        self.0.split(':').filter(|s| !s.is_empty()).collect()
    }
}

impl From<&str> for EnvValue {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

/// 環境変数エラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvError {
    InvalidKey,
    NotFound,
    ValueTooLarge,
    TooManyVariables,
}

/// 環境変数コンテナ
pub struct Environment {
    /// 変数マップ
    vars: PoisonRwLock<BTreeMap<EnvKey, EnvValue>>,
    /// 変数数
    count: AtomicUsize,
    /// 最大変数数
    max_vars: usize,
    /// 最大値サイズ
    max_value_size: usize,
}

impl Environment {
    pub const DEFAULT_MAX_VARS: usize = 1024;
    pub const DEFAULT_MAX_VALUE_SIZE: usize = 32 * 1024; // 32KB

    /// 新しい環境を作成
    pub const fn new() -> Self {
        Self {
            vars: PoisonRwLock::new(BTreeMap::new()),
            count: AtomicUsize::new(0),
            max_vars: Self::DEFAULT_MAX_VARS,
            max_value_size: Self::DEFAULT_MAX_VALUE_SIZE,
        }
    }

    /// 制限付きで作成
    pub fn with_limits(max_vars: usize, max_value_size: usize) -> Self {
        Self {
            vars: PoisonRwLock::new(BTreeMap::new()),
            count: AtomicUsize::new(0),
            max_vars,
            max_value_size,
        }
    }

    /// デフォルト環境変数を設定
    pub fn set_defaults(&self) {
        let defaults = [
            ("PATH", "/bin:/usr/bin:/usr/local/bin"),
            ("HOME", "/root"),
            ("USER", "root"),
            ("SHELL", "/bin/sh"),
            ("TERM", "xterm-256color"),
            ("LANG", "en_US.UTF-8"),
            ("PWD", "/"),
            ("HOSTNAME", "exorust"),
        ];

        for (key, value) in defaults {
            let _ = self.set(key, value);
        }
    }

    /// 環境変数を設定
    pub fn set(&self, key: &str, value: &str) -> Result<(), EnvError> {
        let key = EnvKey::new(key);
        if !key.is_valid() {
            return Err(EnvError::InvalidKey);
        }

        if value.len() > self.max_value_size {
            return Err(EnvError::ValueTooLarge);
        }

        let value = EnvValue::new(value);

        let mut vars = self.vars.write().unwrap_or_else(|e| e.into_inner());

        if !vars.contains_key(&key) {
            if self.count.load(Ordering::Acquire) >= self.max_vars {
                return Err(EnvError::TooManyVariables);
            }
            self.count.fetch_add(1, Ordering::AcqRel);
        }

        vars.insert(key, value);
        Ok(())
    }

    /// 環境変数を取得
    pub fn get(&self, key: &str) -> Option<EnvValue> {
        let key = EnvKey::new(key);
        let vars = self.vars.read().unwrap_or_else(|e| e.into_inner());
        vars.get(&key).cloned()
    }

    /// 環境変数を削除
    pub fn unset(&self, key: &str) -> Result<(), EnvError> {
        let key = EnvKey::new(key);
        let mut vars = self.vars.write().unwrap_or_else(|e| e.into_inner());

        if vars.remove(&key).is_some() {
            self.count.fetch_sub(1, Ordering::AcqRel);
            Ok(())
        } else {
            Err(EnvError::NotFound)
        }
    }

    /// 環境変数が存在するか
    pub fn contains(&self, key: &str) -> bool {
        let key = EnvKey::new(key);
        let vars = self.vars.read().unwrap_or_else(|e| e.into_inner());
        vars.contains_key(&key)
    }

    /// 全環境変数を取得
    pub fn all(&self) -> Vec<(String, String)> {
        let vars = self.vars.read().unwrap_or_else(|e| e.into_inner());
        vars.iter()
            .map(|(k, v)| (String::from(k.as_str()), String::from(v.as_str())))
            .collect()
    }

    /// 環境変数一覧を "KEY=VALUE" 形式で取得
    pub fn to_strings(&self) -> Vec<String> {
        let vars = self.vars.read().unwrap_or_else(|e| e.into_inner());
        vars.iter()
            .map(|(k, v)| alloc::format!("{}={}", k.as_str(), v.as_str()))
            .collect()
    }

    /// 文字列から環境変数を解析して設定
    pub fn parse_and_set(&self, s: &str) -> Result<(), EnvError> {
        if let Some((key, value)) = s.split_once('=') {
            self.set(key, value)
        } else {
            Err(EnvError::InvalidKey)
        }
    }

    /// 環境変数数を取得
    pub fn len(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// クリア
    pub fn clear(&self) {
        let mut vars = self.vars.write().unwrap_or_else(|e| e.into_inner());
        vars.clear();
        self.count.store(0, Ordering::Release);
    }

    /// 環境をコピー
    pub fn clone_from(&self, other: &Environment) {
        let other_vars = other.vars.read().unwrap_or_else(|e| e.into_inner());
        let mut vars = self.vars.write().unwrap_or_else(|e| e.into_inner());

        vars.clear();
        for (k, v) in other_vars.iter() {
            vars.insert(EnvKey::new(k.as_str()), EnvValue::new(v.as_str()));
        }

        self.count.store(other_vars.len(), Ordering::Release);
    }

    /// 環境変数を展開 ($VAR や ${VAR} を置換)
    pub fn expand(&self, s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();

        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while let Some(c) = chars.next() {
            if c == '$' {
                let mut var_name = String::new();
                let braced = chars.peek() == Some(&'{');

                if braced {
                    chars.next(); // '{'
                    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
                    while let Some(&c) = chars.peek() {
                        if c == '}' {
                            chars.next();
                            break;
                        }
                        var_name.push(chars.next().unwrap());
                    }
                } else {
                    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
                    while let Some(&c) = chars.peek() {
                        if c.is_ascii_alphanumeric() || c == '_' {
                            var_name.push(chars.next().unwrap());
                        } else {
                            break;
                        }
                    }
                }

                if let Some(value) = self.get(&var_name) {
                    result.push_str(value.as_str());
                }
            } else {
                result.push(c);
            }
        }

        result
    }
}

/// グローバルカーネル環境変数
static KERNEL_ENV: Environment = Environment::new();

/// カーネル環境変数を取得
pub fn kernel_env() -> &'static Environment {
    &KERNEL_ENV
}

/// 初期化
pub fn init() {
    KERNEL_ENV.set_defaults();
}

/// PATH を取得
pub fn get_path() -> Option<EnvValue> {
    KERNEL_ENV.get("PATH")
}

/// HOME を取得
pub fn get_home() -> Option<EnvValue> {
    KERNEL_ENV.get("HOME")
}

/// USER を取得
pub fn get_user() -> Option<EnvValue> {
    KERNEL_ENV.get("USER")
}

/// PWD を取得
pub fn get_pwd() -> Option<EnvValue> {
    KERNEL_ENV.get("PWD")
}

/// PWD を設定
pub fn set_pwd(path: &str) -> Result<(), EnvError> {
    KERNEL_ENV.set("PWD", path)
}

/// TERM を取得
pub fn get_term() -> Option<EnvValue> {
    KERNEL_ENV.get("TERM")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_env_basic() {
        let env = Environment::new();

        env.set("TEST_VAR", "test_value").unwrap();
        assert_eq!(env.get("TEST_VAR").unwrap().as_str(), "test_value");

        env.unset("TEST_VAR").unwrap();
        assert!(env.get("TEST_VAR").is_none());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_env_key_validation() {
        assert!(EnvKey::new("VALID_KEY").is_valid());
        assert!(EnvKey::new("_also_valid").is_valid());
        assert!(EnvKey::new("KEY123").is_valid());

        assert!(!EnvKey::new("").is_valid());
        assert!(!EnvKey::new("123_invalid").is_valid());
        assert!(!EnvKey::new("key-with-dash").is_valid());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_env_expand() {
        let env = Environment::new();
        env.set("USER", "testuser").unwrap();
        env.set("HOME", "/home/testuser").unwrap();

        assert_eq!(env.expand("Hello $USER!"), "Hello testuser!");
        assert_eq!(env.expand("Home is ${HOME}"), "Home is /home/testuser");
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_environ_parsing() {
        use alloc::vec;
        let value = EnvValue::new("/bin:/usr/bin:/usr/local/bin");
        let paths = value.parse_path_list();
        assert_eq!(paths, vec!["/bin", "/usr/bin", "/usr/local/bin"]);
    }
}
