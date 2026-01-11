// ============================================================================
// kernel/src/shell/exoshell/display.rs - Display implementations
// ============================================================================

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::{self, Display};

use super::types::*;

impl<'a> Display for ExoValue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExoValue::Nil => write!(f, "nil"),
            ExoValue::Bool(b) => write!(f, "{}", b),
            ExoValue::Int(i) => write!(f, "{}", i),
            ExoValue::Float(fl) => write!(f, "{:.2}", fl),
            ExoValue::String(s) => write!(f, "{}", s),
            ExoValue::Bytes(b) => write!(f, "<{} bytes>", b.len()),
            ExoValue::Array(arr) => {
                writeln!(f, "[")?;
                for (i, item) in arr.iter().enumerate() {
                    writeln!(f, "  [{}] {}", i, item)?;
                }
                write!(f, "]")
            }
            ExoValue::Map(map) => {
                writeln!(f, "{{")?;
                for (k, v) in map.iter() {
                    writeln!(f, "  {}: {}", k, v)?;
                }
                write!(f, "}}")
            }
            ExoValue::FileEntry(e) => e.fmt(f),
            ExoValue::NetConnection(c) => c.fmt(f),
            ExoValue::Process(p) => p.fmt(f),
            ExoValue::Capability(cap) => cap.fmt(f),
            ExoValue::Iterator(it) => write!(
                f,
                "<Iterator: {} -> {} filters>",
                it.source,
                it.filters.len()
            ),
            ExoValue::BufferRef(b) => write!(f, "<BufferRef: {} bytes, zero-copy>", b.len()),
            ExoValue::StringRef(s) => write!(f, "{}", s.as_str()),
            ExoValue::Error(e) => write!(f, "Error: {}", e),
            ExoValue::Break => write!(f, "<Break>"),
            ExoValue::Continue => write!(f, "<Continue>"),
            ExoValue::Exit => write!(f, "Exit"),
        }
    }
}

impl Display for FileEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let type_char = match self.file_type {
            FileType::Directory => 'd',
            FileType::Symlink => 'l',
            FileType::Device => 'c',
            FileType::Socket => 's',
            FileType::Pipe => 'p',
            FileType::Regular => '-',
        };
        let perm = format!(
            "{}{}{}",
            if self.permissions.read { "r" } else { "-" },
            if self.permissions.write { "w" } else { "-" },
            if self.permissions.execute { "x" } else { "-" }
        );
        write!(
            f,
            "{}{} {:>8} {} {}",
            type_char,
            perm,
            format_size(self.size),
            self.owner,
            self.name
        )
    }
}

impl Display for NetConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<5} {}.{}.{}.{}:{:<5} -> {}.{}.{}.{}:{:<5} [{}]",
            self.protocol,
            self.local_addr[0],
            self.local_addr[1],
            self.local_addr[2],
            self.local_addr[3],
            self.local_port,
            self.remote_addr[0],
            self.remote_addr[1],
            self.remote_addr[2],
            self.remote_addr[3],
            self.remote_port,
            self.state
        )
    }
}

impl Display for ProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:>5} {:>8} {:>5.1}% {:>8} KB  {}",
            self.pid,
            format!("{:?}", self.state),
            self.cpu_usage,
            self.memory_kb,
            self.name
        )
    }
}

impl Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ops: Vec<&str> = self
            .operations
            .iter()
            .map(|op| match op {
                CapOperation::Read => "R",
                CapOperation::Write => "W",
                CapOperation::Execute => "X",
                CapOperation::Delete => "D",
                CapOperation::Grant => "G",
                CapOperation::Revoke => "V",
                CapOperation::Create => "C",
                CapOperation::List => "L",
            })
            .collect();
        write!(
            f,
            "Cap[{}] {} [{}] from:{} delegatable:{}",
            self.id,
            self.resource,
            ops.join(""),
            self.issuer,
            self.delegatable
        )
    }
}

/// ファイルサイズを人間が読みやすい形式にフォーマット
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1}G", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}M", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}K", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

/// シェル出力用に値をフォーマット
/// - Nil: 出力なし (None)
/// - Bytes: UTF-8なら文字列として表示
/// - Array: 各要素を改行区切りで表示
/// - その他: そのまま文字列化
pub fn format_shell_output(val: &ExoValue) -> Option<String> {
    match val {
        ExoValue::Nil | ExoValue::Exit | ExoValue::Break | ExoValue::Continue => None,
        ExoValue::Bytes(bytes) => {
            if let Ok(s) = core::str::from_utf8(bytes) {
                Some(s.to_string())
            } else {
                Some(format!("{}", val))
            }
        }
        ExoValue::Array(items) => {
            if items.is_empty() {
                return None;
            }
            let lines: Vec<String> = items.iter().map(|item| format!("{}", item)).collect();
            Some(lines.join("\n"))
        }
        _ => Some(format!("{}", val)),
    }
}
