// ============================================================================
// libs/vfs/src/path.rs - Path Manipulation
// ============================================================================

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

/// ファイルパス
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Path {
    inner: String,
}

impl Path {
    pub fn new(path: &str) -> Self {
        Self {
            inner: path.to_string(),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }

    pub fn components(&self) -> Vec<&str> {
        self.inner.split('/').filter(|s| !s.is_empty()).collect()
    }

    pub fn parent(&self) -> Option<Path> {
        if self.inner == "/" {
            return None;
        }

        let components = self.components();
        if components.is_empty() {
            return Some(Path::new("/"));
        }

        let mut parent = String::from("/");
        for (i, component) in components.iter().enumerate() {
            if i == components.len() - 1 {
                break;
            }
            if i > 0 {
                parent.push('/');
            }
            parent.push_str(component);
        }

        Some(Path::new(&parent))
    }

    pub fn join(&self, path: &str) -> Path {
        let mut new_path = self.inner.clone();
        if !new_path.ends_with('/') {
            new_path.push('/');
        }
        new_path.push_str(path);
        Path::new(&new_path)
    }
}

impl fmt::Debug for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Path({:?})", self.inner)
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl From<&str> for Path {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}
