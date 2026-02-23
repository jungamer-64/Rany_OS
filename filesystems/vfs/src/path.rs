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
    #[must_use]
    pub fn new(path: &str) -> Self {
        Self {
            inner: path.to_string(),
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    #[must_use]
    pub fn components(&self) -> Vec<&str> {
        self.inner.split('/').filter(|s| !s.is_empty()).collect()
    }

    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        if self.inner == "/" {
            return None;
        }

        let components = self.components();
        if components.is_empty() {
            return Some(Self::new("/"));
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

        Some(Self::new(&parent))
    }

    #[must_use]
    pub fn join(&self, path: &str) -> Self {
        let mut new_path = self.inner.clone();
        if !new_path.ends_with('/') {
            new_path.push('/');
        }
        new_path.push_str(path);
        Self::new(&new_path)
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
