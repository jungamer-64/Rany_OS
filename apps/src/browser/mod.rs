// apps/src/browser/mod.rs - Browser Application Stub
//!
//! Web browser application (stub - full impl to be migrated).

#![allow(dead_code)]

/// Browser application stub
pub struct Browser;

impl Browser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Browser {
    fn default() -> Self {
        Self::new()
    }
}
