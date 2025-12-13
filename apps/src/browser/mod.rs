// ============================================================================
// apps/src/browser/mod.rs - Browser Application Module
// ============================================================================
//!
//! # Browser Application
//!
//! A web browser with HTML/CSS parsing, DOM, layout, and rendering.

#![allow(dead_code)]
#![allow(unused_variables)]

pub mod browser;
pub mod css;
pub mod dom;
pub mod html;
pub mod layout;
pub mod render;
pub mod style;

pub use browser::Browser;
