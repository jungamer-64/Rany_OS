// ============================================================================
// src/application/browser/script/vm/mod.rs - Virtual Machine Module
// ============================================================================
//!
//! # 仮想マシン
//!
//! RustScriptのバイトコードを実行するスタックベースの仮想マシン。
//!
//! ## モジュール構成
//! - `instructions` - バイトコード命令と定数プール
//! - `frame` - 呼び出しフレームとループ情報
//! - `dom` - DOM操作定義
//! - `vm_core` - VM本体
//! - `exec` - 命令実行
//! - `ops` - 演算ヘルパー
//! - `native` - ネイティブ関数実行
//! - `methods` - メソッド呼び出し

mod dom;
mod exec;
mod frame;
mod instructions;
mod methods;
mod native;
mod ops;
mod vm_core;

// 型の再エクスポート
pub use dom::DomOperation;
pub use frame::CallFrame;
pub use instructions::{ConstantPool, Instruction};
pub use vm_core::VirtualMachine;
