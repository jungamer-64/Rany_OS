// ============================================================================
// src/syscall/mod.rs - System Call Interface
// 設計書: SPL（Single Privilege Level）環境でのシステムコール
// ============================================================================
//!
//! # システムコールインターフェース
//!
//! SPL環境では従来のint/syscall命令によるシステムコールは不要だが、
//! セル間のサービス呼び出しのための統一インターフェースを提供。
//!
//! ## 設計原則
//! - 関数呼び出しベースのシステムコール（SPLなのでトラップ不要）
//! - 非同期対応のシステムコールAPI
//! - ケーパビリティベースのアクセス制御

#![allow(dead_code)]

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use alloc::vec::Vec;
use alloc::string::String;

// ============================================================================
// システムコール番号
// ============================================================================

/// システムコール番号
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SyscallNumber {
    // プロセス管理
    Exit = 0,
    Yield = 1,
    GetPid = 2,
    Fork = 3,
    Exec = 4,
    Wait = 5,
    
    // メモリ管理
    Mmap = 10,
    Munmap = 11,
    Mprotect = 12,
    Brk = 13,
    
    // ファイル操作
    Open = 20,
    Close = 21,
    Read = 22,
    Write = 23,
    Seek = 24,
    Stat = 25,
    Fstat = 26,
    Mkdir = 27,
    Rmdir = 28,
    Unlink = 29,
    Readdir = 30,
    
    // 時間関連
    GetTime = 40,
    Sleep = 41,
    Nanosleep = 42,
    
    // ネットワーク
    Socket = 50,
    Bind = 51,
    Listen = 52,
    Accept = 53,
    Connect = 54,
    Send = 55,
    Recv = 56,
    
    // IPC
    SendMsg = 60,
    RecvMsg = 61,
    CreateChannel = 62,
    CloseChannel = 63,
    
    // システム情報
    Sysinfo = 70,
    Uname = 71,
    
    // セル管理
    CellCreate = 80,
    CellDestroy = 81,
    CellInfo = 82,
    
    // デバッグ
    Debug = 255,
}

impl TryFrom<u64> for SyscallNumber {
    type Error = SyscallError;
    
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SyscallNumber::Exit),
            1 => Ok(SyscallNumber::Yield),
            2 => Ok(SyscallNumber::GetPid),
            3 => Ok(SyscallNumber::Fork),
            4 => Ok(SyscallNumber::Exec),
            5 => Ok(SyscallNumber::Wait),
            10 => Ok(SyscallNumber::Mmap),
            11 => Ok(SyscallNumber::Munmap),
            12 => Ok(SyscallNumber::Mprotect),
            13 => Ok(SyscallNumber::Brk),
            20 => Ok(SyscallNumber::Open),
            21 => Ok(SyscallNumber::Close),
            22 => Ok(SyscallNumber::Read),
            23 => Ok(SyscallNumber::Write),
            24 => Ok(SyscallNumber::Seek),
            25 => Ok(SyscallNumber::Stat),
            26 => Ok(SyscallNumber::Fstat),
            27 => Ok(SyscallNumber::Mkdir),
            28 => Ok(SyscallNumber::Rmdir),
            29 => Ok(SyscallNumber::Unlink),
            30 => Ok(SyscallNumber::Readdir),
            40 => Ok(SyscallNumber::GetTime),
            41 => Ok(SyscallNumber::Sleep),
            42 => Ok(SyscallNumber::Nanosleep),
            50 => Ok(SyscallNumber::Socket),
            51 => Ok(SyscallNumber::Bind),
            52 => Ok(SyscallNumber::Listen),
            53 => Ok(SyscallNumber::Accept),
            54 => Ok(SyscallNumber::Connect),
            55 => Ok(SyscallNumber::Send),
            56 => Ok(SyscallNumber::Recv),
            60 => Ok(SyscallNumber::SendMsg),
            61 => Ok(SyscallNumber::RecvMsg),
            62 => Ok(SyscallNumber::CreateChannel),
            63 => Ok(SyscallNumber::CloseChannel),
            70 => Ok(SyscallNumber::Sysinfo),
            71 => Ok(SyscallNumber::Uname),
            80 => Ok(SyscallNumber::CellCreate),
            81 => Ok(SyscallNumber::CellDestroy),
            82 => Ok(SyscallNumber::CellInfo),
            255 => Ok(SyscallNumber::Debug),
            _ => Err(SyscallError::InvalidSyscall),
        }
    }
}

// ============================================================================
// システムコール結果
// ============================================================================

/// システムコール結果
pub type SyscallResult<T> = Result<T, SyscallError>;

/// システムコールエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum SyscallError {
    /// 成功（エラーなし）
    Success = 0,
    /// 不正なシステムコール番号
    InvalidSyscall = -1,
    /// 不正な引数
    InvalidArgument = -2,
    /// 権限不足
    PermissionDenied = -3,
    /// リソースが見つからない
    NotFound = -4,
    /// リソースが存在する
    AlreadyExists = -5,
    /// メモリ不足
    OutOfMemory = -6,
    /// バッファが小さすぎる
    BufferTooSmall = -7,
    /// 操作がブロックされる
    WouldBlock = -8,
    /// 割り込まれた
    Interrupted = -9,
    /// I/Oエラー
    IoError = -10,
    /// タイムアウト
    Timeout = -11,
    /// 操作はサポートされていない
    NotSupported = -12,
    /// 不正なハンドル
    InvalidHandle = -13,
    /// リソースがビジー
    Busy = -14,
    /// デッドロック回避
    Deadlock = -15,
    /// 名前が長すぎる
    NameTooLong = -16,
    /// ディレクトリが空でない
    NotEmpty = -17,
    /// ファイルが大きすぎる
    FileTooLarge = -18,
    /// 接続が拒否された
    ConnectionRefused = -19,
    /// 接続がリセットされた
    ConnectionReset = -20,
    /// 内部エラー
    InternalError = -99,
}

impl SyscallError {
    /// エラーコードから変換
    pub fn from_code(code: i64) -> Self {
        match code {
            0 => SyscallError::Success,
            -1 => SyscallError::InvalidSyscall,
            -2 => SyscallError::InvalidArgument,
            -3 => SyscallError::PermissionDenied,
            -4 => SyscallError::NotFound,
            -5 => SyscallError::AlreadyExists,
            -6 => SyscallError::OutOfMemory,
            -7 => SyscallError::BufferTooSmall,
            -8 => SyscallError::WouldBlock,
            -9 => SyscallError::Interrupted,
            -10 => SyscallError::IoError,
            -11 => SyscallError::Timeout,
            -12 => SyscallError::NotSupported,
            -13 => SyscallError::InvalidHandle,
            -14 => SyscallError::Busy,
            -15 => SyscallError::Deadlock,
            -16 => SyscallError::NameTooLong,
            -17 => SyscallError::NotEmpty,
            -18 => SyscallError::FileTooLarge,
            -19 => SyscallError::ConnectionRefused,
            -20 => SyscallError::ConnectionReset,
            _ => SyscallError::InternalError,
        }
    }
}

// ============================================================================
// システムコールコンテキスト
// ============================================================================

/// システムコールの引数
#[derive(Debug, Clone)]
pub struct SyscallArgs {
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
}

impl SyscallArgs {
    /// 新しい引数セットを作成
    pub const fn new() -> Self {
        Self {
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        }
    }
    
    /// 引数を設定
    pub fn with_args(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> Self {
        Self {
            arg0: a0,
            arg1: a1,
            arg2: a2,
            arg3: a3,
            arg4: a4,
            arg5: a5,
        }
    }
}

/// システムコールの戻り値
#[derive(Debug, Clone)]
pub struct SyscallReturn {
    pub value: i64,
    pub extra: u64,
}

impl SyscallReturn {
    /// 成功を返す
    pub fn success(value: i64) -> Self {
        Self { value, extra: 0 }
    }
    
    /// エラーを返す
    pub fn error(err: SyscallError) -> Self {
        Self {
            value: err as i64,
            extra: 0,
        }
    }
}

// ============================================================================
// システムコールハンドラ
// ============================================================================

/// システムコールディスパッチャ
pub fn dispatch(syscall_num: u64, args: &SyscallArgs) -> SyscallReturn {
    let syscall = match SyscallNumber::try_from(syscall_num) {
        Ok(s) => s,
        Err(e) => return SyscallReturn::error(e),
    };
    
    match syscall {
        SyscallNumber::Exit => sys_exit(args.arg0 as i32),
        SyscallNumber::Yield => sys_yield(),
        SyscallNumber::GetPid => sys_getpid(),
        SyscallNumber::GetTime => sys_gettime(),
        SyscallNumber::Sleep => sys_sleep(args.arg0),
        SyscallNumber::Sysinfo => sys_sysinfo(args.arg0 as *mut SysInfo),
        SyscallNumber::Debug => sys_debug(args.arg0, args.arg1),
        _ => SyscallReturn::error(SyscallError::NotSupported),
    }
}

// ============================================================================
// 個別システムコール実装
// ============================================================================

/// プロセス終了
fn sys_exit(code: i32) -> SyscallReturn {
    crate::log!("[SYSCALL] exit({})\n", code);
    // 実際の実装ではタスクを終了させる
    SyscallReturn::success(0)
}

/// CPUを譲る
fn sys_yield() -> SyscallReturn {
    // SPL環境では非同期yieldを使用
    // 注: 同期コンテキストからの呼び出しなのでスピンループでyieldをシミュレート
    core::hint::spin_loop();
    SyscallReturn::success(0)
}

/// プロセスIDを取得
fn sys_getpid() -> SyscallReturn {
    // 現在のタスクIDを返す
    // TODO: 実際のタスクID管理を実装
    SyscallReturn::success(1)
}

/// 現在時刻を取得（ナノ秒）
fn sys_gettime() -> SyscallReturn {
    let ticks = crate::task::timer::current_tick();
    let ns = ticks * 1_000_000; // 1msを1_000_000nsとして
    SyscallReturn::success(ns as i64)
}

/// スリープ（ミリ秒）
fn sys_sleep(ms: u64) -> SyscallReturn {
    // TODO: 実際のスリープ実装
    crate::log!("[SYSCALL] sleep({}ms)\n", ms);
    SyscallReturn::success(0)
}

/// システム情報を取得
fn sys_sysinfo(info_ptr: *mut SysInfo) -> SyscallReturn {
    if info_ptr.is_null() {
        return SyscallReturn::error(SyscallError::InvalidArgument);
    }
    
    let info = SysInfo {
        total_memory: 128 * 1024 * 1024, // 128MB（仮）
        free_memory: 64 * 1024 * 1024,   // 64MB（仮）
        uptime_ms: crate::task::timer::current_tick(),
        num_cpus: 1,
        load_average: [0, 0, 0],
    };
    
    unsafe {
        core::ptr::write(info_ptr, info);
    }
    
    SyscallReturn::success(0)
}

/// デバッグ出力
fn sys_debug(arg0: u64, arg1: u64) -> SyscallReturn {
    crate::log!("[SYSCALL] debug: 0x{:X}, 0x{:X}\n", arg0, arg1);
    SyscallReturn::success(0)
}

// ============================================================================
// システム情報構造体
// ============================================================================

/// システム情報
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SysInfo {
    /// 総メモリ（バイト）
    pub total_memory: u64,
    /// 空きメモリ（バイト）
    pub free_memory: u64,
    /// 稼働時間（ミリ秒）
    pub uptime_ms: u64,
    /// CPU数
    pub num_cpus: u32,
    /// ロードアベレージ（1, 5, 15分）
    pub load_average: [u32; 3],
}

// ============================================================================
// 非同期システムコール
// ============================================================================

/// 非同期ファイル読み取り
pub struct AsyncRead {
    fd: i32,
    buffer: *mut u8,
    len: usize,
    completed: bool,
    result: Option<SyscallResult<usize>>,
}

impl AsyncRead {
    /// 新しい非同期読み取りを作成
    pub fn new(fd: i32, buffer: *mut u8, len: usize) -> Self {
        Self {
            fd,
            buffer,
            len,
            completed: false,
            result: None,
        }
    }
}

impl Future for AsyncRead {
    type Output = SyscallResult<usize>;
    
    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.completed {
            return Poll::Ready(self.result.take().unwrap_or(Err(SyscallError::InternalError)));
        }
        
        // TODO: 実際の非同期読み取り実装
        // ここでは即座に完了を返す
        self.completed = true;
        self.result = Some(Ok(0));
        
        Poll::Ready(Ok(0))
    }
}

/// 非同期ファイル書き込み
pub struct AsyncWrite {
    fd: i32,
    buffer: *const u8,
    len: usize,
    completed: bool,
    result: Option<SyscallResult<usize>>,
}

impl AsyncWrite {
    /// 新しい非同期書き込みを作成
    pub fn new(fd: i32, buffer: *const u8, len: usize) -> Self {
        Self {
            fd,
            buffer,
            len,
            completed: false,
            result: None,
        }
    }
}

impl Future for AsyncWrite {
    type Output = SyscallResult<usize>;
    
    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.completed {
            return Poll::Ready(self.result.take().unwrap_or(Err(SyscallError::InternalError)));
        }
        
        // TODO: 実際の非同期書き込み実装
        self.completed = true;
        self.result = Some(Ok(self.len));
        
        Poll::Ready(Ok(self.len))
    }
}

// ============================================================================
// ユーザー向けAPI
// ============================================================================

/// プロセスを終了
pub fn exit(code: i32) -> ! {
    let args = SyscallArgs::with_args(code as u64, 0, 0, 0, 0, 0);
    dispatch(SyscallNumber::Exit as u64, &args);
    loop {
        core::hint::spin_loop();
    }
}

/// CPUを譲る
pub fn yield_now() {
    let args = SyscallArgs::new();
    dispatch(SyscallNumber::Yield as u64, &args);
}

/// プロセスIDを取得
pub fn getpid() -> i32 {
    let args = SyscallArgs::new();
    let ret = dispatch(SyscallNumber::GetPid as u64, &args);
    ret.value as i32
}

/// 現在時刻を取得（ナノ秒）
pub fn gettime() -> u64 {
    let args = SyscallArgs::new();
    let ret = dispatch(SyscallNumber::GetTime as u64, &args);
    ret.value as u64
}

/// スリープ（ミリ秒）
pub fn sleep(ms: u64) {
    let args = SyscallArgs::with_args(ms, 0, 0, 0, 0, 0);
    dispatch(SyscallNumber::Sleep as u64, &args);
}

/// システム情報を取得
pub fn sysinfo() -> SyscallResult<SysInfo> {
    let mut info = SysInfo {
        total_memory: 0,
        free_memory: 0,
        uptime_ms: 0,
        num_cpus: 0,
        load_average: [0; 3],
    };
    
    let args = SyscallArgs::with_args(&mut info as *mut SysInfo as u64, 0, 0, 0, 0, 0);
    let ret = dispatch(SyscallNumber::Sysinfo as u64, &args);
    
    if ret.value >= 0 {
        Ok(info)
    } else {
        Err(SyscallError::from_code(ret.value))
    }
}

/// デバッグ出力
pub fn debug(arg0: u64, arg1: u64) {
    let args = SyscallArgs::with_args(arg0, arg1, 0, 0, 0, 0);
    dispatch(SyscallNumber::Debug as u64, &args);
}

// ============================================================================
// 初期化
// ============================================================================

/// システムコールサブシステムを初期化
pub fn init() {
    crate::log!("[SYSCALL] System call interface initialized\n");
}
