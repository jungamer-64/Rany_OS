//! VirtIO GPU ドライバ
//!
//! VirtIO GPUデバイスのサポート
//! - 2D/3D レンダリング
//! - ディスプレイ管理
//! - カーソル制御
//! - スキャンアウト

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::{Mutex, RwLock};

// =============================================================================
// 定数
// =============================================================================

/// VirtIO GPU フィーチャービット
const VIRTIO_GPU_F_VIRGL: u64 = 1 << 0; // Virgl 3Dサポート
const VIRTIO_GPU_F_EDID: u64 = 1 << 1; // EDID取得サポート
const VIRTIO_GPU_F_RESOURCE_UUID: u64 = 1 << 2; // リソースUUID
const VIRTIO_GPU_F_RESOURCE_BLOB: u64 = 1 << 3; // BLOBリソース

/// キューインデックス
const VIRTQUEUE_CTRL: u16 = 0;
const VIRTQUEUE_CURSOR: u16 = 1;

/// キューサイズ
const QUEUE_SIZE: u16 = 64;

/// 最大スキャンアウト数
const MAX_SCANOUTS: usize = 16;

// =============================================================================
// エラー
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuError {
    /// デバイスが見つからない
    DeviceNotFound,
    /// 初期化失敗
    InitFailed,
    /// リソースが見つからない
    ResourceNotFound,
    /// 無効なパラメータ
    InvalidParameter,
    /// メモリ不足
    OutOfMemory,
    /// デバイスエラー
    DeviceError,
    /// タイムアウト
    Timeout,
    /// サポートされていない
    NotSupported,
}

pub type GpuResult<T> = Result<T, GpuError>;

// =============================================================================
// GPU コマンド
// =============================================================================

/// コマンドタイプ
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuCmd {
    // 2D コマンド
    GetDisplayInfo = 0x0100,
    ResourceCreate2D = 0x0101,
    ResourceUnref = 0x0102,
    SetScanout = 0x0103,
    ResourceFlush = 0x0104,
    TransferToHost2D = 0x0105,
    ResourceAttachBacking = 0x0106,
    ResourceDetachBacking = 0x0107,
    GetCapsetInfo = 0x0108,
    GetCapset = 0x0109,
    GetEdid = 0x010A,

    // カーソル コマンド
    UpdateCursor = 0x0300,
    MoveCursor = 0x0301,

    // 3D コマンド (Virgl)
    CtxCreate = 0x0200,
    CtxDestroy = 0x0201,
    CtxAttachResource = 0x0202,
    CtxDetachResource = 0x0203,
    ResourceCreate3D = 0x0204,
    TransferToHost3D = 0x0205,
    TransferFromHost3D = 0x0206,
    Submit3D = 0x0207,

    // レスポンス
    RespOkNoData = 0x1100,
    RespOkDisplayInfo = 0x1101,
    RespOkCapsetInfo = 0x1102,
    RespOkCapset = 0x1103,
    RespOkEdid = 0x1104,
    RespErrUnspec = 0x1200,
    RespErrOutOfMemory = 0x1201,
    RespErrInvalidScanoutId = 0x1202,
    RespErrInvalidResourceId = 0x1203,
    RespErrInvalidCtxId = 0x1204,
    RespErrInvalidParameter = 0x1205,
}

/// コントロールヘッダ
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GpuCtrlHdr {
    pub cmd_type: u32,
    pub flags: u32,
    pub fence_id: u64,
    pub ctx_id: u32,
    pub _padding: u32,
}

impl GpuCtrlHdr {
    pub fn new(cmd_type: GpuCmd) -> Self {
        Self {
            cmd_type: cmd_type as u32,
            flags: 0,
            fence_id: 0,
            ctx_id: 0,
            _padding: 0,
        }
    }

    pub fn with_fence(mut self, fence_id: u64) -> Self {
        self.flags |= 1; // VIRTIO_GPU_FLAG_FENCE
        self.fence_id = fence_id;
        self
    }
}

// =============================================================================
// ディスプレイ情報
// =============================================================================

/// 長方形
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }
}

/// ディスプレイモード
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DisplayMode {
    pub rect: Rect,
    pub enabled: u32,
    pub flags: u32,
}

/// ディスプレイ情報レスポンス
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DisplayInfo {
    pub modes: [DisplayMode; MAX_SCANOUTS],
}

// =============================================================================
// リソース
// =============================================================================

/// ピクセルフォーマット
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    B8G8R8A8Unorm = 1,
    B8G8R8X8Unorm = 2,
    A8R8G8B8Unorm = 3,
    X8R8G8B8Unorm = 4,
    R8G8B8A8Unorm = 67,
    X8B8G8R8Unorm = 68,
    A8B8G8R8Unorm = 121,
    R8G8B8X8Unorm = 134,
}

/// 2Dリソース作成リクエスト
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ResourceCreate2D {
    pub hdr: GpuCtrlHdr,
    pub resource_id: u32,
    pub format: u32,
    pub width: u32,
    pub height: u32,
}

/// バッキングメモリエントリ
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemEntry {
    pub addr: u64,
    pub length: u32,
    pub _padding: u32,
}

/// バッキングアタッチリクエスト
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ResourceAttachBacking {
    pub hdr: GpuCtrlHdr,
    pub resource_id: u32,
    pub nr_entries: u32,
}

/// 2D転送リクエスト
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TransferToHost2D {
    pub hdr: GpuCtrlHdr,
    pub rect: Rect,
    pub offset: u64,
    pub resource_id: u32,
    pub _padding: u32,
}

/// スキャンアウト設定リクエスト
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SetScanout {
    pub hdr: GpuCtrlHdr,
    pub rect: Rect,
    pub scanout_id: u32,
    pub resource_id: u32,
}

/// リソースフラッシュリクエスト
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ResourceFlush {
    pub hdr: GpuCtrlHdr,
    pub rect: Rect,
    pub resource_id: u32,
    pub _padding: u32,
}

// =============================================================================
// カーソル
// =============================================================================

/// カーソル位置
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CursorPos {
    pub scanout_id: u32,
    pub x: u32,
    pub y: u32,
    pub _padding: u32,
}

/// カーソル更新リクエスト
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UpdateCursor {
    pub hdr: GpuCtrlHdr,
    pub pos: CursorPos,
    pub resource_id: u32,
    pub hot_x: u32,
    pub hot_y: u32,
    pub _padding: u32,
}

// =============================================================================
// フレームバッファ
// =============================================================================

/// フレームバッファ
pub struct Framebuffer {
    pub resource_id: u32,
    pub width: u32,
    pub height: u32,
    pub format: PixelFormat,
    pub buffer: Vec<u8>,
    pub stride: u32,
}

impl Framebuffer {
    pub fn new(resource_id: u32, width: u32, height: u32, format: PixelFormat) -> Self {
        let bpp = 4; // 32ビット
        let stride = width * bpp;
        let size = (stride * height) as usize;

        Self {
            resource_id,
            width,
            height,
            format,
            buffer: vec![0u8; size],
            stride,
        }
    }

    /// ピクセルを設定
    pub fn set_pixel(&mut self, x: u32, y: u32, color: u32) {
        if x >= self.width || y >= self.height {
            return;
        }

        let offset = ((y * self.stride) + (x * 4)) as usize;
        if offset + 4 <= self.buffer.len() {
            self.buffer[offset..offset + 4].copy_from_slice(&color.to_le_bytes());
        }
    }

    /// 領域をクリア
    pub fn clear(&mut self, color: u32) {
        let bytes = color.to_le_bytes();
        for chunk in self.buffer.chunks_exact_mut(4) {
            chunk.copy_from_slice(&bytes);
        }
    }

    /// 長方形を描画
    pub fn fill_rect(&mut self, rect: &Rect, color: u32) {
        let x_end = (rect.x + rect.width).min(self.width);
        let y_end = (rect.y + rect.height).min(self.height);

        for y in rect.y..y_end {
            for x in rect.x..x_end {
                self.set_pixel(x, y, color);
            }
        }
    }

    /// バッファポインタを取得
    pub fn as_ptr(&self) -> *const u8 {
        self.buffer.as_ptr()
    }

    /// バッファサイズを取得
    pub fn size(&self) -> usize {
        self.buffer.len()
    }
}

// =============================================================================
// VirtIO GPU デバイス
// =============================================================================

/// Virtqueueディスクリプタ
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

/// Virtqueue Availableリング
#[repr(C, align(2))]
#[derive(Debug)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; QUEUE_SIZE as usize],
}

/// Virtqueue Usedエレメント
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

/// VirtIO GPUデバイス
pub struct VirtioGpu {
    /// MMIO ベースアドレス
    base: u64,

    /// フィーチャービット
    features: u64,

    /// リソースID生成
    next_resource_id: AtomicU32,

    /// フェンスID生成
    next_fence_id: AtomicU32,

    /// ディスプレイ情報
    display_info: RwLock<Option<DisplayInfo>>,

    /// アクティブなスキャンアウト
    active_scanouts: RwLock<Vec<u32>>,

    /// フレームバッファ
    framebuffers: RwLock<Vec<Framebuffer>>,

    /// 初期化済みフラグ
    initialized: AtomicBool,

    /// 3Dサポート
    has_3d: bool,
}

impl VirtioGpu {
    /// 新しいVirtIO GPUデバイスを作成
    pub fn new(base: u64) -> Self {
        Self {
            base,
            features: 0,
            next_resource_id: AtomicU32::new(1),
            next_fence_id: AtomicU32::new(1),
            display_info: RwLock::new(None),
            active_scanouts: RwLock::new(Vec::new()),
            framebuffers: RwLock::new(Vec::new()),
            initialized: AtomicBool::new(false),
            has_3d: false,
        }
    }

    /// デバイスを初期化
    pub fn init(&mut self) -> GpuResult<()> {
        // VirtIOデバイス初期化シーケンス
        self.reset()?;
        self.acknowledge()?;
        self.negotiate_features()?;
        self.setup_queues()?;
        self.driver_ok()?;

        // ディスプレイ情報を取得
        self.get_display_info()?;

        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn reset(&self) -> GpuResult<()> {
        unsafe {
            let status = (self.base + 0x70) as *mut u32;
            core::ptr::write_volatile(status, 0);
        }
        Ok(())
    }

    fn acknowledge(&self) -> GpuResult<()> {
        unsafe {
            let status = (self.base + 0x70) as *mut u32;
            let current = core::ptr::read_volatile(status);
            core::ptr::write_volatile(status, current | 1); // ACKNOWLEDGE
        }
        Ok(())
    }

    fn negotiate_features(&mut self) -> GpuResult<()> {
        unsafe {
            // ホストフィーチャーを読み取り
            let feature_sel = (self.base + 0x14) as *mut u32;
            let feature = (self.base + 0x10) as *const u32;

            // Low 32 bits
            core::ptr::write_volatile(feature_sel, 0);
            let low = core::ptr::read_volatile(feature);

            // High 32 bits
            core::ptr::write_volatile(feature_sel, 1);
            let high = core::ptr::read_volatile(feature);

            let host_features = ((high as u64) << 32) | (low as u64);

            // サポートするフィーチャーを選択
            self.features = host_features & (VIRTIO_GPU_F_VIRGL | VIRTIO_GPU_F_EDID);
            self.has_3d = (self.features & VIRTIO_GPU_F_VIRGL) != 0;

            // ドライバフィーチャーを書き込み
            let driver_feature_sel = (self.base + 0x24) as *mut u32;
            let driver_feature = (self.base + 0x20) as *mut u32;

            core::ptr::write_volatile(driver_feature_sel, 0);
            core::ptr::write_volatile(driver_feature, self.features as u32);

            core::ptr::write_volatile(driver_feature_sel, 1);
            core::ptr::write_volatile(driver_feature, (self.features >> 32) as u32);

            // FEATURES_OK を設定
            let status = (self.base + 0x70) as *mut u32;
            let current = core::ptr::read_volatile(status);
            core::ptr::write_volatile(status, current | 8); // FEATURES_OK
        }
        Ok(())
    }

    fn setup_queues(&self) -> GpuResult<()> {
        // 簡略化: キュー設定はドライバ実装で行う
        Ok(())
    }

    fn driver_ok(&self) -> GpuResult<()> {
        unsafe {
            let status = (self.base + 0x70) as *mut u32;
            let current = core::ptr::read_volatile(status);
            core::ptr::write_volatile(status, current | 4); // DRIVER_OK
        }
        Ok(())
    }

    /// 新しいリソースIDを割り当て
    fn alloc_resource_id(&self) -> u32 {
        self.next_resource_id.fetch_add(1, Ordering::SeqCst)
    }

    /// 新しいフェンスIDを割り当て
    fn alloc_fence_id(&self) -> u32 {
        self.next_fence_id.fetch_add(1, Ordering::SeqCst)
    }

    /// ディスプレイ情報を取得
    pub fn get_display_info(&self) -> GpuResult<DisplayInfo> {
        // コマンドを送信（簡略化）
        // 実際の実装ではVirtqueueを使用

        let info = DisplayInfo {
            modes: [DisplayMode {
                rect: Rect::new(0, 0, 1920, 1080),
                enabled: 1,
                flags: 0,
            }; MAX_SCANOUTS],
        };

        *self.display_info.write() = Some(info.clone());
        Ok(info)
    }

    /// 2Dリソースを作成
    pub fn create_resource_2d(
        &self,
        width: u32,
        height: u32,
        format: PixelFormat,
    ) -> GpuResult<u32> {
        let resource_id = self.alloc_resource_id();

        let _req = ResourceCreate2D {
            hdr: GpuCtrlHdr::new(GpuCmd::ResourceCreate2D),
            resource_id,
            format: format as u32,
            width,
            height,
        };

        // コマンドを送信（簡略化）

        Ok(resource_id)
    }

    /// リソースを解放
    pub fn unref_resource(&self, _resource_id: u32) -> GpuResult<()> {
        // コマンドを送信（簡略化）
        Ok(())
    }

    /// バッキングメモリをアタッチ
    pub fn attach_backing(&self, _resource_id: u32, _addr: u64, _size: u32) -> GpuResult<()> {
        // コマンドを送信（簡略化）
        Ok(())
    }

    /// ホストに転送
    pub fn transfer_to_host_2d(
        &self,
        _resource_id: u32,
        _rect: &Rect,
        _offset: u64,
    ) -> GpuResult<()> {
        // コマンドを送信（簡略化）
        Ok(())
    }

    /// スキャンアウトを設定
    pub fn set_scanout(&self, scanout_id: u32, resource_id: u32, rect: &Rect) -> GpuResult<()> {
        let _req = SetScanout {
            hdr: GpuCtrlHdr::new(GpuCmd::SetScanout),
            rect: *rect,
            scanout_id,
            resource_id,
        };

        // コマンドを送信（簡略化）

        self.active_scanouts.write().push(scanout_id);
        Ok(())
    }

    /// リソースをフラッシュ
    pub fn flush(&self, _resource_id: u32, _rect: &Rect) -> GpuResult<()> {
        // コマンドを送信（簡略化）
        Ok(())
    }

    /// フレームバッファを作成
    pub fn create_framebuffer(&self, width: u32, height: u32) -> GpuResult<u32> {
        let format = PixelFormat::B8G8R8A8Unorm;

        // リソースを作成
        let resource_id = self.create_resource_2d(width, height, format)?;

        // フレームバッファを作成
        let fb = Framebuffer::new(resource_id, width, height, format);

        // バッキングメモリをアタッチ
        // 注: 実際の実装では物理アドレスが必要

        self.framebuffers.write().push(fb);

        Ok(resource_id)
    }

    /// フレームバッファを取得
    pub fn framebuffer(&self, resource_id: u32) -> Option<Framebuffer> {
        self.framebuffers
            .read()
            .iter()
            .find(|fb| fb.resource_id == resource_id)
            .cloned()
    }

    /// 画面を更新
    pub fn present(&self, resource_id: u32) -> GpuResult<()> {
        let fb = self
            .framebuffers
            .read()
            .iter()
            .find(|fb| fb.resource_id == resource_id)
            .cloned()
            .ok_or(GpuError::ResourceNotFound)?;

        let rect = Rect::new(0, 0, fb.width, fb.height);

        // ホストに転送
        self.transfer_to_host_2d(resource_id, &rect, 0)?;

        // フラッシュ
        self.flush(resource_id, &rect)?;

        Ok(())
    }

    /// カーソルを更新
    pub fn update_cursor(
        &self,
        resource_id: u32,
        scanout_id: u32,
        x: u32,
        y: u32,
        hot_x: u32,
        hot_y: u32,
    ) -> GpuResult<()> {
        let _req = UpdateCursor {
            hdr: GpuCtrlHdr::new(GpuCmd::UpdateCursor),
            pos: CursorPos {
                scanout_id,
                x,
                y,
                _padding: 0,
            },
            resource_id,
            hot_x,
            hot_y,
            _padding: 0,
        };

        // コマンドを送信（簡略化）
        Ok(())
    }

    /// カーソルを移動
    pub fn move_cursor(&self, scanout_id: u32, x: u32, y: u32) -> GpuResult<()> {
        let _req = UpdateCursor {
            hdr: GpuCtrlHdr::new(GpuCmd::MoveCursor),
            pos: CursorPos {
                scanout_id,
                x,
                y,
                _padding: 0,
            },
            resource_id: 0,
            hot_x: 0,
            hot_y: 0,
            _padding: 0,
        };

        // コマンドを送信（簡略化）
        Ok(())
    }

    /// 3Dサポートがあるか
    pub fn has_3d_support(&self) -> bool {
        self.has_3d
    }

    /// 初期化済みか
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Relaxed)
    }
}

impl Clone for Framebuffer {
    fn clone(&self) -> Self {
        Self {
            resource_id: self.resource_id,
            width: self.width,
            height: self.height,
            format: self.format,
            buffer: self.buffer.clone(),
            stride: self.stride,
        }
    }
}

// =============================================================================
// グラフィックスマネージャ
// =============================================================================

/// グラフィックスマネージャ
pub struct GraphicsManager {
    gpu: Mutex<Option<VirtioGpu>>,
    primary_scanout: AtomicU32,
    primary_framebuffer: AtomicU32,
}

impl GraphicsManager {
    pub const fn new() -> Self {
        Self {
            gpu: Mutex::new(None),
            primary_scanout: AtomicU32::new(0),
            primary_framebuffer: AtomicU32::new(0),
        }
    }

    /// 初期化
    pub fn init(&self, base: u64) -> GpuResult<()> {
        let mut gpu = VirtioGpu::new(base);
        gpu.init()?;

        // プライマリフレームバッファを作成
        let display_info = gpu.get_display_info()?;
        if let Some(mode) = display_info.modes.iter().find(|m| m.enabled != 0) {
            let fb_id = gpu.create_framebuffer(mode.rect.width, mode.rect.height)?;
            gpu.set_scanout(0, fb_id, &mode.rect)?;

            self.primary_framebuffer.store(fb_id, Ordering::SeqCst);
        }

        *self.gpu.lock() = Some(gpu);
        Ok(())
    }

    /// 画面をクリア
    pub fn clear(&self, color: u32) -> GpuResult<()> {
        let gpu = self.gpu.lock();
        let gpu = gpu.as_ref().ok_or(GpuError::DeviceNotFound)?;

        let fb_id = self.primary_framebuffer.load(Ordering::Relaxed);

        // フレームバッファを取得してクリア（簡略化）
        // 実際の実装ではミュータブルなアクセスが必要

        gpu.present(fb_id)?;
        Ok(())
    }

    /// 画面を更新
    pub fn present(&self) -> GpuResult<()> {
        let gpu = self.gpu.lock();
        let gpu = gpu.as_ref().ok_or(GpuError::DeviceNotFound)?;

        let fb_id = self.primary_framebuffer.load(Ordering::Relaxed);
        gpu.present(fb_id)
    }
}

// =============================================================================
// グローバルインスタンス
// =============================================================================

static GRAPHICS_MANAGER: spin::Once<GraphicsManager> = spin::Once::new();

pub fn graphics_manager() -> &'static GraphicsManager {
    GRAPHICS_MANAGER.call_once(GraphicsManager::new)
}

/// 初期化
pub fn init(base: u64) -> GpuResult<()> {
    graphics_manager().init(base)
}
