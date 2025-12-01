// ============================================================================
// src/io/virtio.rs - Async VirtIO Driver Example
// ============================================================================
use core::future::poll_fn;
use core::task::{Poll, Waker};
use core::sync::atomic::{AtomicBool, Ordering};
use alloc::vec::Vec;
use spin::Mutex;

/// 割り込みハンドラとドライバをつなぐ共有ステート
pub struct VirtioSharedState {
    pub waker: Mutex<Option<Waker>>,
    pub ready: AtomicBool,
}

impl VirtioSharedState {
    pub const fn new() -> Self {
        Self {
            waker: Mutex::new(None),
            ready: AtomicBool::new(false),
        }
    }
}

/// グローバルなネットワークデバイスステート
static NET_DEVICE_STATE: VirtioSharedState = VirtioSharedState::new();

/// 割り込みハンドラ (ISR)
/// 注意: x86_64::structures::idt::InterruptStackFrame を使う場合は
/// #![feature(abi_x86_interrupt)] が必要
/// 
/// この実装は概念を示すためのもの。実際のIDT設定は main.rs で行う
pub fn virtio_net_interrupt_handler() {
    // 1. 割り込み要因のクリア（ドライバ依存）
    // TODO: VirtIOレジスタからの読み取り処理
    
    // 2. フラグをセット
    NET_DEVICE_STATE.ready.store(true, Ordering::SeqCst);
    
    // 3. Wakerを起動
    // SpinlockはISR内で短期間なので許容される場合が多いが、
    // 本来は futures::task::AtomicWaker を推奨
    if let Some(waker) = NET_DEVICE_STATE.waker.lock().take() {
        waker.wake_by_ref();
    }
    
    // 4. EOI送信
    // TODO: APIC/PICへのEOI送信処理
}

/// 非同期パケット受信関数
/// poll_fn を使ってカスタムFutureを構築
pub async fn async_receive_packet() -> Vec<u8> {
    poll_fn(|cx| {
        if NET_DEVICE_STATE.ready.load(Ordering::SeqCst) {
            // パケット読み出し処理 (VirtIOリングからデータをコピーまたはRRef移動)
            NET_DEVICE_STATE.ready.store(false, Ordering::SeqCst);
            
            // TODO: 実際のVirtIOリングバッファからの読み取り
            // ここではダミーデータを返す
            return Poll::Ready(alloc::vec![0x45, 0x00, 0x00, 0x3c]); // IPv4 header start
        }
        
        // まだデータがないならWakerを登録
        let mut waker_guard = NET_DEVICE_STATE.waker.lock();
        *waker_guard = Some(cx.waker().clone());
        Poll::Pending
    }).await
}

/// 非同期パケット送信関数（例）
pub async fn async_send_packet(data: &[u8]) -> Result<(), &'static str> {
    // TODO: VirtIOの送信キューにデータを投入
    // ここでは単純にログ出力のみ
    crate::log!("Sending packet of {} bytes\n", data.len());
    Ok(())
}
