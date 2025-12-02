//! USB (Universal Serial Bus) スタック
//! 
//! ExoRust用のUSBホストコントローラドライバとデバイス管理
//! - xHCI (USB 3.x) コントローラサポート
//! - USBデバイス列挙と設定
//! - 非同期転送API

use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};
use spin::RwLock;

// =============================================================================
// USB定数
// =============================================================================

/// USB速度
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UsbSpeed {
    /// Low Speed (1.5 Mbps)
    Low = 1,
    /// Full Speed (12 Mbps)
    Full = 2,
    /// High Speed (480 Mbps)
    High = 3,
    /// Super Speed (5 Gbps)
    Super = 4,
    /// Super Speed Plus (10 Gbps)
    SuperPlus = 5,
}

impl UsbSpeed {
    pub fn max_packet_size(&self) -> u16 {
        match self {
            UsbSpeed::Low => 8,
            UsbSpeed::Full => 64,
            UsbSpeed::High => 512,
            UsbSpeed::Super | UsbSpeed::SuperPlus => 1024,
        }
    }
}

/// USB転送タイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransferType {
    Control = 0,
    Isochronous = 1,
    Bulk = 2,
    Interrupt = 3,
}

/// USB方向
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    Out = 0,
    In = 1,
}

/// USBエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbError {
    /// デバイスが見つからない
    DeviceNotFound,
    /// エンドポイントが見つからない
    EndpointNotFound,
    /// 転送エラー
    TransferError,
    /// タイムアウト
    Timeout,
    /// ストール
    Stall,
    /// バッファオーバーラン
    BufferOverrun,
    /// 無効なパラメータ
    InvalidParameter,
    /// リソース不足
    NoResources,
    /// プロトコルエラー
    ProtocolError,
    /// デバイスが切断された
    Disconnected,
    /// コントローラエラー
    ControllerError,
}

pub type UsbResult<T> = Result<T, UsbError>;

// =============================================================================
// USBディスクリプタ
// =============================================================================

/// デバイスディスクリプタ
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct DeviceDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub usb_version: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub max_packet_size0: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_version: u16,
    pub manufacturer_index: u8,
    pub product_index: u8,
    pub serial_number_index: u8,
    pub num_configurations: u8,
}

/// コンフィグレーションディスクリプタ
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct ConfigurationDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub total_length: u16,
    pub num_interfaces: u8,
    pub configuration_value: u8,
    pub configuration_index: u8,
    pub attributes: u8,
    pub max_power: u8,
}

/// インターフェースディスクリプタ
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct InterfaceDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub num_endpoints: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub interface_index: u8,
}

/// エンドポイントディスクリプタ
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct EndpointDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub endpoint_address: u8,
    pub attributes: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

impl EndpointDescriptor {
    pub fn number(&self) -> u8 {
        self.endpoint_address & 0x0F
    }
    
    pub fn direction(&self) -> Direction {
        if self.endpoint_address & 0x80 != 0 {
            Direction::In
        } else {
            Direction::Out
        }
    }
    
    pub fn transfer_type(&self) -> TransferType {
        match self.attributes & 0x03 {
            0 => TransferType::Control,
            1 => TransferType::Isochronous,
            2 => TransferType::Bulk,
            3 => TransferType::Interrupt,
            _ => unreachable!(),
        }
    }
}

// =============================================================================
// USBセットアップパケット
// =============================================================================

/// セットアップパケット
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SetupPacket {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

impl SetupPacket {
    pub const fn new(request_type: u8, request: u8, value: u16, index: u16, length: u16) -> Self {
        Self {
            request_type,
            request,
            value,
            index,
            length,
        }
    }
    
    /// GET_DESCRIPTOR リクエスト
    pub fn get_descriptor(desc_type: u8, desc_index: u8, length: u16) -> Self {
        Self::new(
            0x80, // Device to Host, Standard, Device
            6,    // GET_DESCRIPTOR
            ((desc_type as u16) << 8) | (desc_index as u16),
            0,
            length,
        )
    }
    
    /// SET_ADDRESS リクエスト
    pub fn set_address(address: u8) -> Self {
        Self::new(
            0x00, // Host to Device, Standard, Device
            5,    // SET_ADDRESS
            address as u16,
            0,
            0,
        )
    }
    
    /// SET_CONFIGURATION リクエスト
    pub fn set_configuration(config: u8) -> Self {
        Self::new(
            0x00, // Host to Device, Standard, Device
            9,    // SET_CONFIGURATION
            config as u16,
            0,
            0,
        )
    }
}

// =============================================================================
// xHCI コントローラ
// =============================================================================

/// xHCIケーパビリティレジスタオフセット
mod xhci_cap {
    pub const CAPLENGTH: usize = 0x00;
    pub const HCIVERSION: usize = 0x02;
    pub const HCSPARAMS1: usize = 0x04;
    pub const HCSPARAMS2: usize = 0x08;
    pub const HCSPARAMS3: usize = 0x0C;
    pub const HCCPARAMS1: usize = 0x10;
    pub const DBOFF: usize = 0x14;
    pub const RTSOFF: usize = 0x18;
    pub const HCCPARAMS2: usize = 0x1C;
}

/// xHCI操作レジスタオフセット
mod xhci_op {
    pub const USBCMD: usize = 0x00;
    pub const USBSTS: usize = 0x04;
    pub const PAGESIZE: usize = 0x08;
    pub const DNCTRL: usize = 0x14;
    pub const CRCR: usize = 0x18;
    pub const DCBAAP: usize = 0x30;
    pub const CONFIG: usize = 0x38;
}

/// xHCIコマンド
mod xhci_cmd {
    pub const RUN_STOP: u32 = 1 << 0;
    pub const HCRST: u32 = 1 << 1;
    pub const INTE: u32 = 1 << 2;
    pub const HSEE: u32 = 1 << 3;
}

/// xHCIステータス
mod xhci_sts {
    pub const HCH: u32 = 1 << 0;
    pub const HSE: u32 = 1 << 2;
    pub const EINT: u32 = 1 << 3;
    pub const PCD: u32 = 1 << 4;
    pub const CNR: u32 = 1 << 11;
}

/// TRB (Transfer Request Block) タイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrbType {
    Normal = 1,
    SetupStage = 2,
    DataStage = 3,
    StatusStage = 4,
    Isoch = 5,
    Link = 6,
    EventData = 7,
    NoOp = 8,
    EnableSlot = 9,
    DisableSlot = 10,
    AddressDevice = 11,
    ConfigureEndpoint = 12,
    EvaluateContext = 13,
    ResetEndpoint = 14,
    StopEndpoint = 15,
    SetTrDequeue = 16,
    ResetDevice = 17,
    ForceEvent = 18,
    NegotiateBandwidth = 19,
    SetLatencyTolerance = 20,
    GetPortBandwidth = 21,
    ForceHeader = 22,
    NoOpCommand = 23,
    TransferEvent = 32,
    CommandCompletion = 33,
    PortStatusChange = 34,
    BandwidthRequest = 35,
    Doorbell = 36,
    HostController = 37,
    DeviceNotification = 38,
    MfindexWrap = 39,
}

/// TRB構造
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Trb {
    pub parameter: u64,
    pub status: u32,
    pub control: u32,
}

impl Trb {
    pub const fn new() -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: 0,
        }
    }
    
    pub fn set_type(&mut self, trb_type: TrbType) {
        self.control = (self.control & !0xFC00) | ((trb_type as u32) << 10);
    }
    
    pub fn get_type(&self) -> u8 {
        ((self.control >> 10) & 0x3F) as u8
    }
    
    pub fn set_cycle(&mut self, cycle: bool) {
        if cycle {
            self.control |= 1;
        } else {
            self.control &= !1;
        }
    }
    
    pub fn cycle(&self) -> bool {
        self.control & 1 != 0
    }
}

/// リング構造（コマンド/転送/イベント）
pub struct Ring {
    trbs: *mut Trb,
    size: usize,
    enqueue: usize,
    dequeue: usize,
    cycle_bit: bool,
    physical_addr: u64,
}

// SAFETY: Ring is only accessed from one core at a time with proper synchronization
unsafe impl Send for Ring {}
unsafe impl Sync for Ring {}

impl Ring {
    pub unsafe fn new(size: usize) -> Self {
        use core::alloc::Layout;
        
        let layout = Layout::from_size_align(
            size * core::mem::size_of::<Trb>(),
            4096,
        ).unwrap();
        
        let ptr = alloc::alloc::alloc_zeroed(layout) as *mut Trb;
        
        Self {
            trbs: ptr,
            size,
            enqueue: 0,
            dequeue: 0,
            cycle_bit: true,
            physical_addr: ptr as u64,
        }
    }
    
    pub fn enqueue_trb(&mut self, mut trb: Trb) -> &mut Trb {
        trb.set_cycle(self.cycle_bit);
        
        unsafe {
            let slot = self.trbs.add(self.enqueue);
            core::ptr::write_volatile(slot, trb);
            
            self.enqueue += 1;
            if self.enqueue >= self.size - 1 {
                // リンクTRBを設定
                let link = self.trbs.add(self.size - 1);
                (*link).parameter = self.physical_addr;
                (*link).control = (TrbType::Link as u32) << 10;
                if self.cycle_bit {
                    (*link).control |= 1;
                }
                (*link).control |= 1 << 1; // Toggle Cycle
                
                self.enqueue = 0;
                self.cycle_bit = !self.cycle_bit;
            }
            
            &mut *slot
        }
    }
    
    pub fn dequeue_trb(&mut self) -> Option<Trb> {
        unsafe {
            let slot = self.trbs.add(self.dequeue);
            let trb = core::ptr::read_volatile(slot);
            
            if trb.cycle() != self.cycle_bit {
                return None;
            }
            
            self.dequeue += 1;
            if self.dequeue >= self.size {
                self.dequeue = 0;
                self.cycle_bit = !self.cycle_bit;
            }
            
            Some(trb)
        }
    }
}

/// スロット状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    Disabled,
    Default,
    Addressed,
    Configured,
}

/// デバイススロット
pub struct DeviceSlot {
    pub slot_id: u8,
    pub state: SlotState,
    pub port: u8,
    pub speed: UsbSpeed,
    pub device_descriptor: Option<DeviceDescriptor>,
    pub configuration: Option<u8>,
    pub endpoints: [Option<EndpointDescriptor>; 31],
}

impl DeviceSlot {
    pub fn new(slot_id: u8, port: u8, speed: UsbSpeed) -> Self {
        Self {
            slot_id,
            state: SlotState::Disabled,
            port,
            speed,
            device_descriptor: None,
            configuration: None,
            endpoints: [None; 31],
        }
    }
}

/// xHCIコントローラ
pub struct XhciController {
    mmio_base: u64,
    cap_length: u8,
    max_slots: u8,
    max_ports: u8,
    page_size: u32,
    
    command_ring: Option<Ring>,
    event_ring: Option<Ring>,
    dcbaa: *mut u64,
    
    slots: [Option<Box<DeviceSlot>>; 256],
    
    initialized: AtomicBool,
    stats: XhciStats,
}

// SAFETY: XhciController is protected by a Mutex at the global level
unsafe impl Send for XhciController {}
unsafe impl Sync for XhciController {}

/// xHCI統計
#[derive(Debug, Default)]
pub struct XhciStats {
    pub commands_issued: AtomicU64,
    pub commands_completed: AtomicU64,
    pub transfers_completed: AtomicU64,
    pub transfer_errors: AtomicU64,
    pub port_changes: AtomicU64,
}

impl XhciController {
    pub const fn new(mmio_base: u64) -> Self {
        const NONE_SLOT: Option<Box<DeviceSlot>> = None;
        
        Self {
            mmio_base,
            cap_length: 0,
            max_slots: 0,
            max_ports: 0,
            page_size: 4096,
            command_ring: None,
            event_ring: None,
            dcbaa: core::ptr::null_mut(),
            slots: [NONE_SLOT; 256],
            initialized: AtomicBool::new(false),
            stats: XhciStats {
                commands_issued: AtomicU64::new(0),
                commands_completed: AtomicU64::new(0),
                transfers_completed: AtomicU64::new(0),
                transfer_errors: AtomicU64::new(0),
                port_changes: AtomicU64::new(0),
            },
        }
    }
    
    unsafe fn read32(&self, offset: usize) -> u32 {
        core::ptr::read_volatile((self.mmio_base as *const u8).add(offset) as *const u32)
    }
    
    unsafe fn write32(&self, offset: usize, value: u32) {
        core::ptr::write_volatile((self.mmio_base as *mut u8).add(offset) as *mut u32, value);
    }
    
    unsafe fn read64(&self, offset: usize) -> u64 {
        core::ptr::read_volatile((self.mmio_base as *const u8).add(offset) as *const u64)
    }
    
    unsafe fn write64(&self, offset: usize, value: u64) {
        core::ptr::write_volatile((self.mmio_base as *mut u8).add(offset) as *mut u64, value);
    }
    
    fn op_base(&self) -> usize {
        self.cap_length as usize
    }
    
    /// コントローラを初期化
    pub unsafe fn init(&mut self) -> UsbResult<()> {
        // ケーパビリティレジスタを読み取り
        self.cap_length = self.read32(xhci_cap::CAPLENGTH) as u8;
        let hcsparams1 = self.read32(xhci_cap::HCSPARAMS1);
        
        self.max_slots = (hcsparams1 & 0xFF) as u8;
        self.max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;
        
        let page_size = self.read32(self.op_base() + xhci_op::PAGESIZE);
        self.page_size = 1 << (page_size.trailing_zeros() + 12);
        
        // コントローラをリセット
        self.reset()?;
        
        // DCBAAを割り当て
        self.allocate_dcbaa()?;
        
        // コマンドリングを作成
        self.command_ring = Some(Ring::new(256));
        
        // イベントリングを作成
        self.event_ring = Some(Ring::new(256));
        
        // コントローラを設定
        self.configure()?;
        
        // コントローラを開始
        self.start()?;
        
        self.initialized.store(true, Ordering::SeqCst);
        
        Ok(())
    }
    
    unsafe fn reset(&mut self) -> UsbResult<()> {
        let op_base = self.op_base();
        
        // 停止
        let cmd = self.read32(op_base + xhci_op::USBCMD);
        self.write32(op_base + xhci_op::USBCMD, cmd & !xhci_cmd::RUN_STOP);
        
        // 停止を待機
        for _ in 0..1000 {
            if self.read32(op_base + xhci_op::USBSTS) & xhci_sts::HCH != 0 {
                break;
            }
            core::hint::spin_loop();
        }
        
        // リセット
        self.write32(op_base + xhci_op::USBCMD, xhci_cmd::HCRST);
        
        // リセット完了を待機
        for _ in 0..1000 {
            let cmd = self.read32(op_base + xhci_op::USBCMD);
            let sts = self.read32(op_base + xhci_op::USBSTS);
            if cmd & xhci_cmd::HCRST == 0 && sts & xhci_sts::CNR == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        
        Err(UsbError::ControllerError)
    }
    
    unsafe fn allocate_dcbaa(&mut self) -> UsbResult<()> {
        use core::alloc::Layout;
        
        let size = (self.max_slots as usize + 1) * 8;
        let layout = Layout::from_size_align(size, 64).unwrap();
        self.dcbaa = alloc::alloc::alloc_zeroed(layout) as *mut u64;
        
        if self.dcbaa.is_null() {
            return Err(UsbError::NoResources);
        }
        
        // DCBAAPを設定
        let op_base = self.op_base();
        self.write64(op_base + xhci_op::DCBAAP, self.dcbaa as u64);
        
        Ok(())
    }
    
    unsafe fn configure(&mut self) -> UsbResult<()> {
        let op_base = self.op_base();
        
        // 有効スロット数を設定
        self.write32(op_base + xhci_op::CONFIG, self.max_slots as u32);
        
        // コマンドリングを設定
        if let Some(ref ring) = self.command_ring {
            self.write64(op_base + xhci_op::CRCR, ring.physical_addr | 1);
        }
        
        Ok(())
    }
    
    unsafe fn start(&mut self) -> UsbResult<()> {
        let op_base = self.op_base();
        
        // 割り込みを有効化してコントローラを開始
        let cmd = self.read32(op_base + xhci_op::USBCMD);
        self.write32(
            op_base + xhci_op::USBCMD,
            cmd | xhci_cmd::RUN_STOP | xhci_cmd::INTE,
        );
        
        // 開始を確認
        for _ in 0..1000 {
            if self.read32(op_base + xhci_op::USBSTS) & xhci_sts::HCH == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        
        Err(UsbError::ControllerError)
    }
    
    /// ポートステータスを取得
    pub fn port_status(&self, port: u8) -> u32 {
        if port == 0 || port > self.max_ports {
            return 0;
        }
        
        let port_offset = 0x400 + (port as usize - 1) * 0x10;
        unsafe { self.read32(self.op_base() + port_offset) }
    }
    
    /// デバイスを列挙
    pub fn enumerate_devices(&mut self) -> UsbResult<Vec<u8>> {
        let mut devices = Vec::new();
        
        for port in 1..=self.max_ports {
            let status = self.port_status(port);
            
            // Current Connect Status
            if status & 1 != 0 {
                // Port Enabled
                if status & (1 << 1) != 0 {
                    if let Ok(slot_id) = self.enable_slot() {
                        devices.push(slot_id);
                    }
                }
            }
        }
        
        Ok(devices)
    }
    
    fn enable_slot(&mut self) -> UsbResult<u8> {
        let ring = self.command_ring.as_mut().ok_or(UsbError::ControllerError)?;
        
        let mut trb = Trb::new();
        trb.set_type(TrbType::EnableSlot);
        ring.enqueue_trb(trb);
        
        self.stats.commands_issued.fetch_add(1, Ordering::Relaxed);
        
        // ドアベルを鳴らす
        self.ring_doorbell(0, 0);
        
        // 完了を待機（実際には非同期で処理すべき）
        // ここでは簡略化のため同期的に待機
        for _ in 0..10000 {
            if let Some(event) = self.poll_event() {
                if event.get_type() == TrbType::CommandCompletion as u8 {
                    let slot_id = ((event.control >> 24) & 0xFF) as u8;
                    self.stats.commands_completed.fetch_add(1, Ordering::Relaxed);
                    return Ok(slot_id);
                }
            }
            core::hint::spin_loop();
        }
        
        Err(UsbError::Timeout)
    }
    
    fn ring_doorbell(&self, slot: u8, target: u8) {
        let db_offset = unsafe { self.read32(xhci_cap::DBOFF) } as usize;
        let doorbell = self.mmio_base as usize + db_offset + (slot as usize * 4);
        unsafe {
            core::ptr::write_volatile(doorbell as *mut u32, target as u32);
        }
    }
    
    fn poll_event(&mut self) -> Option<Trb> {
        self.event_ring.as_mut()?.dequeue_trb()
    }
    
    /// 統計を取得
    pub fn stats(&self) -> &XhciStats {
        &self.stats
    }
}

// =============================================================================
// USBデバイスマネージャ
// =============================================================================

/// USBデバイス情報
#[derive(Debug, Clone)]
pub struct UsbDeviceInfo {
    pub slot_id: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub speed: UsbSpeed,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
}

/// USBマネージャ
pub struct UsbManager {
    controllers: Vec<Arc<RwLock<XhciController>>>,
    devices: RwLock<Vec<UsbDeviceInfo>>,
}

impl UsbManager {
    pub const fn new() -> Self {
        Self {
            controllers: Vec::new(),
            devices: RwLock::new(Vec::new()),
        }
    }
    
    /// xHCIコントローラを追加
    pub fn add_controller(&mut self, mmio_base: u64) -> UsbResult<()> {
        let mut controller = XhciController::new(mmio_base);
        unsafe { controller.init()? };
        
        self.controllers.push(Arc::new(RwLock::new(controller)));
        Ok(())
    }
    
    /// 全デバイスを列挙
    pub fn enumerate_all(&self) -> UsbResult<Vec<UsbDeviceInfo>> {
        let mut all_devices = Vec::new();
        
        for controller in &self.controllers {
            let mut ctrl = controller.write();
            let slot_ids = ctrl.enumerate_devices()?;
            
            for slot_id in slot_ids {
                all_devices.push(UsbDeviceInfo {
                    slot_id,
                    vendor_id: 0,
                    product_id: 0,
                    device_class: 0,
                    device_subclass: 0,
                    speed: UsbSpeed::High,
                    manufacturer: None,
                    product: None,
                });
            }
        }
        
        *self.devices.write() = all_devices.clone();
        Ok(all_devices)
    }
    
    /// デバイス一覧を取得
    pub fn devices(&self) -> Vec<UsbDeviceInfo> {
        self.devices.read().clone()
    }
}

// =============================================================================
// USBクラスドライバ
// =============================================================================

/// USBクラスドライバトレイト
pub trait UsbClassDriver: Send + Sync {
    /// ドライバ名
    fn name(&self) -> &'static str;
    
    /// このドライバがデバイスをサポートするか
    fn supports(&self, info: &UsbDeviceInfo) -> bool;
    
    /// デバイスにアタッチ
    fn attach(&mut self, slot_id: u8) -> UsbResult<()>;
    
    /// デバイスからデタッチ
    fn detach(&mut self, slot_id: u8) -> UsbResult<()>;
}

/// USBマスストレージクラスドライバ
pub struct UsbMassStorage {
    attached_slots: Vec<u8>,
}

impl UsbMassStorage {
    pub const fn new() -> Self {
        Self {
            attached_slots: Vec::new(),
        }
    }
}

impl UsbClassDriver for UsbMassStorage {
    fn name(&self) -> &'static str {
        "USB Mass Storage"
    }
    
    fn supports(&self, info: &UsbDeviceInfo) -> bool {
        info.device_class == 0x08 // Mass Storage Class
    }
    
    fn attach(&mut self, slot_id: u8) -> UsbResult<()> {
        self.attached_slots.push(slot_id);
        Ok(())
    }
    
    fn detach(&mut self, slot_id: u8) -> UsbResult<()> {
        self.attached_slots.retain(|&s| s != slot_id);
        Ok(())
    }
}

/// USBキーボードドライバ（HID）
pub struct UsbKeyboard {
    attached_slots: Vec<u8>,
    key_buffer: [u8; 8],
}

impl UsbKeyboard {
    pub const fn new() -> Self {
        Self {
            attached_slots: Vec::new(),
            key_buffer: [0; 8],
        }
    }
    
    /// キーバッファを読み取り
    pub fn read_keys(&self) -> &[u8] {
        &self.key_buffer
    }
}

impl UsbClassDriver for UsbKeyboard {
    fn name(&self) -> &'static str {
        "USB Keyboard (HID)"
    }
    
    fn supports(&self, info: &UsbDeviceInfo) -> bool {
        info.device_class == 0x03 && info.device_subclass == 0x01
    }
    
    fn attach(&mut self, slot_id: u8) -> UsbResult<()> {
        self.attached_slots.push(slot_id);
        Ok(())
    }
    
    fn detach(&mut self, slot_id: u8) -> UsbResult<()> {
        self.attached_slots.retain(|&s| s != slot_id);
        Ok(())
    }
}

// =============================================================================
// グローバルインスタンス
// =============================================================================

static USB_MANAGER: spin::Once<RwLock<UsbManager>> = spin::Once::new();

pub fn usb_manager() -> &'static RwLock<UsbManager> {
    USB_MANAGER.call_once(|| RwLock::new(UsbManager::new()))
}

/// USBサブシステムを初期化
pub fn init() {
    let _ = usb_manager();
}

/// xHCIコントローラを登録
pub fn register_xhci(mmio_base: u64) -> UsbResult<()> {
    usb_manager().write().add_controller(mmio_base)
}
