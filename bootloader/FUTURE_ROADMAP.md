# ExoLoader 将来機能実装ロードマップ

> ExoLoader v0.1.0 - UEFI Bootloader for RanyOS

## 現在の実装状態 ✅

### 完了済み機能

| 機能 | 状態 | 説明 |
|------|------|------|
| **UEFI ブート** | ✅ | UEFI環境での起動 |
| **ELF ローディング** | ✅ | xmas-elfによるPIE ELFパース |
| **PIE リロケーション** | ✅ | R_X86_64_RELATIVE対応 |
| **Ed25519 署名検証** | ✅ | ed25519-compactによるセキュアブート |
| **Higher-Half マッピング** | ✅ | KERNEL_BASE (0xFFFF_FFFF_8000_0000) |
| **HHDM (Higher Half Direct Map)** | ✅ | 0xFFFF_8000_0000_0000～物理メモリ |
| **Framebuffer 初期化** | ✅ | GOP経由、BGRA/RGBA対応 |
| **ACPI RSDP検出** | ✅ | ACPI2/ACPI1テーブル検索 |
| **Memory Map 引き渡し** | ✅ | ExoBootInfo経由 |
| **Initramfs ローディング** | ✅ | initramfs.tar（オプション） |
| **2MB/4KB ページマッピング** | ✅ | 混合ページサイズ対応 |

---

## Phase 1: パフォーマンス最適化 ✅

### 1.1 1GBページサポート ✅ 完了

**目的**: TLBエントリ消費を最小化し、大容量メモリシステムでのオーバーヘッドを削減

**実装内容**:

- `CpuPageFeatures::detect()` - CPUID経由でPSE/Page1GBサポートを検出
- `map_page_1gb()` - PDPTエントリに直接1GBページを設定
- HHDMマッピングで1GB > 2MB > 4KB の優先順位で自動選択
- ログ出力で使用ページ数を確認可能

```rust
// page_table.rs に実装済み
pub fn map_page_1gb(&mut self, virt: u64, phys: u64, flags: u64) -> Result<(), ()>
```

**実装タスク**:

- [x] 1GB Huge Page対応 (`PAGE_HUGE` on PDPT entry)
- [x] CPUID.01H:EDX[PSE] でPSE(2MB)、CPUID.80000001H:EDX[Page1GB] で1GBページ対応確認
- [x] HHDMマッピングで1GBページを優先使用
- [x] 1GBアライメント境界チェック

### 1.2 早期NUMA検出 ✅ 完了

**目的**: カーネルに起動時点でのNUMAトポロジを提供

**実装内容**:

- `numa.rs` モジュール追加
- ACPI RSDP → XSDT/RSDT → SRATテーブルのパース
- プロセッサアフィニティ（APIC ID）検出
- メモリアフィニティ（物理アドレス範囲）検出
- x2APICアフィニティ対応
- `NumaInfo`構造体をExoBootInfoに追加

```rust
// boot_proto/src/lib.rs に実装済み
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NumaInfo {
    pub node_count: u8,
    pub _reserved: [u8; 7],
    pub nodes: [NumaNodeInfo; MAX_NUMA_NODES],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NumaNodeInfo {
    pub proximity_domain: u32,
    pub memory_range_count: u8,
    pub cpu_count: u8,
    pub _reserved: [u8; 2],
    pub memory_ranges: [NumaMemoryRange; 4],
    pub cpu_apic_mask_low: u64,
    pub cpu_apic_mask_high: u64,
}
```

**実装タスク**:

- [x] ACPI SRATテーブルパース
- [x] NumaInfo構造体をExoBootInfoに追加
- [x] 静的バッファでのNUMA情報格納
- [x] プロセッサアフィニティ検出
- [x] メモリアフィニティ検出
- [x] x2APICアフィニティ対応

### 1.3 AP (Application Processor) 起動準備 ✅ 完了

**目的**: カーネルがマルチコア起動を即座に開始できるよう準備

**実装内容**:

- `ap_boot.rs` モジュール追加
- UEFI MP Servicesプロトコル経由でCPU数検出
- リアルモードトランポリンコード領域（1MB以下）の事前割り当て
- AP用スタック（各64KB）の事前割り当て
- `ApBootInfo`構造体をExoBootInfoに追加

```rust
// boot_proto/src/lib.rs に実装済み
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ApBootInfo {
    pub ap_count: u16,
    pub _reserved: [u8; 6],
    pub trampoline_addr: u64,
    pub trampoline_size: u64,
    pub stack_base: u64,
    pub stack_size: u64,
    pub stack_count: u16,
    pub _reserved2: [u8; 6],
}
```

**実装タスク**:

- [x] MP Servicesプロトコル経由CPU数検出
- [x] リアルモードトランポリン領域割り当て（0x8000優先）
- [x] AP用スタック事前割り当て
- [x] ApBootInfo構造体定義・初期化

### 1.3 TLS (Thread Local Storage) 初期化 ✅ 完了

**目的**: カーネルのper-CPU変数を即座に使用可能に

**実装内容**:

- PT_TLSセグメント（Type=7）を自動検出
- `TlsInfo`構造体（start_addr, file_size, mem_size, align）を完全初期化
- ExoBootInfo経由でカーネルに渡す

**実装タスク**:

- [x] PT_TLSセグメント検出・パース
- [x] TlsInfo構造体の完全な初期化
- [ ] BSP用TLS領域の事前割り当て（カーネル側で実装）

---

## Phase 2: セキュリティ強化 🔒

### 2.1 Measured Boot (TPM 2.0統合) ✅ 完了

**目的**: 起動チェーンの完全性を暗号学的に証明

**実装内容**:

- `tpm.rs` モジュール追加
- UEFI TCG2プロトコル検出・利用
- カーネル、initramfs、コマンドラインをそれぞれPCRに測定
- TPMが利用可能でない場合も正常にフォールバック

```rust
// PCR割り当て
pub const PCR_KERNEL: u32 = 8;      // カーネルイメージ
pub const PCR_INITRAMFS: u32 = 9;   // initramfs
pub const PCR_BOOT_CONFIG: u32 = 14; // コマンドライン等
```

**実装タスク**:

- [x] UEFI TCG2プロトコル対応
- [x] PCR[8]にカーネルハッシュを拡張
- [x] PCR[9]にinitramfsハッシュを拡張
- [x] PCR[14]にコマンドラインハッシュを拡張
- [x] イベントログ生成

### 2.2 UEFI Runtime Services保存 ✅ 完了

**目的**: カーネルがUEFI変数、RTC、リセット機能にアクセス可能に

**実装内容**:

- `uefi_runtime.rs` モジュール追加
- Runtime Servicesテーブルアドレスの保存
- ランタイムメモリ領域（RUNTIME_SERVICES_CODE/DATA、MMIO等）の収集
- 機能フラグ（TIME_SERVICES、VARIABLE_SERVICES、RESET_SYSTEM）の設定

```rust
// boot_proto/src/lib.rs に実装済み
pub struct UefiRuntimeInfo {
    pub runtime_services_addr: u64,
    pub runtime_services_virt: u64,
    pub runtime_mmap_count: u32,
    pub capabilities: u32,
    pub runtime_mmap: [RuntimeMemoryRegion; MAX_RUNTIME_MMAP_ENTRIES],
}
```

**実装タスク**:

- [x] Runtime Servicesテーブルアドレス保存
- [x] ランタイムメモリ領域収集
- [x] 機能フラグ検出
- [ ] SetVirtualAddressMap呼び出し（カーネル側で実装）

### 2.3 UEFI Secure Boot統合 ✅ 完了

**目的**: ファームウェアレベルでのブートローダー検証状態の検出

**実装内容**:

- `secure_boot.rs` モジュール追加
- UEFI変数からSecure Boot状態を検出
- SetupMode/UserMode/AuditMode/DeployedMode判定
- PK/KEK/db/dbx存在確認
- SecureBootInfo構造体でカーネルに状態を伝達

```rust
// boot_proto/src/lib.rs に実装済み
pub struct SecureBootInfo {
    pub secure_boot_enabled: bool,
    pub setup_mode: bool,
    pub pk_present: bool,
    pub kek_present: bool,
    pub db_present: bool,
    pub dbx_present: bool,
    pub audit_mode: bool,
    pub deployed_mode: bool,
    pub vendor_keys: bool,
}
```

**実装タスク**:

- [x] セキュアブート状態のカーネルへの伝達
- [x] SecureBoot/SetupMode/AuditMode/DeployedMode変数読み取り
- [x] PK/KEK/db/dbx存在確認
- [x] Shim loader対応
- [x] MOK (Machine Owner Key) 管理

### 2.3.1 Shim Loader・MOK対応 ✅ 完了

**目的**: Shim bootloader経由での起動とMOK管理機能

**実装内容**:

- `shim_mok.rs` モジュール追加
- SHIM_LOCK_PROTOCOL検出（GUID: 605DAB50-E046-4300-ABB6-3DD810DD8B23）
- MOK関連UEFI変数の読み取り（MokSBState, MokList, MokListRT, MokListX, SbatLevel）
- MOK証明書数のカウント
- Shimバイナリ検証機能（verify_with_shim）

```rust
// boot_proto/src/lib.rs に実装済み
pub struct ShimMokInfo {
    pub shim_detected: bool,
    pub mok_sb_state: u8,
    pub mok_list_present: bool,
    pub mok_list_rt_present: bool,
    pub mok_list_x_present: bool,
    pub sbat_level_present: bool,
    pub shim_validated: bool,
    pub mok_count: u16,
    pub shim_version_major: u8,
    pub shim_version_minor: u8,
}
```

**実装タスク**:

- [x] SHIM_LOCK_PROTOCOL検出
- [x] MOK変数読み取り（MokSBState, MokList等）
- [x] ShimMokInfo構造体追加
- [x] Shimバイナリ検証API

### 2.4 メモリ暗号化対応 (AMD SME/SEV) ✅ 完了

**目的**: メモリ内容の保護

**実装内容**:

- `sme_sev.rs` モジュール追加
- CPUID経由でAMD SME/SEV/SEV-ES/SEV-SNP機能を検出
- MSR読み取りで暗号化の有効状態を確認
- Intel TDX基本検出（CPUID leaf 0x21）
- C-bit位置と暗号化マスクをカーネルに渡す

```rust
// boot_proto/src/lib.rs に実装済み
pub struct MemoryEncryptionInfo {
    pub sme_available: bool,
    pub sev_available: bool,
    pub sev_es_available: bool,
    pub sev_snp_available: bool,
    pub sme_enabled: bool,
    pub sev_enabled: bool,
    pub c_bit_position: u8,
    pub phys_addr_reduction: u8,
    pub encryption_mask: u64,
    pub tdx_available: bool,
}
```

**実装タスク**:

- [x] AMD SME/SEV検出 (CPUID Fn8000_001F)
- [x] MSR読み取りで有効状態確認
- [x] Intel TDX基本検出
- [x] MemoryEncryptionInfo構造体追加
- [ ] 暗号化ページテーブルフラグ設定（カーネル側で実装）

---

## Phase 3: 機能拡張 🚀

### 3.1 マルチブートカーネル選択 ✅ 完了

**目的**: 複数カーネルバージョンからの選択起動

**実装内容**:

- `config.rs` モジュール追加 - INIスタイル設定ファイルパーサー
- `menu.rs` モジュール追加 - テキストベースブートメニューUI
- 矢印キーナビゲーション、Enterで選択
- タイムアウト付きデフォルト選択
- ESCキーでキャンセル

```rust
// config.rs に実装済み
pub struct BootEntry {
    pub name: String,
    pub kernel: String,
    pub initramfs: Option<String>,
    pub cmdline: Option<String>,
}

pub struct BootConfig {
    pub timeout: u32,
    pub default_entry: usize,
    pub entries: Vec<BootEntry>,
}
```

**設定ファイル例** (exoloader.cfg):

```ini
timeout = 5
default = 0

[entry]
name = RanyOS (Default)
kernel = rany_os
initramfs = initramfs.tar
cmdline = loglevel=info console=serial

[entry]
name = RanyOS (Debug Mode)
kernel = rany_os
initramfs = initramfs.tar
cmdline = loglevel=debug console=serial
```

**実装タスク**:

- [x] 設定ファイル (exoloader.cfg) パース
- [x] シンプルなテキストUIブートメニュー
- [x] タイムアウト付きデフォルト選択
- [ ] 前回起動カーネルの記憶（UEFI変数経由）

### 3.2 カーネルコマンドライン ✅ 完了

**目的**: 起動時パラメータのカーネルへの引き渡し

**実装内容**:

- `exoloader.cmdline` ファイルからコマンドライン読み込み
- UTF-8テキスト、末尾改行/null自動トリム
- HHDM仮想アドレスでカーネルに渡す
- `boot_info.cmdline_ptr` / `boot_info.cmdline_len` に設定

**実装タスク**:

- [x] コマンドラインファイル読み込み
- [ ] UEFI変数からの読み込み（オプション）
- [x] 文字列のHHDMアドレスへのマッピング

### 3.3 シリアルコンソールログ ✅ 完了

**目的**: ヘッドレス環境でのデバッグ

**実装内容**:

- `serial.rs` モジュール追加
- COM1 (0x3F8) への直接I/Oポートアクセス
- 115200 baud, 8N1 設定
- `serial_print!` / `serial_println!` マクロ
- UEFI初期化前から使用可能

**実装タスク**:

- [x] UART (COM1/COM2) 初期化
- [x] serial_print!/serial_println!マクロ
- [x] ボーレート設定 (115200固定)
- [ ] ボーレート設定可能化（オプション）

---

## Phase 4: ハードウェア情報拡張 🏗️

### 4.1 SMBIOS情報取得 ✅ 完了

**目的**: ハードウェア情報の詳細取得

**実装内容**:

- `smbios.rs` モジュール追加
- UEFI Configuration TableからSMBIOS 3.x/2.xテーブル検出
- BIOS情報（ベンダー、バージョン）パース
- システム情報（製造元、製品名、シリアル番号、UUID）パース
- SmbiosInfo構造体でカーネルに情報を伝達

```rust
// boot_proto/src/lib.rs に実装済み
pub struct SmbiosInfo {
    pub smbios3_addr: u64,
    pub smbios_addr: u64,
    pub major_version: u8,
    pub minor_version: u8,
    pub table_max_size: u32,
    pub flags: u16,
    pub system_uuid: [u8; 16],
    // ... その他フィールド
}
```

**実装タスク**:

- [x] SMBIOS 3.x/2.x テーブルアドレス取得
- [x] UEFI Configuration Tableパース
- [x] BIOS情報（Type 0）パース
- [x] システム情報（Type 1）パース
- [x] SmbiosInfo構造体でカーネルに情報を伝達

---

## Phase 5: レジリエンス・回復機能 🛡️

### 5.1 フォールバックカーネル

**目的**: 起動失敗時の自動リカバリ

**実装タスク**:

- [ ] 起動成功フラグ (UEFI変数)
- [ ] 連続失敗カウンター
- [ ] フォールバックカーネルへの自動切り替え
- [ ] リカバリモード

### 5.2 ブートログ永続化

**目的**: 起動失敗の事後診断

**実装タスク**:

- [ ] EFI変数へのログ保存
- [ ] 前回ブートログの取得API
- [ ] ログローテーション

### 5.3 セルフテスト機能

**目的**: ハードウェア問題の早期検出

**実装タスク**:

- [ ] メモリテスト (オプション)
- [ ] ACPI テーブル検証
- [ ] GOP動作確認

---

## 実装優先度マトリクス

| 機能 | 難易度 | 影響度 | 優先度 | 状態 |
|------|--------|--------|--------|------|
| 1GB ページサポート | 低 | 高 | ⭐⭐⭐⭐⭐ | ✅ 完了 |
| TLS 初期化 | 中 | 高 | ⭐⭐⭐⭐⭐ | ✅ 完了 |
| コマンドライン | 低 | 中 | ⭐⭐⭐⭐ | ✅ 完了 |
| シリアルログ | 低 | 中 | ⭐⭐⭐⭐ | ✅ 完了 |
| NUMA検出 | 中 | 中 | ⭐⭐⭐ | ✅ 完了 |
| ブートメニュー | 中 | 中 | ⭐⭐⭐ | ✅ 完了 |
| TPM統合 | 高 | 高 | ⭐⭐⭐ | ✅ 完了 |
| AP準備 | 中 | 高 | ⭐⭐⭐ | ✅ 完了 |
| UEFI Runtime | 中 | 低 | ⭐⭐ | ✅ 完了 |
| メモリ暗号化 | 高 | 中 | ⭐⭐ | ✅ 完了 |
| Secure Boot | 中 | 高 | ⭐⭐⭐ | ✅ 完了 |
| Shim/MOK | 中 | 中 | ⭐⭐ | ✅ 完了 |
| SMBIOS情報 | 低 | 中 | ⭐⭐ | ✅ 完了 |

---

## ファイル構成（現在）

```
bootloader/
├── Cargo.toml
├── FUTURE_ROADMAP.md       # このファイル
├── src/
│   ├── main.rs             # エントリポイント
│   ├── page_table.rs       # ページテーブル操作 (1GB対応) ✅
│   ├── serial.rs           # シリアルログ ✅
│   ├── config.rs           # 設定ファイルパーサー ✅
│   ├── menu.rs             # ブートメニューUI ✅
│   ├── numa.rs             # NUMA検出 ✅
│   ├── ap_boot.rs          # AP起動準備 ✅
│   ├── tpm.rs              # TPM 2.0統合 ✅
│   ├── uefi_runtime.rs     # UEFI Runtime Services ✅
│   ├── sme_sev.rs          # AMD SME/SEV検出 ✅
│   ├── secure_boot.rs      # Secure Boot状態検出 ✅
│   ├── shim_mok.rs         # Shim/MOK管理 ✅
│   └── smbios.rs           # SMBIOS情報取得 ✅
└── assets/
    └── exoloader.cfg.example  # 設定ファイル例 ✅
```

---

## 関連設計ドキュメント

- [ExoRust設計書](../Rustカーネル設計案作成.md) - アーキテクチャ全体
- [docs/exorust_design/bootstrap/](../docs/exorust_design/bootstrap/) - ブートストラップ詳細
  - `early_pagetable.rs` - 1GBページ設計参照
  - `numa_detection.rs` - NUMA検出設計参照

---

## 更新履歴

| 日付 | バージョン | 内容 |
|------|-----------|------|
| 2026-01-03 | v0.1 | 初版作成 |
| 2026-01-03 | v0.2 | Phase 1完了 (1GBページ、TLS、コマンドライン、シリアルログ) |
| 2026-01-03 | v0.3 | Phase 2完了 (TPM、UEFI Runtime、Secure Boot、SME/SEV) |
| 2026-01-03 | v0.4 | Phase 2.3追加 (Shim/MOK管理)、Phase 3完了 (ブートメニュー) |
| 2026-01-03 | v0.5 | Phase 4完了 (SMBIOS情報取得)
