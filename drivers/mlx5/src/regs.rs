// ============================================================================
// drivers/mlx5/src/regs.rs - Hardware register definitions
// ============================================================================
//! ConnectX ファミリ レジスタマップ定義
//!
//! BAR0 にマッピングされる初期化セグメントおよびコマンドインタフェースレジスタ。
//! mlx5 IFC (Interface Control) 仕様に基づく。

/// BAR0 レジスタオフセット (Initialization Segment)
pub mod init_seg {
    /// ファームウェアリビジョン (major/minor packed)
    pub const FW_REV: usize = 0x0000;
    /// コマンドIFリビジョン/サブマイナ (cmdif_rev[31:16], fw_subminor[15:0])
    pub const CMDIF_REV_FW_SUB: usize = 0x0004;

    /// 健全性カウンタ
    pub const HEALTH_COUNTER: usize = 0x1010;

    /// コマンドキュー上位32ビットアドレス
    pub const CMDQ_ADDR_H: usize = 0x0010;
    /// コマンドキュー低32ビットアドレス + ログサイズ
    pub const CMDQ_ADDR_L_SZ: usize = 0x0014;

    /// コマンドドアベル
    pub const CMDQ_DOORBELL: usize = 0x0018;

    /// 初期化進行状態（bit31=1 で初期化中）
    pub const INITIALIZING: usize = 0x01FC;

    /// HCA健全性バッファオフセット
    pub const HEALTH_BUFFER: usize = 0x0200;

    /// ソフトウェアリセットレジスタ
    /// bit 0: 1を書き込むとリセット開始
    pub const SW_RESET: usize = 0x01F0;

    /// Internal Timer（高位32ビット）
    pub const INTERNAL_TIMER_H: usize = 0x1000;
    /// Internal Timer（低位32ビット）
    pub const INTERNAL_TIMER_L: usize = 0x1004;

    /// EQドアベルアドレスオフセット
    ///
    /// UAR (User Access Region) ページ内のドアベルオフセット基準
    pub const EQ_DOORBELL_OFFSET: usize = 0x0040;

    /// BF (BlueFlame) レジスタオフセット
    ///
    /// UAR ページ内送信ドアベル / BlueFlame領域
    pub const BF_OFFSET: usize = 0x0800;
}

/// コマンドキューエントリ (CQE) レイアウト
///
/// 各コマンドエントリは64バイト。メールボックスポインタと
/// ステータスフィールドで構成。
pub mod cmd_entry {
    /// エントリサイズ
    pub const ENTRY_SIZE: usize = 64;

    /// コマンドエントリにおけるOPCODEフィールドのオフセット。
    /// (書き込みは32bit単位で行われ、TYPEフィールドは後から submit() で
    /// 上書きされるためここでは 0 を使う)
    pub const OPCODE: usize = 0x00;

    /// 記述子タイプ (MLX5_PCI_CMD_XPORT=7)
    pub const TYPE: usize = 0x00;

    /// 入力データ長 (input_length)
    pub const IN_LENGTH: usize = 0x04;

    /// 入力メールボックスポインタ(高位)
    pub const IN_MBOX_PTR_H: usize = 0x08;
    /// 入力メールボックスポインタ(低位)
    pub const IN_MBOX_PTR_L: usize = 0x0C;

    /// 入力インラインデータ（16 bytes）
    pub const IN_INLINE: usize = 0x10;

    /// 出力インラインデータ（16 bytes）
    pub const OUT_INLINE: usize = 0x20;

    /// 出力メールボックスポインタ(高位)
    pub const OUT_MBOX_PTR_H: usize = 0x30;
    /// 出力メールボックスポインタ(低位)
    pub const OUT_MBOX_PTR_L: usize = 0x34;

    /// 出力データ長 (output_length)
    pub const OUT_LENGTH: usize = 0x38;

    /// コマンドトークン
    pub const TOKEN: usize = 0x3C;
    /// 記述子シグネチャ
    pub const SIG: usize = 0x3D;

    /// ステータス/オーナー
    /// bit0=owner (0=SW,1=HW), bits[7:1]=status
    pub const STATUS_OWN: usize = 0x3F;
}

/// UAR (User Access Region) レジスタ
///
/// 各UARページは4KBで、ドアベルレジスタやBlueFlame書き込み領域を含む。
pub mod uar {
    /// 1 UARページサイズ
    pub const PAGE_SIZE: usize = 0x1000;

    /// CQドアベルオフセット（8バイト: CQ番号 + CI）
    pub const CQ_DOORBELL: usize = 0x0020;

    /// EQドアベルオフセット
    pub const EQ_DOORBELL: usize = 0x0040;

    /// SQドアベルオフセット（4バイト: SQ番号）
    pub const SQ_DOORBELL: usize = 0x0800;

    /// BlueFlame領域オフセット（256バイト）
    pub const BLUEFLAME: usize = 0x0800;

    /// CQ ARMドアベルオフセット
    pub const CQ_ARM_DOORBELL: usize = 0x0028;
}

/// ファームウェア状態ビット
pub mod fw_state {
    /// 初期化中フラグ（1=初期化中, 0=ready）
    pub const INITIALIZING_BIT: u32 = 1 << 31;
    /// 内蔵 CPU (ECPU) フラグ
    pub const EMBEDDED_CPU_BIT: u32 = 1 << 23;
    /// cmdq_addr_l_sz の NIC interface support bit
    pub const NIC_INTERFACE_SUPPORTED_BIT: u32 = 1 << 8;

    /// 健全性: OK
    pub const HEALTH_OK: u32 = 0;
    /// 健全性: FW致命的エラー
    pub const HEALTH_FATAL: u32 = 0x0BAD;
}

/// イベントキューエントリ (EQE) レイアウト
pub mod eqe {
    /// EQEサイズ (bytes)
    pub const EQE_SIZE: usize = 64;

    /// オーナービットを含むステータスバイト (byte 63)
    pub const STATUS_OWN: usize = 0x3F;

    /// イベントタイプフィールド
    pub const TYPE: usize = 0x00;

    /// イベントサブタイプ
    pub const SUBTYPE: usize = 0x01;

    /// CQ完了イベント: CQ番号
    pub const CQ_NUMBER: usize = 0x0C;

    /// ポートイベント: ポート番号
    pub const PORT_NUMBER: usize = 0x08;

    /// ページ要求イベント: 関数ID
    pub const FUNC_ID: usize = 0x08;

    /// ページ要求イベント: 必要ページ数
    pub const NUM_PAGES: usize = 0x0C;
}

/// Completion Queue Entry (CQE) レイアウト (64-byte CQE)
pub mod cqe {
    /// CQEサイズ
    pub const SIZE: usize = 64;

    /// オペコードとオーナービット (byte 63)
    ///
    /// bits [7:4]: opcode
    /// bit 0: ownership (cycle bit)
    pub const OP_OWN: usize = 0x3F;

    /// 受信バイトカウント
    pub const BYTE_COUNT: usize = 0x2C;

    /// WQEカウンタ（SQ/RQインデックス）
    pub const WQE_COUNTER: usize = 0x30;

    /// QP番号 (SQ/RQ識別子)
    pub const QPN: usize = 0x38;

    /// VLANタグ情報
    pub const VLAN_INFO: usize = 0x18;

    /// RXハッシュ情報
    pub const RX_HASH: usize = 0x14;

    /// チェックサムステータスビット
    pub const CHECKSUM: usize = 0x10;

    // byte 0x10 (dword 4) flags:
    // bit 31-24: [31] l3_ok, [30] l4_ok, [29] ip_frag, [28] l3_type, [27:26] l4_type
    pub const L3_OK: u32 = 1 << 31;
    pub const L4_OK: u32 = 1 << 30;
    pub const IP_FRAG: u32 = 1 << 29;
    pub const L3_TYPE_IPV4: u32 = 0 << 28;
    pub const L3_TYPE_IPV6: u32 = 1 << 28;
    pub const L4_TYPE_TCP: u32 = 1 << 26;
    pub const L4_TYPE_UDP: u32 = 2 << 26;

    /// LRO (Large Receive Offload) セグメントサイズ
    pub const LRO_SEG_SIZE: usize = 0x24;
}

/// Work Queue Entry (WQE) レイアウト
pub mod wqe {
    /// WQE Control Segment (16 bytes)
    pub mod ctrl {
        /// オペコードとWQEインデックス（31:24=opcode, 23:0=wqe_index）
        pub const OPMOD_IDX_OPCODE: usize = 0x00;
        /// QP番号とDS (Descriptor Stride) カウント
        pub const QPN_DS: usize = 0x04;
        /// シグネチャとフラグ
        pub const SIGNATURE: usize = 0x08;
        /// FM CE SE フラグ
        pub const FM_CE_SE: usize = 0x0C;
    }

    /// WQE Ethernet Segment (16 bytes) — 送信用
    pub mod eth {
        /// インラインヘッダサイズ（LSB 10ビット）
        pub const INLINE_HDR_SZ: usize = 0x00;
        /// CS flags (チェックサムオフロード)
        pub const CS_FLAGS: usize = 0x02;
        /// MSS（TCP Segmentation Offload）
        pub const MSS: usize = 0x04;
        /// インラインヘッダ開始（最初の2バイト = EtherType部分）
        pub const INLINE_HDR_START: usize = 0x08;
    }

    /// WQE Data Segment (16 bytes)
    pub mod data {
        /// バイトカウント
        pub const BYTE_COUNT: usize = 0x00;
        /// L-Key (Memory Key)
        pub const LKEY: usize = 0x04;
        /// アドレス（64ビット)
        pub const ADDR: usize = 0x08;
    }

    /// WQEBBサイズ（16バイト）
    pub const WQEBB_SIZE: usize = 16;

    /// 送信WQEの最小サイズ（ctrl + eth + data = 48 bytes = 3 WQEBBs）
    pub const MIN_TX_WQE_SIZE: usize = 48;
}
