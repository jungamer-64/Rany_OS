use crate::{Arc, BlockDevice, DefaultZeroCopyBuffer, Fat32FileSystem, FsError, FsInfo, FsResult};

// ============================================================================
// Format Utility (mkfs.fat32)
// ============================================================================

/// FAT32フォーマットオプション
#[derive(Debug, Clone)]
pub struct FormatOptions {
    /// ボリュームラベル（最大11文字、大文字）
    pub label: [u8; 11],
    /// セクタあたりのバイト数（通常512）
    pub bytes_per_sector: u16,
    /// クラスタあたりのセクタ数（自動計算する場合はNone）
    pub sectors_per_cluster: Option<u8>,
}

impl Default for FormatOptions {
    fn default() -> Self {
        Self {
            label: *b"NO NAME    ",
            bytes_per_sector: 512,
            sectors_per_cluster: None,
        }
    }
}

impl FormatOptions {
    /// ボリュームラベルを設定
    pub fn with_label(mut self, label: &str) -> Self {
        let bytes = label.as_bytes();
        let len = bytes.len().min(11);
        self.label = [b' '; 11];
        for (i, &b) in bytes.iter().take(len).enumerate() {
            self.label[i] = b.to_ascii_uppercase();
        }
        self
    }

    /// クラスタサイズを設定
    pub fn with_cluster_size(mut self, sectors: u8) -> Self {
        self.sectors_per_cluster = Some(sectors);
        self
    }
}

/// ディスクサイズに基づいてFAT32の最適なセクタ/クラスタ比を決定する
fn determine_sectors_per_cluster(total_sectors: u32, bytes_per_sector: u32) -> u8 {
    let size_mb = (total_sectors as u64 * bytes_per_sector as u64) / (1024 * 1024);
    match size_mb {
        0..=64 => 1,
        65..=128 => 2,
        129..=256 => 4,
        257..=8192 => 8,
        8193..=16384 => 16,
        _ => 32,
    }
}

/// FAT32ブートセクタのバイト列を構築する
fn build_fat32_boot_sector(
    total_sectors: u32,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    num_fats: u8,
    root_cluster: u32,
    fat_size: u32,
    label: &[u8; 11],
) -> [u8; 512] {
    let mut bs = [0u8; 512];

    // ジャンプ命令
    bs[0] = 0xEB;
    bs[1] = 0x58;
    bs[2] = 0x90;

    // OEM名
    bs[3..11].copy_from_slice(b"RANYOS  ");

    // BPB
    bs[11..13].copy_from_slice(&bytes_per_sector.to_le_bytes());
    bs[13] = sectors_per_cluster;
    bs[14..16].copy_from_slice(&reserved_sectors.to_le_bytes());
    bs[16] = num_fats;
    bs[17..19].copy_from_slice(&0u16.to_le_bytes()); // FAT32では0
    bs[19..21].copy_from_slice(&0u16.to_le_bytes()); // FAT32では0
    bs[21] = 0xF8; // ハードディスク
    bs[22..24].copy_from_slice(&0u16.to_le_bytes()); // FAT32では0
    bs[24..26].copy_from_slice(&63u16.to_le_bytes()); // セクタ/トラック
    bs[26..28].copy_from_slice(&255u16.to_le_bytes()); // ヘッド数
    bs[28..32].copy_from_slice(&0u32.to_le_bytes()); // 隠しセクタ
    bs[32..36].copy_from_slice(&total_sectors.to_le_bytes());

    // FAT32拡張BPB
    bs[36..40].copy_from_slice(&fat_size.to_le_bytes());
    bs[40..42].copy_from_slice(&0u16.to_le_bytes()); // 拡張フラグ
    bs[42..44].copy_from_slice(&0u16.to_le_bytes()); // バージョン
    bs[44..48].copy_from_slice(&root_cluster.to_le_bytes());
    bs[48..50].copy_from_slice(&1u16.to_le_bytes()); // FSInfo sector
    bs[50..52].copy_from_slice(&6u16.to_le_bytes()); // バックアップブートセクタ
    bs[64] = 0x80; // ドライブ番号
    bs[66] = 0x29; // 拡張ブートシグネチャ
    bs[67..71].copy_from_slice(&0x12345678u32.to_le_bytes()); // ボリュームシリアル
    bs[71..82].copy_from_slice(label);
    bs[82..90].copy_from_slice(b"FAT32   ");
    bs[510] = 0x55;
    bs[511] = 0xAA;

    bs
}

/// FATテーブルの初期化（プライマリ＋バックアップ）
fn write_fat32_tables(
    device: &Arc<dyn BlockDevice>,
    fat_start: u64,
    fat_size: u32,
) -> FsResult<()> {
    let mut fat_sector = [0u8; 512];

    // 最初のFATセクタ
    fat_sector[0..4].copy_from_slice(&0x0FFFFFF8u32.to_le_bytes()); // クラスタ0
    fat_sector[4..8].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // クラスタ1
    fat_sector[8..12].copy_from_slice(&0x0FFFFFFFu32.to_le_bytes()); // クラスタ2 (ルート、EOF)

    device.write_sync(fat_start, &fat_sector)?;
    device.write_sync(fat_start + fat_size as u64, &fat_sector)?; // バックアップFAT

    // 残りのFATセクタをゼロ初期化
    let zero_sector = [0u8; 512];
    for i in 1..fat_size {
        device.write_sync(fat_start + i as u64, &zero_sector)?;
        device.write_sync(fat_start + fat_size as u64 + i as u64, &zero_sector)?;
    }
    Ok(())
}

/// FAT32フォーマット構造体をデバイスに書き込む
fn write_format_structures(
    device: &Arc<dyn BlockDevice>,
    boot_sector: &[u8],
    free_clusters: u32,
    reserved_sectors: u16,
    fat_size: u32,
    num_fats: u8,
    label: &[u8; 11],
) -> FsResult<()> {
    device.write_sync(0, boot_sector)?;
    device.write_sync(6, boot_sector)?; // バックアップブートセクタ

    // FSInfo セクタ
    let fsinfo = FsInfo::new(free_clusters, 3);
    device.write_sync(1, &fsinfo.to_bytes())?;
    device.write_sync(7, &fsinfo.to_bytes())?;

    // FAT 初期化
    let fat_start = reserved_sectors as u64;
    write_fat32_tables(device, fat_start, fat_size)?;

    // ルートディレクトリ初期化
    let data_start = reserved_sectors as u32 + num_fats as u32 * fat_size;
    let mut root_dir = [0u8; 512];
    root_dir[0..11].copy_from_slice(label);
    root_dir[11] = 0x08;
    device.write_sync(data_start as u64, &root_dir)?;

    // フラッシュ
    device.flush()?;
    Ok(())
}

impl Fat32FileSystem<DefaultZeroCopyBuffer> {
    /// ブロックデバイスをFAT32でフォーマット
    ///
    /// # Arguments
    /// * `device` - フォーマット対象のブロックデバイス
    /// * `options` - フォーマットオプション
    ///
    /// # Returns
    /// フォーマット済みのファイルシステム
    ///
    /// # Warning
    /// この操作はデバイス上の全データを消去します
    pub fn format(device: Arc<dyn BlockDevice>, options: FormatOptions) -> FsResult<Arc<Self>> {
        let info = device.info();
        let total_sectors = info.total_blocks as u32;
        let bytes_per_sector = options.bytes_per_sector as u32;

        // 最小サイズチェック（FAT32は32MB以上推奨）
        if total_sectors < 65536 {
            return Err(FsError::InvalidInput);
        }

        // クラスタサイズを決定
        let sectors_per_cluster = options
            .sectors_per_cluster
            .unwrap_or_else(|| determine_sectors_per_cluster(total_sectors, bytes_per_sector));

        // FAT32パラメータ計算
        let reserved_sectors: u16 = 32;
        let num_fats: u8 = 2;
        let root_cluster: u32 = 2;

        // FAT サイズ計算
        let data_sectors = total_sectors - reserved_sectors as u32;
        let clusters = data_sectors / sectors_per_cluster as u32;
        let fat_size = (clusters * 4 + bytes_per_sector - 1) / bytes_per_sector;

        // ブートセクタ構築・書き込み
        let boot_sector = build_fat32_boot_sector(
            total_sectors,
            options.bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            root_cluster,
            fat_size,
            &options.label,
        );

        let free_clusters = clusters - 1;
        write_format_structures(
            &device,
            &boot_sector,
            free_clusters,
            reserved_sectors,
            fat_size,
            num_fats,
            &options.label,
        )?;

        // マウント
        Self::mount(device)
    }
}
