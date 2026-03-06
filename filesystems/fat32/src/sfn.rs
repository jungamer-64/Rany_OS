// use hashbrown for collections in no_std
use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashSet;

use crate::{
    DELETED_ENTRY, DirEntryRaw, END_OF_DIR, FileAttributes, FsResult, LfnEntry, MAX_LFN_PARTS,
    SafePackedRead,
};

// Short File Name (SFN) Generation with Collision Handling
// ============================================================================

/// ロングファイル名を8.3形式のショートファイル名に変換
///
/// # Arguments
/// * `name` - ロングファイル名
///
/// # Returns
/// 8.3形式のSFN（8バイト名前 + 3バイト拡張子、スペースパディング）
pub fn long_name_to_sfn(name: &str) -> [u8; 11] {
    let mut sfn = [b' '; 11];

    // 拡張子を分離
    let (base, ext) = if let Some(dot_pos) = name.rfind('.') {
        (&name[..dot_pos], &name[dot_pos + 1..])
    } else {
        (name, "")
    };

    // ベース名を8文字まで
    let mut base_idx = 0;
    for ch in base.chars().take(8) {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            sfn[base_idx] = ch.to_ascii_uppercase() as u8;
            base_idx += 1;
        } else if ch == ' ' {
            // スペースはスキップ
        } else {
            sfn[base_idx] = b'_';
            base_idx += 1;
        }
    }

    // 拡張子を3文字まで
    let mut ext_idx = 8;
    for ch in ext.chars().take(3) {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            sfn[ext_idx] = ch.to_ascii_uppercase() as u8;
            ext_idx += 1;
        } else {
            sfn[ext_idx] = b'_';
            ext_idx += 1;
        }
    }

    sfn
}

/// 既存のSFN一覧との衝突を避けるユニークなSFNを生成
///
/// 例: "LONGFI~1.TXT", "LONGFI~2.TXT", etc.
///
/// # Arguments
/// * `name` - 元のロングファイル名
/// * `existing` - 既存のSFN一覧（ディレクトリ内の全エントリから収集）
///
/// # Returns
/// ユニークなSFN（~1-~9のサフィックス付き）
pub fn generate_unique_sfn(name: &str, existing: &HashSet<[u8; 11]>) -> [u8; 11] {
    let base_sfn = long_name_to_sfn(name);

    // 衝突がなければそのまま返す
    if !existing.contains(&base_sfn) {
        return base_sfn;
    }

    // サフィックス付きで試行（~1から~9まで）
    for suffix in 1..=9 {
        let mut sfn = base_sfn;
        // ベース名の末尾を ~N に置換
        let suffix_pos = 6.min(
            sfn[..8]
                .iter()
                .position(|&b| b == b' ')
                .unwrap_or(8)
                .saturating_sub(2),
        );
        sfn[suffix_pos] = b'~';
        sfn[suffix_pos + 1] = b'0' + suffix;

        if !existing.contains(&sfn) {
            return sfn;
        }
    }

    // 全て使用済みの場合、ハッシュベースのサフィックスを使用
    let hash = name.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
    let mut sfn = base_sfn;
    sfn[4] = b'~';
    sfn[5] = b"0123456789ABCDEF"[(hash >> 4) as usize];
    sfn[6] = b"0123456789ABCDEF"[(hash & 0xF) as usize];
    sfn[7] = b'~';

    sfn
}

/// ディレクトリから既存のSFN一覧を収集
pub fn collect_existing_sfns<'a>(
    entries: impl Iterator<Item = FsResult<(String, DirEntryRaw)>> + 'a,
) -> HashSet<[u8; 11]> {
    entries
        .filter_map(|res| res.ok())
        .map(|(name, _)| long_name_to_sfn(&name))
        .collect()
}

/// ディレクトリエントリの種類を表す列挙型
///
/// 生のバイト列を解析した結果を型安全に表現する。
/// if/else の条件分岐をパターンマッチに置き換えることで、
/// コードの意図が明確になり、網羅性チェックも働く。
#[derive(Debug)]
pub enum DirectoryEntryKind {
    /// ディレクトリの終端マーカー
    End,
    /// 削除済みエントリ
    Deleted,
    /// ロングファイルネームエントリ
    LongName(LfnEntry),
    /// 通常のディレクトリエントリ
    Standard(DirEntryRaw),
    /// ボリュームラベル（スキップ対象）
    VolumeLabel,
}

/// ディレクトリエントリ処理の結果
pub(crate) enum DirEntryAction {
    /// ディレクトリ走査終了
    EndOfDir,
    /// このエントリはスキップ
    Skip,
    /// 有効なエントリが見つかった
    Found(String, DirEntryRaw),
    /// ファイルシステム破損を検出
    Corrupted,
}

/// LFNパーツの連番が有効かどうかを検証する
fn is_valid_lfn_sequence(lfn_parts: &[(u8, bool, String, u8)]) -> bool {
    let n = lfn_parts.len() as u8;
    let mut seen = HashSet::new();
    for &(seq, _, _, _) in lfn_parts {
        if seq == 0 || seq > n || !seen.insert(seq) {
            return false;
        }
    }
    lfn_parts
        .iter()
        .any(|&(seq, is_last, _, _)| seq == n && is_last)
}

/// LFNパーツとSFNエントリからファイル名を解決する
fn resolve_dir_entry_name(
    lfn_parts: &mut Vec<(u8, bool, String, u8)>,
    raw: &DirEntryRaw,
) -> String {
    if lfn_parts.is_empty() {
        return raw.short_name();
    }

    let expected_checksum = raw.calculate_checksum();
    let all_checksum_match = lfn_parts
        .iter()
        .all(|&(_, _, _, cs)| cs == expected_checksum);
    if !all_checksum_match {
        lfn_parts.clear();
        return raw.short_name();
    }

    lfn_parts.sort_by_key(|&(seq, _, _, _)| seq);
    if !is_valid_lfn_sequence(lfn_parts) {
        lfn_parts.clear();
        return raw.short_name();
    }

    let long_name: String = lfn_parts
        .iter()
        .map(|&(_, _, ref s, _)| s.as_str())
        .collect();
    lfn_parts.clear();
    long_name
}

/// ディレクトリエントリ1件を処理し、アクションを返す
pub(crate) fn process_dir_entry(
    entry_bytes: &[u8],
    lfn_parts: &mut Vec<(u8, bool, String, u8)>,
) -> DirEntryAction {
    match DirectoryEntryKind::from(entry_bytes) {
        DirectoryEntryKind::End => DirEntryAction::EndOfDir,
        DirectoryEntryKind::Deleted | DirectoryEntryKind::VolumeLabel => {
            lfn_parts.clear();
            DirEntryAction::Skip
        }
        DirectoryEntryKind::LongName(lfn) => {
            if lfn_parts.len() >= MAX_LFN_PARTS {
                return DirEntryAction::Corrupted;
            }
            lfn_parts.push((
                lfn.sequence(),
                lfn.is_last(),
                lfn.get_name_part(),
                lfn.checksum(),
            ));
            DirEntryAction::Skip
        }
        DirectoryEntryKind::Standard(raw) => {
            let name = resolve_dir_entry_name(lfn_parts, &raw);
            if name == "." || name == ".." {
                return DirEntryAction::Skip;
            }
            DirEntryAction::Found(name, raw)
        }
    }
}

impl From<&[u8]> for DirectoryEntryKind {
    fn from(bytes: &[u8]) -> Self {
        let first_byte = bytes[0];

        if first_byte == END_OF_DIR {
            return DirectoryEntryKind::End;
        }
        if first_byte == DELETED_ENTRY {
            return DirectoryEntryKind::Deleted;
        }

        let attr = FileAttributes::from(bytes[11]);
        if attr.is_long_name() {
            DirectoryEntryKind::LongName(<LfnEntry as SafePackedRead>::from_bytes_safe(bytes))
        } else if attr.is_volume_id() {
            DirectoryEntryKind::VolumeLabel
        } else {
            DirectoryEntryKind::Standard(<DirEntryRaw as SafePackedRead>::from_bytes_safe(bytes))
        }
    }
}
