use super::{Cluster, FsError, FsResult};
use core::marker::PhantomData;

// ----------------------------------------------------------------
// State Markers (Zero-Sized Types for Typestate)
// ----------------------------------------------------------------

/// 未使用状態を表すマーカー型
pub struct Free;

/// 割り当て済み状態を表すマーカー型
pub struct Allocated;

/// クラスタチェーンでリンクされた状態を表すマーカー型
pub struct Linked;

/// チェーン終端状態を表すマーカー型
pub struct EndOfChain;

// ----------------------------------------------------------------
// FatEntry<State> - Type-Safe FAT Entry
// ----------------------------------------------------------------

/// 型安全なFATエントリ
///
/// ジェネリクスの`State`パラメータにより、
/// エントリの現在の状態をコンパイル時に追跡します。
#[derive(Debug, Clone, Copy)]
pub struct FatEntry<State> {
    cluster: Cluster,
    value: u32,
    _state: PhantomData<State>,
}

impl FatEntry<Free> {
    /// 空きクラスタから新しいFatEntryを作成
    ///
    /// # Arguments
    /// * `cluster` - 空きクラスタ番号
    #[inline]
    pub const fn new_free(cluster: Cluster) -> Self {
        FatEntry {
            cluster,
            value: 0,
            _state: PhantomData,
        }
    }

    /// 空きエントリを割り当て状態に遷移
    ///
    /// # Returns
    /// 割り当て済み状態のFatEntry
    #[inline]
    pub fn allocate(self) -> FatEntry<Allocated> {
        FatEntry {
            cluster: self.cluster,
            value: Cluster::EOF.0,
            _state: PhantomData,
        }
    }
}

impl FatEntry<Allocated> {
    /// 割り当て済みエントリを別のクラスタにリンク
    ///
    /// # Arguments
    /// * `next` - リンク先のクラスタ
    ///
    /// # Errors
    /// 無効なクラスタ番号の場合エラー
    #[inline]
    pub fn link_to(self, next: Cluster) -> FsResult<FatEntry<Linked>> {
        if next.0 < 2 {
            return Err(FsError::InvalidInput);
        }
        Ok(FatEntry {
            cluster: self.cluster,
            value: next.0,
            _state: PhantomData,
        })
    }

    /// 割り当て済みエントリをチェーン終端としてマーク
    #[inline]
    pub fn mark_eof(self) -> FatEntry<EndOfChain> {
        FatEntry {
            cluster: self.cluster,
            value: Cluster::EOF.0,
            _state: PhantomData,
        }
    }
}

impl<State> FatEntry<State> {
    /// クラスタ番号を取得
    #[inline]
    pub const fn cluster(&self) -> Cluster {
        self.cluster
    }

    /// FAT値を取得
    #[inline]
    pub const fn fat_value(&self) -> u32 {
        self.value
    }

    /// FATに書き込むべきClusterを取得
    #[inline]
    pub const fn as_cluster_value(&self) -> Cluster {
        Cluster(self.value)
    }
}

// ----------------------------------------------------------------
// Builder for Entry Creation from Raw Values
// ----------------------------------------------------------------

/// 生のFAT値から適切な状態のFatEntryを構築するビルダー
pub struct FatEntryBuilder {
    cluster: Cluster,
    raw_value: u32,
}

impl FatEntryBuilder {
    /// 新しいビルダーを作成
    #[inline]
    pub const fn new(cluster: Cluster, raw_value: u32) -> Self {
        FatEntryBuilder { cluster, raw_value }
    }

    /// 空きエントリとして構築(値が0の場合)
    pub fn build_if_free(self) -> Option<FatEntry<Free>> {
        if self.raw_value == 0 {
            Some(FatEntry {
                cluster: self.cluster,
                value: 0,
                _state: PhantomData,
            })
        } else {
            None
        }
    }

    /// リンク済みエントリとして構築(次のクラスタへのリンクがある場合)
    pub fn build_if_linked(self) -> Option<FatEntry<Linked>> {
        let masked = self.raw_value & 0x0FFFFFFF;
        if masked >= 2 && masked < 0x0FFFFFF8 {
            Some(FatEntry {
                cluster: self.cluster,
                value: masked,
                _state: PhantomData,
            })
        } else {
            None
        }
    }

    /// EOFエントリとして構築(チェーン終端の場合)
    pub fn build_if_eof(self) -> Option<FatEntry<EndOfChain>> {
        let masked = self.raw_value & 0x0FFFFFFF;
        if masked >= 0x0FFFFFF8 {
            Some(FatEntry {
                cluster: self.cluster,
                value: masked,
                _state: PhantomData,
            })
        } else {
            None
        }
    }

    /// 状態を判定して適切な型を返す(動的ディスパッチ用)
    pub fn classify(self) -> FatEntryKind {
        let masked = self.raw_value & 0x0FFFFFFF;
        if masked == 0 {
            FatEntryKind::Free(self.cluster)
        } else if masked >= 0x0FFFFFF8 {
            FatEntryKind::EndOfChain(self.cluster)
        } else if masked >= 2 {
            FatEntryKind::Linked(self.cluster, Cluster(masked))
        } else {
            FatEntryKind::Reserved(self.cluster)
        }
    }
}

/// FATエントリの種類を表す列挙型(動的な判定用)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatEntryKind {
    /// 未使用クラスタ
    Free(Cluster),
    /// 次のクラスタにリンク
    Linked(Cluster, Cluster),
    /// チェーン終端
    EndOfChain(Cluster),
    /// 予約済み(クラスタ0, 1)
    Reserved(Cluster),
}
