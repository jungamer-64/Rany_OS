use super::*;


/// 共有メモリ情報
#[derive(Debug)]
pub struct ShmInfo {
    pub id: ShmId,
    pub key: ShmKey,
    pub size: ShmSize,
    pub attach_count: usize,
    pub permissions: ShmPermissions,
    pub name: Option<String>,
}

/// マネージャー統計
#[derive(Debug)]
pub struct ShmManagerStats {
    pub total_created: u64,
    pub total_destroyed: u64,
    pub total_bytes: usize,
    pub active_regions: usize,
}

/// グローバル共有メモリマネージャー
pub(crate) static SHM_MANAGER: SharedMemoryManager = SharedMemoryManager::new();

/// 共有メモリマネージャーを取得
pub fn shm_manager() -> &'static SharedMemoryManager {
    &SHM_MANAGER
}

// --- System V IPC風 API ---

fn create_or_get_by_key(key: ShmKey, size: ShmSize, flags: ShmFlags) -> Result<ShmId, ShmError> {
    if flags.create || key == ShmKey::IPC_PRIVATE {
        SHM_MANAGER.create(key, size, ShmPermissions::default(), flags)
    } else {
        SHM_MANAGER.get_by_key(key).ok_or(ShmError::NotFound)
    }
}

fn attach_region(id: ShmId, token: Option<u64>) -> Result<ShmHandle, ShmError> {
    SHM_MANAGER.attach_with_token(id, token)
}

fn create_or_get_named(name: &str, size: ShmSize, flags: ShmFlags) -> Result<ShmId, ShmError> {
    if flags.create {
        SHM_MANAGER.create_named(name, size, ShmPermissions::default(), flags)
    } else {
        SHM_MANAGER.get_by_name(name).ok_or(ShmError::NotFound)
    }
}

fn remove_named(name: &str) -> Result<(), ShmError> {
    let id = SHM_MANAGER.get_by_name(name).ok_or(ShmError::NotFound)?;
    SHM_MANAGER.remove(id)
}

/// shmget() 相当
#[cfg(feature = "legacy-posix")]
pub fn shmget(key: ShmKey, size: ShmSize, flags: ShmFlags) -> Result<ShmId, ShmError> {
    create_or_get_by_key(key, size, flags)
}

/// shmat() 相当 (従来互換: トークンなし)
#[cfg(feature = "legacy-posix")]
pub fn shmat(id: ShmId) -> Result<ShmHandle, ShmError> {
    attach_region(id, None)
}

/// shmat() with optional token: attach with a capability token id to register in-flight usage
#[cfg(feature = "legacy-posix")]
pub fn shmat_with_token(id: ShmId, token: Option<u64>) -> Result<ShmHandle, ShmError> {
    attach_region(id, token)
}

/// shmdt() 相当 (ShmHandle::detach を使用)

/// shmctl() 相当 - 削除
#[cfg(feature = "legacy-posix")]
pub fn shmctl_remove(id: ShmId) -> Result<(), ShmError> {
    SHM_MANAGER.remove(id)
}

/// shmctl() 相当 - 情報取得
#[cfg(feature = "legacy-posix")]
pub fn shmctl_stat(id: ShmId) -> Option<ShmInfo> {
    SHM_MANAGER.info(id)
}

// --- POSIX 名前付き共有メモリ風 API ---

/// shm_open() 相当
#[cfg(feature = "legacy-posix")]
pub fn shm_open(name: &str, size: ShmSize, flags: ShmFlags) -> Result<ShmId, ShmError> {
    create_or_get_named(name, size, flags)
}

/// shm_unlink() 相当
#[cfg(feature = "legacy-posix")]
pub fn shm_unlink(name: &str) -> Result<(), ShmError> {
    remove_named(name)
}

// ============================================================================
// Zero-Copy Shared Memory - 設計書 5.3: RRef<T>によるゼロコピーIPC
// ============================================================================

use crate::ipc::rref::{DomainId, RRef};

/// 共有メモリベースのゼロコピーリージョン
///
/// 設計書 5.3: RRef<T>と統合した共有メモリアクセス
pub struct ZeroCopyRegion<T> {
    /// 基底となる共有メモリハンドル
    handle: ShmHandle,
    /// 所有ドメイン
    owner: DomainId,
    /// データ型のファントム
    _marker: core::marker::PhantomData<T>,
}

impl<T: Copy> ZeroCopyRegion<T> {
    /// 新しいゼロコピーリージョンを作成
    pub fn new(name: &str, owner: DomainId) -> Result<Self, ShmError> {
        let size = ShmSize::new(core::mem::size_of::<T>());
        let id = create_or_get_named(
            name,
            size,
            ShmFlags {
                create: true,
                ..Default::default()
            },
        )?;
        let handle = attach_region(id, None)?;

        Ok(Self {
            handle,
            owner,
            _marker: core::marker::PhantomData,
        })
    }

    /// 既存のリージョンを開く
    pub fn open(name: &str, owner: DomainId) -> Result<Self, ShmError> {
        let id = SHM_MANAGER.get_by_name(name).ok_or(ShmError::NotFound)?;
        let handle = attach_region(id, None)?;

        Ok(Self {
            handle,
            owner,
            _marker: core::marker::PhantomData,
        })
    }

    /// RRef<T>として値を読み取り
    ///
    /// 注意: 共有メモリからの読み取りではコピーが発生するが、
    /// 返されるRRefはExchange Heap上に配置され、以後はゼロコピーで
    /// 他のドメインに転送可能
    pub fn read_as_rref(&self) -> Result<RRef<T>, ShmError> {
        let slice = self.handle.read().ok_or(ShmError::NotAttached)?;

        if slice.len() < core::mem::size_of::<T>() {
            return Err(ShmError::InvalidSize);
        }
        let value: T = crate::util::read_struct(slice, 0).ok_or(ShmError::InvalidSize)?;

        Ok(RRef::new(self.owner, value))
    }

    /// RRef<T>から値を書き込み
    ///
    /// 注意: RRefからの所有権移動後、共有メモリへの書き込みが発生
    pub fn write_from_rref(&self, rref: RRef<T>) -> Result<(), ShmError> {
        let value = rref.into_inner();
        let slice = self.handle.write().ok_or(ShmError::NotAttached)?;

        if slice.len() < core::mem::size_of::<T>() {
            return Err(ShmError::InvalidSize);
        }
        crate::util::write_struct(slice, 0, value).ok_or(ShmError::InvalidSize)?;

        Ok(())
    }

    /// 生の値を直接書き込み（ゼロコピーではない）
    pub fn write(&self, value: T) -> Result<(), ShmError> {
        let slice = self.handle.write().ok_or(ShmError::NotAttached)?;

        if slice.len() < core::mem::size_of::<T>() {
            return Err(ShmError::InvalidSize);
        }
        crate::util::write_struct(slice, 0, value).ok_or(ShmError::InvalidSize)?;

        Ok(())
    }

    /// 生の値を直接読み取り（ゼロコピーではない）
    pub fn read(&self) -> Result<T, ShmError> {
        let slice = self.handle.read().ok_or(ShmError::NotAttached)?;

        if slice.len() < core::mem::size_of::<T>() {
            return Err(ShmError::InvalidSize);
        }
        let value = crate::util::read_struct(slice, 0).ok_or(ShmError::InvalidSize)?;

        Ok(value)
    }

    /// 所有ドメインを取得
    pub fn owner(&self) -> DomainId {
        self.owner
    }
}

/// 共有メモリ上のリングバッファ（プロデューサー・コンシューマー間のゼロコピー通信）
///
/// 設計書 5.3: SAS環境での効率的なIPC
pub struct SharedRingBuffer<T: Copy> {
    /// 共有メモリハンドル
    handle: ShmHandle,
    /// プロデューサードメイン
    producer: DomainId,
    /// コンシューマードメイン  
    consumer: DomainId,
    /// 容量（要素数）
    capacity: usize,
    /// ファントム
    _marker: core::marker::PhantomData<T>,
}

/// 共有リングバッファヘッダー
#[repr(C)]
pub(crate) struct SharedRingHeader {
    /// 書き込み位置
    write_pos: AtomicUsize,
    /// 読み取り位置
    read_pos: AtomicUsize,
    /// 容量
    capacity: usize,
    /// 要素サイズ
    element_size: usize,
}

impl<T: Copy> SharedRingBuffer<T> {
    /// 新しい共有リングバッファを作成
    pub fn create(
        name: &str,
        capacity: usize,
        producer: DomainId,
        consumer: DomainId,
    ) -> Result<Self, ShmError> {
        let element_size = core::mem::size_of::<T>();
        let header_size = core::mem::size_of::<SharedRingHeader>();
        let total_size = header_size + capacity * element_size;

        let id = create_or_get_named(
            name,
            ShmSize::new(total_size),
            ShmFlags {
                create: true,
                exclusive: true,
                ..Default::default()
            },
        )?;
        let handle = attach_region(id, None)?;

        // ヘッダーを初期化
        let slice = handle.write().ok_or(ShmError::NotAttached)?;
        let header = crate::util::get_mut_ref::<SharedRingHeader>(slice, 0)
            .ok_or(ShmError::InvalidAddress)?;
        header.write_pos = AtomicUsize::new(0);
        header.read_pos = AtomicUsize::new(0);
        header.capacity = capacity;
        header.element_size = element_size;

        Ok(Self {
            handle,
            producer,
            consumer,
            capacity,
            _marker: core::marker::PhantomData,
        })
    }

    /// 既存の共有リングバッファを開く
    pub fn open(name: &str, producer: DomainId, consumer: DomainId) -> Result<Self, ShmError> {
        let id = SHM_MANAGER.get_by_name(name).ok_or(ShmError::NotFound)?;
        let handle = attach_region(id, None)?;

        // ヘッダーから容量を読み取り（Borrowを短く保つ）
        let capacity_val = {
            let slice = handle.read().ok_or(ShmError::NotAttached)?;
            let header = crate::util::get_ref::<SharedRingHeader>(slice, 0)
                .ok_or(ShmError::InvalidAddress)?;
            header.capacity
        };

        Ok(Self {
            handle,
            producer,
            consumer,
            capacity: capacity_val,
            _marker: core::marker::PhantomData,
        })
    }

    /// 要素を書き込み（プロデューサー用）
    pub fn push(&self, value: T) -> Result<(), ShmError> {
        let slice = self.handle.write().ok_or(ShmError::NotAttached)?;
        // Read header atomically, then drop the reference before mutably writing
        let (write_pos, read_pos) = {
            let header = crate::util::get_ref::<SharedRingHeader>(slice, 0)
                .ok_or(ShmError::InvalidAddress)?;
            (
                header.write_pos.load(Ordering::Acquire),
                header.read_pos.load(Ordering::Acquire),
            )
        };

        // フルチェック
        let next_write = (write_pos + 1) % self.capacity;
        if next_write == read_pos {
            return Err(ShmError::OutOfMemory); // バッファフル
        }

        // データを書き込み
        let header_size = core::mem::size_of::<SharedRingHeader>();
        let element_size = core::mem::size_of::<T>();
        let offset = header_size + write_pos * element_size;

        crate::util::write_struct(slice, offset, value).ok_or(ShmError::InvalidSize)?;

        // write_posを更新
        let header =
            crate::util::get_ref::<SharedRingHeader>(slice, 0).ok_or(ShmError::InvalidAddress)?;
        header.write_pos.store(next_write, Ordering::Release);

        Ok(())
    }

    /// 要素を読み取り（コンシューマー用）
    pub fn pop(&self) -> Result<T, ShmError> {
        let slice = self.handle.read().ok_or(ShmError::NotAttached)?;
        let header =
            crate::util::get_ref::<SharedRingHeader>(slice, 0).ok_or(ShmError::InvalidAddress)?;

        let write_pos = header.write_pos.load(Ordering::Acquire);
        let read_pos = header.read_pos.load(Ordering::Acquire);

        // 空チェック
        if read_pos == write_pos {
            return Err(ShmError::NotFound); // バッファ空
        }

        // データを読み取り
        let header_size = core::mem::size_of::<SharedRingHeader>();
        let element_size = core::mem::size_of::<T>();
        let offset = header_size + read_pos * element_size;

        let value: T = crate::util::read_struct(slice, offset).ok_or(ShmError::InvalidSize)?;

        // read_posを更新
        let next_read = (read_pos + 1) % self.capacity;
        header.read_pos.store(next_read, Ordering::Release);

        Ok(value)
    }

    /// RRefとして読み取り（Exchange Heapに移動）
    pub fn pop_as_rref(&self) -> Result<RRef<T>, ShmError> {
        let value = self.pop()?;
        Ok(RRef::new(self.consumer, value))
    }

    /// バッファが空か
    pub fn is_empty(&self) -> bool {
        if let Some(slice) = self.handle.read() {
            if let Some(header) = crate::util::get_ref::<SharedRingHeader>(slice, 0) {
                header.write_pos.load(Ordering::Acquire) == header.read_pos.load(Ordering::Acquire)
            } else {
                true
            }
        } else {
            true
        }
    }

    /// バッファがフルか
    pub fn is_full(&self) -> bool {
        if let Some(slice) = self.handle.read() {
            if let Some(header) = crate::util::get_ref::<SharedRingHeader>(slice, 0) {
                let write_pos = header.write_pos.load(Ordering::Acquire);
                let read_pos = header.read_pos.load(Ordering::Acquire);
                (write_pos + 1) % self.capacity == read_pos
            } else {
                true
            }
        } else {
            true
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
