use crate::*;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;

    // --- Existing tests ---

    pub fn cluster_smoke() -> bool {
        let c = Cluster(10);
        c.is_valid() && !c.is_free() && !c.is_eof()
    }

    pub fn next_cluster_smoke() -> bool {
        NextCluster::from_fat_entry(Cluster::EOF) == NextCluster::Eof
    }

    pub fn sector_smoke() -> bool {
        let s = Sector(123);
        s.as_u64() == 123
    }

    // --- Migrated from #[cfg(test)] mod tests ---

    pub fn short_name_smoke() -> bool {
        let entry = DirEntryRaw::new(
            *b"TEST    ",
            *b"TXT",
            FileAttributes::from_bits_truncate(0),
            Cluster(0),
            0,
        );
        entry.name == *b"TEST    " && entry.ext == *b"TXT"
    }

    pub fn checksum_smoke() -> bool {
        let entry = DirEntryRaw::new(
            *b"TEST    ",
            *b"TXT",
            FileAttributes::from_bits_truncate(0),
            Cluster(0),
            0,
        );
        entry.calculate_checksum() != 0
    }

    pub fn cluster_validation_smoke() -> bool {
        Cluster(2).is_valid()
            && Cluster(100).is_valid()
            && Cluster(0x0FFFFFF0 - 1).is_valid()
            && !Cluster(0).is_valid()
            && !Cluster(1).is_valid()
            && !Cluster::EOF.is_valid()
            && !Cluster::BAD.is_valid()
    }

    pub fn cluster_special_values_smoke() -> bool {
        Cluster::FREE.is_free() && Cluster::EOF.is_eof() && Cluster(0x0FFFFFFF).is_eof()
    }

    pub fn cluster_contiguity_smoke() -> bool {
        let c1 = Cluster(100);
        let c2 = Cluster(101);
        let c3 = Cluster(102);
        let c5 = Cluster(105);
        c1.is_contiguous_with(c2)
            && c2.is_contiguous_with(c3)
            && !c1.is_contiguous_with(c3)
            && !c1.is_contiguous_with(c5)
    }

    pub fn cluster_in_range_smoke() -> bool {
        const MAX_CLUSTERS: u32 = 65525;
        Cluster::in_range(2, MAX_CLUSTERS)
            && Cluster::in_range(100, MAX_CLUSTERS)
            && Cluster::in_range(65524, MAX_CLUSTERS)
            && !Cluster::in_range(0, MAX_CLUSTERS)
            && !Cluster::in_range(1, MAX_CLUSTERS)
            && !Cluster::in_range(65525, MAX_CLUSTERS)
            && !Cluster::in_range(100000, MAX_CLUSTERS)
    }

    pub fn file_offset_calculation_smoke() -> bool {
        let o1 = FileOffset(8192);
        let o2 = FileOffset(5000);
        let o3 = FileOffset(0);
        o1.cluster_index(4096) == 2
            && o1.offset_in_cluster(4096) == 0
            && o2.cluster_index(4096) == 1
            && o2.offset_in_cluster(4096) == 904
            && o3.cluster_index(4096) == 0
            && o3.offset_in_cluster(4096) == 0
    }

    pub fn file_offset_in_range_smoke() -> bool {
        const FILE_SIZE: u64 = 1024 * 1024;
        FileOffset::in_range(0, FILE_SIZE)
            && FileOffset::in_range(500, FILE_SIZE)
            && FileOffset::in_range(FILE_SIZE - 1, FILE_SIZE)
            && !FileOffset::in_range(FILE_SIZE, FILE_SIZE)
            && !FileOffset::in_range(FILE_SIZE + 1, FILE_SIZE)
    }

    pub fn file_offset_arithmetic_smoke() -> bool {
        let offset = FileOffset(100);
        let new_offset = offset + 50usize;
        new_offset.as_u64() == 150
    }

    pub fn byte_count_operations_smoke() -> bool {
        let a = ByteCount(100);
        let b = ByteCount(50);
        a.min(b) == b && b.min(a) == b && (a - b).as_usize() == 50 && (a + b).as_usize() == 150
    }

    pub fn byte_count_saturating_sub_smoke() -> bool {
        let a = ByteCount(50);
        let b = ByteCount(100);
        (a - b).as_usize() == 0
    }

    pub fn byte_count_empty_smoke() -> bool {
        ByteCount::ZERO.is_empty() && ByteCount(0).is_empty() && !ByteCount(1).is_empty()
    }

    pub fn next_cluster_from_fat_entry_smoke() -> bool {
        NextCluster::from_fat_entry(Cluster::FREE) == NextCluster::Free
            && NextCluster::from_fat_entry(Cluster::EOF) == NextCluster::Eof
            && NextCluster::from_fat_entry(Cluster::BAD) == NextCluster::Bad
            && NextCluster::from_fat_entry(Cluster(100)) == NextCluster::Valid(Cluster(100))
    }

    pub fn next_cluster_as_valid_smoke() -> bool {
        NextCluster::Valid(Cluster(100)).as_valid() == Some(Cluster(100))
            && NextCluster::Eof.as_valid().is_none()
            && NextCluster::Free.as_valid().is_none()
            && NextCluster::Bad.as_valid().is_none()
    }

    pub fn file_attributes_smoke() -> bool {
        let attrs = FileAttributes::from_bits_truncate(0x21);
        attrs.is_read_only()
            && (attrs.bits() & FileAttributes::ARCHIVE) != 0
            && !attrs.is_hidden()
            && !attrs.is_system()
            && !attrs.is_directory()
    }

    pub fn file_attributes_directory_smoke() -> bool {
        let attrs = FileAttributes::from_bits_truncate(0x10);
        attrs.is_directory() && !attrs.is_read_only()
    }

    pub fn mount_minimal_boot_sector_smoke() -> bool {
        use vfs::block::RamDisk;
        let disk = Arc::new(RamDisk::new(2048, 512));

        let mut bs = [0u8; BOOT_SECTOR_SIZE];
        bs[11..13].copy_from_slice(&512u16.to_le_bytes());
        bs[13] = 1;
        bs[14..16].copy_from_slice(&32u16.to_le_bytes());
        bs[16] = 2;
        bs[32..36].copy_from_slice(&4096u32.to_le_bytes());
        bs[36..40].copy_from_slice(&1u32.to_le_bytes());
        bs[44..48].copy_from_slice(&2u32.to_le_bytes());
        bs[82..90].copy_from_slice(b"FAT32   ");
        bs[510] = 0x55;
        bs[511] = 0xAA;

        if disk.write_sync(0, &bs).is_err() {
            return false;
        }
        let fs = match DefaultFat32FileSystem::mount(disk) {
            Ok(fs) => fs,
            Err(_) => return false,
        };
        (&*fs).root_cluster == Cluster(2)
    }

    pub fn write_and_flush_fat_entry_smoke() -> bool {
        use vfs::block::RamDisk;
        let disk = Arc::new(RamDisk::new(2048, 512));

        let mut bs = [0u8; BOOT_SECTOR_SIZE];
        bs[11..13].copy_from_slice(&512u16.to_le_bytes());
        bs[13] = 1;
        bs[14..16].copy_from_slice(&1u16.to_le_bytes());
        bs[16] = 2;
        bs[32..36].copy_from_slice(&4096u32.to_le_bytes());
        bs[36..40].copy_from_slice(&1u32.to_le_bytes());
        bs[44..48].copy_from_slice(&2u32.to_le_bytes());
        bs[82..90].copy_from_slice(b"FAT32   ");
        bs[510] = 0x55;
        bs[511] = 0xAA;

        if disk.write_sync(0, &bs).is_err() {
            return false;
        }
        let fs = match DefaultFat32FileSystem::mount(disk.clone()) {
            Ok(fs) => fs,
            Err(_) => return false,
        };

        if fs.write_fat_entry(Cluster(2), Cluster::EOF).is_err() {
            return false;
        }
        if !fs.fat_sector_cache.has_dirty() {
            return false;
        }
        if fs.sync().is_err() {
            return false;
        }
        if fs.fat_sector_cache.has_dirty() {
            return false;
        }

        let mut buf = [0u8; BLOCK_SIZE];
        let device = match fs.legacy_device.as_ref() {
            Some(d) => d,
            None => return false,
        };
        if device
            .read_sync(fs.fat_start_sector.as_u64(), &mut buf)
            .is_err()
        {
            return false;
        }

        let offset = 2 * 4;
        let val = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]) & 0x0FFFFFFF;
        val == (Cluster::EOF.0 & 0x0FFFFFFF)
    }

    pub fn file_attributes_lfn_smoke() -> bool {
        let attrs = FileAttributes::from_bits_truncate(0x0F);
        attrs.is_long_name()
    }

    pub fn lfn_checksum_smoke() -> bool {
        let mut base = [b' '; 8];
        base[0..4].copy_from_slice(b"TEST");
        let mut ext = [b' '; 3];
        ext[0..3].copy_from_slice(b"TXT");
        let entry = DirEntryRaw::new(
            base,
            ext,
            FileAttributes::from_bits_truncate(0),
            Cluster(2),
            0,
        );
        entry.calculate_checksum() == 0x8F
    }

    pub fn fat_sector_cache_update_and_dirty_smoke() -> bool {
        let cache = FatSectorCache::new(2);
        let mut data = Vec::with_capacity(FAT_ENTRIES_PER_SECTOR);
        for i in 0..FAT_ENTRIES_PER_SECTOR {
            data.push(Cluster(i as u32));
        }

        cache.insert(5, data);
        if cache.get(5).is_none() {
            return false;
        }
        if !cache.update_entry(5, 2, Cluster(42)) {
            return false;
        }
        let got_arc = match cache.get(5) {
            Some(a) => a,
            None => return false,
        };
        let got = got_arc.lock();
        if got[2] != Cluster(42) {
            return false;
        }
        if !cache.has_dirty() {
            return false;
        }
        let dirty = cache.take_dirty_sectors();
        dirty.iter().any(|(idx, _)| *idx == 5)
    }

    pub fn update_entry_if_smoke() -> bool {
        let cache = FatSectorCache::new(2);
        let data = vec![Cluster(0); FAT_ENTRIES_PER_SECTOR];
        cache.insert(7, data);
        if cache.update_entry_if(7, 1, Cluster(1), Cluster(2)) {
            return false;
        }
        if !cache.update_entry_if(7, 1, Cluster(0), Cluster(9)) {
            return false;
        }
        let got_arc = match cache.get(7) {
            Some(a) => a,
            None => return false,
        };
        let got = got_arc.lock();
        got[1] == Cluster(9)
    }

    pub fn dir_entry_cache_arc_smoke() -> bool {
        let cache = DirEntryCache::new(2);
        let entry = DirEntryRaw::new(
            *b"A       ",
            *b"TXT",
            FileAttributes::from_bits_truncate(0),
            Cluster(2),
            10,
        );
        let entries = vec![(String::from("a"), entry)];
        cache.insert(Cluster(2), entries.clone());
        let got = match cache.get(Cluster(2)) {
            Some(g) => g,
            None => return false,
        };
        &*got == entries.as_slice()
    }

    pub fn cluster_chain_cycle_detection_smoke() -> bool {
        use vfs::block::RamDisk;
        let disk = Arc::new(RamDisk::new(65536, 512));

        let mut bs = [0u8; BOOT_SECTOR_SIZE];
        bs[11..13].copy_from_slice(&512u16.to_le_bytes());
        bs[13] = 1;
        bs[14..16].copy_from_slice(&32u16.to_le_bytes());
        bs[16] = 2;
        bs[32..36].copy_from_slice(&4096u32.to_le_bytes());
        bs[36..40].copy_from_slice(&1u32.to_le_bytes());
        bs[44..48].copy_from_slice(&2u32.to_le_bytes());
        bs[82..90].copy_from_slice(b"FAT32   ");
        bs[510] = 0x55;
        bs[511] = 0xAA;

        if disk.write_sync(0, &bs).is_err() {
            return false;
        }
        let fs = match DefaultFat32FileSystem::mount(disk) {
            Ok(fs) => fs,
            Err(_) => return false,
        };

        let start = 2u32;
        let chain_len = 10u32;
        for i in 0..chain_len {
            if fs
                .write_fat_entry_to_disk(Cluster(start + i), Cluster(start + i + 1))
                .is_err()
            {
                return false;
            }
        }
        if fs
            .write_fat_entry_to_disk(Cluster(start + chain_len), Cluster(3))
            .is_err()
        {
            return false;
        }
        fs.fat_sector_cache.clear();

        let mut iter = fs.clusters(Cluster(2));
        loop {
            match iter.next() {
                Some(Ok(_)) => continue,
                Some(Err(_)) => return true,
                None => return false,
            }
        }
    }

    // --- Migrated from async_mutex.rs ---

    pub fn async_mutex_blocking_lock_basic_smoke() -> bool {
        super::async_mutex::qemu_tests::blocking_lock_basic_smoke()
    }

    pub fn async_mutex_wait_then_acquire_smoke() -> bool {
        super::async_mutex::qemu_tests::async_lock_wait_then_acquire_smoke()
    }

    // --- Migrated from irq_lock.rs ---

    pub fn irq_poison_lock_basic_smoke() -> bool {
        super::irq_lock::qemu_tests::basic_locking_smoke()
    }

    pub fn irq_try_lock_smoke() -> bool {
        super::irq_lock::qemu_tests::try_lock_contention_smoke()
    }

    pub fn irq_restore_smoke() -> bool {
        super::irq_lock::qemu_tests::irq_restore_smoke()
    }
