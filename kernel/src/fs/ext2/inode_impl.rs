use super::*;


impl Inode for Ext2InodeWrapper {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn getattr(&self) -> FsResult<FileAttr> {
        Ok(FileAttr {
            ino: self.inode_num as InodeNum,
            size: self.inode.file_size(),
            blocks: self.inode.blocks as u64,
            file_type: self.inode.file_type(),
            mode: FileMode(self.inode.mode & 0x0FFF),
            nlink: self.inode.links_count as u32,
            uid: self.inode.uid as u32,
            gid: self.inode.gid as u32,
            rdev: 0,
            blksize: self.fs.block_size,
            atime: self.inode.atime as u64 * 1_000_000_000,
            mtime: self.inode.mtime as u64 * 1_000_000_000,
            ctime: self.inode.ctime as u64 * 1_000_000_000,
        })
    }

    fn setattr(&self, _attr: &FileAttr) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    fn lookup(&self, name: &str) -> FsResult<Arc<dyn Inode>> {
        let entries = self.read_dir_entries()?;

        for (entry_name, inode_num, _) in entries {
            if entry_name == name {
                let inode = self.fs.read_inode(inode_num)?;
                return Ok(Arc::new(Ext2InodeWrapper {
                    fs: self.fs.clone(),
                    inode_num,
                    inode,
                }));
            }
        }

        Err(FsError::NotFound)
    }

    fn readdir(&self, _offset: u64) -> FsResult<Vec<DirEntry>> {
        let entries = self.read_dir_entries()?;

        Ok(entries
            .into_iter()
            .map(|(name, ino, file_type)| DirEntry {
                name,
                ino: ino as InodeNum,
                file_type,
            })
            .collect())
    }

    fn create(&self, _name: &str, _mode: FileMode, _flags: OpenFlags) -> FsResult<Arc<dyn Inode>> {
        Err(FsError::NotSupported)
    }

    fn mkdir(&self, _name: &str, _mode: FileMode) -> FsResult<Arc<dyn Inode>> {
        Err(FsError::NotSupported)
    }

    fn unlink(&self, _name: &str) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    fn rmdir(&self, _name: &str) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    fn rename(&self, _old_name: &str, _new_dir: &Arc<dyn Inode>, _new_name: &str) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    fn link(&self, _name: &str, _inode: &Arc<dyn Inode>) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    fn symlink(&self, _name: &str, _target: &str) -> FsResult<Arc<dyn Inode>> {
        Err(FsError::NotSupported)
    }

    fn readlink(&self) -> FsResult<String> {
        if self.inode.file_type() != FileType::Symlink {
            return Err(FsError::InvalidArgument);
        }

        // 小さなシンボリックリンクはinodeに直接格納される
        let size = self.inode.file_size();
        if size <= 60 {
            // packed structのフィールドを安全に読み取り
            let block: [u32; 15] = unsafe {
                let ptr = core::ptr::addr_of!(self.inode.block);
                core::ptr::read_unaligned(ptr)
            };
            let bytes: &[u8] =
                unsafe { core::slice::from_raw_parts(block.as_ptr() as *const u8, size as usize) };
            return Ok(String::from_utf8_lossy(bytes).into_owned());
        }

        // 大きなシンボリックリンクはデータブロックに格納
        let mut buffer = vec![0u8; size as usize];
        let bytes_read = self.read(0, &mut buffer)?;
        buffer.truncate(bytes_read);

        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }

    fn read(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        let size = self.inode.file_size();
        if offset >= size {
            return Ok(0);
        }

        let to_read = buf.len().min((size - offset) as usize);
        let block_size = self.fs.block_size as u64;
        let mut bytes_read = 0usize;
        let mut current_offset = offset;

        while bytes_read < to_read {
            let logical_block = (current_offset / block_size) as u32;
            let block_offset = (current_offset % block_size) as usize;

            let physical_block = self.fs.get_block_num(&self.inode, logical_block)?;
            if physical_block == 0 {
                // スパースファイル：ゼロで埋める
                let available = (block_size as usize - block_offset).min(to_read - bytes_read);
                for i in 0..available {
                    buf[bytes_read + i] = 0;
                }
                bytes_read += available;
                current_offset += available as u64;
                continue;
            }

            let mut block_buffer = vec![0u8; self.fs.block_size as usize];
            self.fs.read_block(physical_block, &mut block_buffer)?;

            let available = (block_size as usize - block_offset).min(to_read - bytes_read);
            buf[bytes_read..bytes_read + available]
                .copy_from_slice(&block_buffer[block_offset..block_offset + available]);

            bytes_read += available;
            current_offset += available as u64;
        }

        Ok(bytes_read)
    }

    fn write(&self, _offset: u64, _buf: &[u8]) -> FsResult<usize> {
        Err(FsError::NotSupported)
    }

    fn truncate(&self, _size: u64) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    fn fsync(&self, _datasync: bool) -> FsResult<()> {
        self.fs.sync()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

