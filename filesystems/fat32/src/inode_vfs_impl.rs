use crate::*;
use vfs::{Directory, File, Metadata, SeekFrom};

impl<B: ZeroCopyBufferMut + 'static> Inode for Fat32Inode<B> {
    fn metadata(&self) -> FsResult<Metadata> {
        let attr = self.getattr()?;
        let inner = self.inner.blocking_lock();
        Ok(Metadata {
            file_type: Some(self.file_type),
            size: inner.size,
            created: inner.created,
            modified: inner.modified,
            accessed: inner.accessed,
            readonly: inner.attributes.is_read_only(),
        })
    }

    fn open(&self, _flags: OpenFlags) -> FsResult<Box<dyn File>> {
        Ok(Box::new(Fat32File {
            inode: Arc::new(self.clone()),
            position: 0,
        }))
    }

    fn as_dir(&self) -> FsResult<Box<dyn Directory>> {
        if self.file_type != FileType::Directory {
            return Err(FsError::NotADirectory);
        }
        Ok(Box::new(Fat32Directory {
            inode: Arc::new(self.clone()),
        }))
    }

    fn name(&self) -> String {
        let inner = self.inner.blocking_lock();
        inner.name.clone()
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}


impl<B: ZeroCopyBufferMut + 'static> Clone for Fat32Inode<B> {
    fn clone(&self) -> Self {
        Self {
            fs: self.fs.clone(),
            file_type: self.file_type,
            inner: AsyncMutex::new(self.inner.blocking_lock().clone()),
        }
    }
}

impl<B: ZeroCopyBufferMut + 'static> File for Fat32File<B> {
    fn read(&mut self, buf: &mut [u8]) -> FsResult<usize> {
        let n = self.inode.read(self.position, buf)?;
        self.position += n as u64;
        Ok(n)
    }

    fn write(&mut self, buf: &[u8]) -> FsResult<usize> {
        let n = self.inode.write(self.position, buf)?;
        self.position += n as u64;
        Ok(n)
    }

    fn seek(&mut self, pos: SeekFrom) -> FsResult<u64> {
        let new_pos = match pos {
            SeekFrom::Start(off) => off,
            SeekFrom::End(off) => {
                let size = self.inode.getattr()?.size;
                if off < 0 {
                    size.checked_sub((-off) as u64)
                        .ok_or(FsError::InvalidInput)?
                } else {
                    size + off as u64
                }
            }
            SeekFrom::Current(off) => {
                if off < 0 {
                    self.position
                        .checked_sub((-off) as u64)
                        .ok_or(FsError::InvalidInput)?
                } else {
                    self.position + off as u64
                }
            }
        };
        self.position = new_pos;
        Ok(new_pos)
    }

    fn flush(&mut self) -> FsResult<()> {
        Ok(())
    }

    fn set_len(&mut self, size: u64) -> FsResult<()> {
        let mut attr = self.inode.getattr()?;
        attr.size = size;
        self.inode.setattr(&attr)
    }
}

impl<B: ZeroCopyBufferMut + 'static> Directory for Fat32Directory<B> {
    fn lookup(&self, name: &str) -> FsResult<Box<dyn Inode>> {
        let inode = self.inode.lookup(name)?;
        Ok(Box::new(
            Arc::try_unwrap(inode).unwrap_or_else(|arc| (*arc).clone()),
        ))
    }

    fn create(&mut self, name: &str, file_type: FileType) -> FsResult<Box<dyn Inode>> {
        let inode = if file_type == FileType::Directory {
            self.inode
                .mkdir(name, FileMode::from_bits_truncate(0o755))?
        } else {
            self.inode.create(
                name,
                FileMode::from_bits_truncate(0o644),
                OpenFlags::empty(),
            )?
        };
        Ok(Box::new(
            Arc::try_unwrap(inode).unwrap_or_else(|arc| (*arc).clone()),
        ))
    }

    fn remove(&mut self, name: &str) -> FsResult<()> {
        let target = self.inode.lookup(name)?;
        if target.getattr()?.file_type == Some(FileType::Directory) {
            self.inode.rmdir(name)
        } else {
            self.inode.unlink(name)
        }
    }

    fn read_dir(&mut self) -> FsResult<Vec<DirEntry>> {
        self.inode.readdir(0)
    }
}

