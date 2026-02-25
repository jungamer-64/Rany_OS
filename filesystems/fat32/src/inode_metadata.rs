use crate::{
    Fat32Inode,
    FileAttr,
    FsResult,
    ZeroCopyBufferMut,
};

impl<B: ZeroCopyBufferMut + 'static> Fat32Inode<B> {
    pub fn getattr(&self) -> FsResult<FileAttr> {
        let inner = self.inner.blocking_lock();
        Ok(FileAttr {
            file_type: Some(self.file_type),
            size: inner.size,
            created: inner.created,
            modified: inner.modified,
            accessed: inner.accessed,
            readonly: inner.attributes.is_read_only(),
        })
    }

    /// 非同期で属性を取得
    pub async fn getattr_async(&self) -> FsResult<FileAttr> {
        self.getattr()
    }

    pub fn setattr(&self, attr: &FileAttr) -> FsResult<()> {
        let mut size_changed = false;
        {
            let mut inner = self.inner.blocking_lock();
            if attr.size != inner.size {
                size_changed = true;
            }
            if attr.created > 0 {
                inner.created = attr.created;
            }
            if attr.modified > 0 {
                inner.modified = attr.modified;
            }
            if attr.accessed > 0 {
                inner.accessed = attr.accessed;
            }
        }

        if size_changed {
            self.truncate(attr.size)?;
        }

        self.sync_metadata()?;
        Ok(())
    }

    /// 非同期で属性を設定
    pub async fn setattr_async(&self, attr: &FileAttr) -> FsResult<()> {
        let mut size_changed = false;
        {
            let mut inner = self.inner.blocking_lock();
            if attr.size != inner.size {
                size_changed = true;
            }
            if attr.created > 0 {
                inner.created = attr.created;
            }
            if attr.modified > 0 {
                inner.modified = attr.modified;
            }
            if attr.accessed > 0 {
                inner.accessed = attr.accessed;
            }
        }

        if size_changed {
            self.truncate_async(attr.size).await?;
        } else {
            self.sync_metadata_async().await?;
        }

        Ok(())
    }
}
