use super::*;

pub(crate) fn open_with_token(
    path: &str,
    mode: OpenMode,
    token: Option<u64>,
) -> Result<FileHandle, KapiError> {
    use crate::fs::memfs;

    let path_buf = alloc::string::String::from(path);

    match mode {
        OpenMode::Read => {
            if memfs::stat_file(&path_buf, "/").is_err() {
                return Err(KapiError::NotFound);
            }
        }
        OpenMode::Write | OpenMode::ReadWrite | OpenMode::Append | OpenMode::Create => {
            if memfs::stat_file(&path_buf, "/").is_err()
                && memfs::touch_file(&path_buf, "/").is_err()
            {
                return Err(KapiError::IoError);
            }
        }
    }

    let caller = context::current_subject().domain.as_u64();
    if let Some(t) = token {
        if !crate::security::capability::manager().validate_token(
            caller,
            t,
            crate::security::capability::CAP_FOWNER,
        ) {
            return Err(KapiError::PermissionDenied);
        }

        if crate::security::capability::manager()
            .increment_in_flight(t)
            .is_err()
        {
            return Err(KapiError::PermissionDenied);
        }
    }

    let handle_id = crate::resource_registry::fs::register_handle(
        crate::resource_registry::fs::FileHandleEntry {
            path: path_buf,
            mode,
            position: 0,
            token,
            owner: caller,
        },
    );

    Ok(FileHandle::new(handle_id, mode))
}

pub(crate) fn close(handle: FileHandle) -> Result<(), KapiError> {
    let handle_id = handle.id();
    if let Some(entry) = crate::resource_registry::fs::unregister_handle(handle_id) {
        if let Some(t) = entry.token {
            let _ = crate::security::capability::manager().decrement_in_flight(t);
        }
        Ok(())
    } else {
        Err(KapiError::InvalidHandle)
    }
}
