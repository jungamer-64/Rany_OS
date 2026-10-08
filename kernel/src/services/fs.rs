use super::*;
use kernel_api::resource::fs::FsMutationError;

pub(super) async fn open_with_token(
    path: &str,
    mode: OpenMode,
    token: Option<u64>,
) -> Result<FileHandle, FsMutationError> {
    use crate::fs::memfs;

    let caller = current_subject().domain.as_u64();
    let token = token
        .map(|token_id| {
            crate::security::capability::manager().retain_token(
                caller,
                token_id,
                crate::security::capability::CAP_FOWNER,
            )
        })
        .transpose()
        .map_err(|cause| {
            FsMutationError::Filesystem(match cause {
                crate::security::capability::CapabilityError::ReclamationBusy => KapiError::Busy,
                _ => KapiError::PermissionDenied,
            })
        })?;
    let path_buf = alloc::string::String::from(path);

    match mode {
        OpenMode::Read => {
            if memfs::stat_file(&path_buf, "/").is_err() {
                return Err(FsMutationError::Filesystem(KapiError::NotFound));
            }
        }
        OpenMode::Write | OpenMode::ReadWrite | OpenMode::Append | OpenMode::Create => {
            if memfs::stat_file(&path_buf, "/").is_err() {
                memfs::touch_file(&path_buf, "/")
                    .await
                    .map_err(mutation_error)?;
            }
        }
    }

    let handle_id = crate::resource_registry::fs::register_handle(
        crate::resource_registry::fs::FileHandleEntry {
            token,
            owner: caller,
        },
    );

    Ok(FileHandle::new(handle_id, mode))
}

pub(super) fn mutation_error(cause: crate::fs::FsError) -> FsMutationError {
    use crate::fs::FsError;
    match cause {
        FsError::MemoryCommitted(cause) => FsMutationError::MemoryCommitted(cause),
        FsError::JournalUnavailable(cause) => FsMutationError::JournalUnavailable(cause),
        FsError::MutationRecoveryRequired { intent_bytes } => {
            FsMutationError::RecoveryRequired { intent_bytes }
        }
        cause => FsMutationError::Filesystem(match cause {
            FsError::NotFound => KapiError::NotFound,
            FsError::PermissionDenied | FsError::ReadOnly => KapiError::PermissionDenied,
            FsError::AlreadyExists => KapiError::AlreadyExists,
            FsError::NoSpace | FsError::TooManyOpenFiles => KapiError::ResourceExhausted,
            FsError::NotSupported => KapiError::NotSupported,
            _ => KapiError::IoError,
        }),
    }
}

pub(super) fn close(handle: FileHandle) -> Result<(), KapiError> {
    let handle_id = handle.id();
    let caller = current_subject().domain.as_u64();
    match crate::resource_registry::fs::unregister_handle_owned(handle_id, caller) {
        Ok(entry) => {
            drop(entry.token);
            Ok(())
        }
        Err(crate::resource_registry::fs::FileHandleError::InvalidHandle) => {
            Err(KapiError::InvalidHandle)
        }
        Err(crate::resource_registry::fs::FileHandleError::PermissionDenied) => {
            Err(KapiError::PermissionDenied)
        }
    }
}
