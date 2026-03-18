use super::*;

impl KernelServices for ExoKernel {
    fn nvme_submit_rw(
        &self,
        request: NvmeRwRequest,
        io_type: NvmeIoType,
    ) -> KapiResult<NvmeIoHandle> {
        use crate::io::io_scheduler::{
            DeviceId as IoDeviceId, DmaBufHandle, IoCommand, IoPriority,
        };

        let device = IoDeviceId::Nvme {
            controller: 0,
            namespace: request.namespace_id,
        };

        let priority = match request.priority {
            NvmeIoPriority::Background => IoPriority::Background,
            NvmeIoPriority::Idle => IoPriority::Idle,
            NvmeIoPriority::Normal => IoPriority::Normal,
            NvmeIoPriority::High => IoPriority::High,
            NvmeIoPriority::Realtime => IoPriority::Realtime,
        };

        // Build IoCommand (new API) and submit via submit_io_command
        let command = match io_type {
            NvmeIoType::Read => IoCommand::BlockRead {
                lba: request.lba,
                blocks: request.blocks,
                bytes: request.bytes,
                buf: DmaBufHandle {
                    iova: request.prp1,
                    len: request.bytes,
                },
            },
            NvmeIoType::Write => IoCommand::BlockWrite {
                lba: request.lba,
                blocks: request.blocks,
                bytes: request.bytes,
                buf: DmaBufHandle {
                    iova: request.prp1,
                    len: request.bytes,
                },
            },
            NvmeIoType::Flush => IoCommand::Flush,
            NvmeIoType::Discard => IoCommand::Discard {
                lba: request.lba,
                blocks: request.blocks as u16,
            },
        };

        let future = crate::io::io_scheduler::hybrid_coordinator()
            .submit_io_command(device, command, priority);
        let request_id = future.request_id().0;

        Ok(NvmeIoHandle::new(request_id))
    }

    fn nvme_wait_io(
        &self,
        handle: NvmeIoHandle,
    ) -> Pin<Box<dyn Future<Output = NvmeIoResult> + Send>> {
        use crate::io::io_scheduler::{IoRequestId, IoResult as SchedIoResult};

        let request_id = IoRequestId(handle.request_id());

        Box::pin(async move {
            // Poll the io_scheduler for completion
            // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
            loop {
                if let Some(result) =
                    crate::io::io_scheduler::io_scheduler().take_result(request_id)
                {
                    return match result {
                        SchedIoResult::Success(bytes) => NvmeIoResult::Success(bytes),
                        SchedIoResult::Error(e) => match e {
                            crate::io::io_scheduler::IoError::Timeout => NvmeIoResult::Timeout,
                            crate::io::io_scheduler::IoError::Cancelled => NvmeIoResult::Cancelled,
                            crate::io::io_scheduler::IoError::InvalidParameter => {
                                NvmeIoResult::InvalidParameter
                            }
                            _ => NvmeIoResult::DeviceError,
                        },
                    };
                }
                // Yield to allow other tasks to run
                core::hint::spin_loop();
            }
        })
    }

    fn nvme_register_completion_hook(
        &self,
        handle: NvmeIoHandle,
        hook: Box<dyn FnOnce(NvmeIoResult) + Send>,
    ) {
        use crate::io::io_scheduler::{CompletionHook, IoRequestId, IoResult as SchedIoResult};

        let request_id = IoRequestId(handle.request_id());

        let wrapper: CompletionHook = Box::new(move |result: SchedIoResult| {
            let converted = match result {
                SchedIoResult::Success(bytes) => NvmeIoResult::Success(bytes),
                SchedIoResult::Error(e) => match e {
                    crate::io::io_scheduler::IoError::Timeout => NvmeIoResult::Timeout,
                    crate::io::io_scheduler::IoError::Cancelled => NvmeIoResult::Cancelled,
                    crate::io::io_scheduler::IoError::InvalidParameter => {
                        NvmeIoResult::InvalidParameter
                    }
                    _ => NvmeIoResult::DeviceError,
                },
            };
            hook(converted);
        });

        crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, wrapper);
    }

    fn ipc_create_channel(&self) -> Result<(ChannelHandle, ChannelHandle), KapiError> {
        let (writer_id, reader_id) = CHANNEL_REGISTRY.create_channel();
        Ok((ChannelHandle::new(writer_id), ChannelHandle::new(reader_id)))
    }

    fn ipc_close(&self, channel: ChannelHandle) -> Result<(), KapiError> {
        let channel_id = channel.id();
        if CHANNEL_REGISTRY.unregister(channel_id).is_some() {
            Ok(())
        } else {
            Err(KapiError::InvalidHandle)
        }
    }

    fn ipc_current_domain(&self) -> kernel_api::ipc::DomainId {
        kernel_api::ipc::DomainId::new(context::current_subject().domain.as_u64())
    }

    fn exchange_alloc_raw(
        &self,
        size: usize,
        align: usize,
    ) -> Result<(NonNull<u8>, kernel_api::ipc::DomainId), KapiError> {
        let layout = core::alloc::Layout::from_size_align(size.max(1), align.max(1))
            .map_err(|_| KapiError::InvalidHandle)?;
        let owner = context::current_subject().domain;
        let ptr =
            crate::mm::cache::exchange_heap::allocate_raw(layout).ok_or(KapiError::OutOfMemory)?;
        crate::sas::register_object(ptr.as_ptr() as usize, layout.size(), owner);
        Ok((ptr, kernel_api::ipc::DomainId::new(owner.as_u64())))
    }

    fn exchange_dealloc_raw(
        &self,
        ptr: NonNull<u8>,
        owner: kernel_api::ipc::DomainId,
        size: usize,
        align: usize,
    ) -> Result<(), KapiError> {
        let caller = context::current_subject().domain.as_u64();
        if owner != kernel_api::ipc::DomainId::KERNEL && caller != owner.as_u64() {
            return Err(KapiError::PermissionDenied);
        }
        if owner != kernel_api::ipc::DomainId::KERNEL
            && crate::sas::get_owner(ptr.as_ptr() as usize)
                != Some(crate::domain_system::DomainId::new(owner.as_u64()))
        {
            return Err(KapiError::PermissionDenied);
        }

        let layout = core::alloc::Layout::from_size_align(size.max(1), align.max(1))
            .map_err(|_| KapiError::InvalidHandle)?;
        crate::sas::unregister_any(ptr.as_ptr() as usize);
        unsafe {
            crate::mm::cache::exchange_heap::deallocate_raw(ptr, layout);
        }
        Ok(())
    }

    fn exchange_transfer_raw(
        &self,
        ptr: NonNull<u8>,
        from: kernel_api::ipc::DomainId,
        to: kernel_api::ipc::DomainId,
    ) -> Result<(), KapiError> {
        let caller = context::current_subject().domain.as_u64();
        if from != kernel_api::ipc::DomainId::KERNEL && caller != from.as_u64() {
            return Err(KapiError::PermissionDenied);
        }
        crate::sas::transfer_ownership(
            ptr.as_ptr() as usize,
            crate::domain_system::DomainId::new(from.as_u64()),
            crate::domain_system::DomainId::new(to.as_u64()),
        )
        .map_err(|_| KapiError::PermissionDenied)
    }

    fn ipc_send_raw(
        &self,
        channel: ChannelHandle,
        mut raw: kernel_api::abi::driver::AbiRRefRaw,
    ) -> Result<(), KapiError> {
        let caller = context::current_subject().domain;
        let ptr = NonNull::new(raw.ptr).ok_or(KapiError::InvalidHandle)?;
        if let Err(err) = self.exchange_transfer_raw(
            ptr,
            kernel_api::ipc::DomainId::new(caller.as_u64()),
            kernel_api::ipc::DomainId::KERNEL,
        ) {
            drop_abi_rref_raw(raw);
            return Err(err);
        }

        raw.owner = kernel_api::ipc::DomainId::KERNEL.as_u64();
        if let Err(err) = CHANNEL_REGISTRY.send_raw(channel, caller.as_u64(), raw) {
            if crate::sas::transfer_ownership(
                ptr.as_ptr() as usize,
                crate::domain_system::DomainId::KERNEL,
                caller,
            )
            .is_ok()
            {
                raw.owner = caller.as_u64();
            }
            drop_abi_rref_raw(raw);
            return Err(err);
        }
        Ok(())
    }

    fn ipc_recv_raw(
        &self,
        channel: ChannelHandle,
    ) -> Result<kernel_api::abi::driver::AbiRRefRaw, KapiError> {
        let caller = context::current_subject().domain;
        let mut raw = CHANNEL_REGISTRY.recv_raw(channel, caller.as_u64())?;
        let ptr = NonNull::new(raw.ptr).ok_or(KapiError::InvalidHandle)?;
        self.exchange_transfer_raw(
            ptr,
            kernel_api::ipc::DomainId::KERNEL,
            kernel_api::ipc::DomainId::new(caller.as_u64()),
        )?;
        raw.owner = caller.as_u64();
        Ok(raw)
    }

    fn time_service(&self) -> Option<&dyn kernel_api::service::time::TimeService> {
        crate::provider_registry::time_service()
    }

    fn platform_acpi(&self) -> Option<&dyn kernel_api::service::platform::AcpiServices> {
        crate::provider_registry::acpi_service()
    }

    fn platform_pci(&self) -> Option<&dyn kernel_api::service::platform::PciServices> {
        crate::provider_registry::pci_service()
    }

    fn platform_apic(&self) -> Option<&dyn kernel_api::service::platform::ApicServices> {
        crate::provider_registry::apic_service()
    }

    fn storage(&self) -> Option<&dyn kernel_api::service::storage::StorageServices> {
        crate::provider_registry::storage_service()
    }

    fn netdev(&self) -> Option<&dyn kernel_api::service::netdev::NetDeviceServices> {
        crate::provider_registry::netdev_service()
    }

    fn input(&self) -> Option<&dyn kernel_api::service::input::InputServices> {
        crate::provider_registry::input_service()
    }

    fn serial(&self) -> Option<&dyn kernel_api::service::serial::SerialServices> {
        crate::provider_registry::serial_service()
    }

    fn graphics(&self) -> Option<&dyn kernel_api::service::graphics::GraphicsServices> {
        crate::provider_registry::graphics_service()
    }

    fn audio(&self) -> Option<&dyn kernel_api::service::audio::AudioServices> {
        crate::provider_registry::audio_service()
    }

    fn gui(&self) -> Option<&dyn kernel_api::service::gui::GuiServices> {
        #[cfg(not(any(test, feature = "bench")))]
        {
            // GUI services are available only if framebuffer exists
            if crate::graphics::framebuffer().is_some() {
                Some(self)
            } else {
                None
            }
        }

        #[cfg(any(test, feature = "bench"))]
        {
            // In test/bench builds, graphics subsystem is disabled
            None
        }
    }

    fn shell(&self) -> Option<&dyn kernel_api::service::shell::ShellServices> {
        // Shell services are always available
        Some(self)
    }
}
