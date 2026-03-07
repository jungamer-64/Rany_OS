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
        let channel_id = CHANNEL_REGISTRY.allocate_channel_id();
        let writer_id = CHANNEL_REGISTRY.register(ChannelEntry {
            channel_id,
            role: ChannelRole::Sender,
        });
        let reader_id = CHANNEL_REGISTRY.register(ChannelEntry {
            channel_id,
            role: ChannelRole::Receiver,
        });

        // info!(target: "ipc", "Created channel: reader={}, writer={}", reader_id, writer_id);

        Ok((ChannelHandle::new(writer_id), ChannelHandle::new(reader_id))) // Return (Sender, Receiver)
    }

    fn ipc_close(&self, channel: ChannelHandle) -> Result<(), KapiError> {
        let channel_id = channel.id();
        if CHANNEL_REGISTRY.unregister(channel_id).is_some() {
            Ok(())
        } else {
            Err(KapiError::InvalidHandle)
        }
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
