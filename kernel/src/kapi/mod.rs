// ============================================================================
// kernel/src/kapi/mod.rs - Canonical KernelServices boundary
// ============================================================================
extern crate alloc;

pub(crate) use alloc::boxed::Box;
pub(crate) use core::future::Future;
pub(crate) use core::pin::Pin;
pub(crate) use core::ptr::NonNull;
pub(crate) use kernel_api::KapiResult;
pub(crate) use kernel_api::dma::{CpuDmaLease, DmaAllocationRequest};
pub(crate) use kernel_api::error::KapiError;
pub(crate) use kernel_api::ipc::ChannelHandle;
pub(crate) use kernel_api::resource::fs::{FileHandle, OpenMode};
pub(crate) use kernel_api::resource::storage::{
    DirectBlockHandle, NvmeIoHandle, NvmeIoPriority, NvmeIoResult, NvmeIoType, NvmeRwRequest,
};
pub(crate) use kernel_api::resource::task::TaskHandle;
pub(crate) use kernel_api::service::kernel::KernelServices;

pub(crate) use crate::io::dma;
pub(crate) use crate::task::{current_subject, current_task_id};

pub mod bootstrap;
pub mod device_registration;
pub mod fs;
pub mod gui;
pub mod ipc;
pub mod kernel_services;
pub mod net;
pub mod providers;
pub mod storage;
pub mod task;

pub(crate) use bootstrap::{register_builtin_service_providers, register_kernel_services};

pub struct ExoKernel;

impl ExoKernel {
    pub const fn new() -> Self {
        ExoKernel
    }
}
