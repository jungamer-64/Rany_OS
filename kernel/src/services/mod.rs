//! Kernel-owned implementations of the contracts in `kernel_api`.
//!
//! Boot publishes these implementations through the installation entry points.
//! Service implementation types and subsystem adapters stay inside this module;
//! callers use the shared traits rather than acquiring an implementation object.
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

mod bootstrap;
mod device_registration;
mod fs;
mod gui;
mod ipc;
mod kernel;
mod net;
mod providers;
mod storage;
mod task;

pub(crate) use bootstrap::{register_builtin_service_providers, register_kernel_services};
