//! Kernel-owned implementations of the contracts in `kernel_api`.
//!
//! Boot publishes these implementations through the installation entry points.
//! Service implementation types and subsystem adapters stay inside this module;
//! callers use the shared traits rather than acquiring an implementation object.
extern crate alloc;

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::ptr::NonNull;
use kernel_api::KapiResult;
use kernel_api::dma::{CpuDmaLease, DmaAllocationRequest};
use kernel_api::error::KapiError;
use kernel_api::ipc::ChannelHandle;
use kernel_api::resource::fs::{FileHandle, OpenMode};
use kernel_api::resource::storage::DirectBlockHandle;
use kernel_api::resource::task::{SpawnError, TaskId, TaskOptions};
use kernel_api::service::kernel::KernelServices;

use crate::task::{current_subject, current_task_id};

mod bootstrap;
mod device_registration;
mod dma_failure;
mod fs;
mod gui;
mod host;
mod ipc;
mod kernel;
mod maintenance;
mod net;
mod providers;
mod storage;
mod task;

pub(crate) use bootstrap::{install, install_builtin_providers};
pub(crate) use device_registration::authorize_pci_device_for_current_subject;
use host::KernelServiceHost;
pub(crate) use maintenance::{
    start_amd_services, start_intel_services, start_runtime_maintenance, start_security_monitor,
};
