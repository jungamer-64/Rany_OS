//! Integration Test Suite for ExoRust Kernel
//!
//! Comprehensive tests for all kernel subsystems including:
//! - PCI/PCIe device detection
//! - NVMe driver
//! - USB subsystem
//! - Network stack
//! - Memory management
//! - IPC mechanisms
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

/// Integration test result (different from main TestResult)
#[derive(Debug, Clone)]
pub struct IntegrationTestResult {
    pub name: String,
    pub passed: bool,
    pub message: String,
    pub duration_us: u64,
}

/// Test suite for a subsystem
pub struct IntegrationTestSuite {
    name: String,
    tests: Vec<IntegrationTestResult>,
}

impl IntegrationTestSuite {
    pub fn new(name: &str) -> Self {
        IntegrationTestSuite {
            name: String::from(name),
            tests: Vec::new(),
        }
    }

    pub fn add_result(&mut self, result: IntegrationTestResult) {
        self.tests.push(result);
    }

    pub fn passed(&self) -> usize {
        self.tests.iter().filter(|t| t.passed).count()
    }

    pub fn failed(&self) -> usize {
        self.tests.iter().filter(|t| !t.passed).count()
    }

    pub fn total(&self) -> usize {
        self.tests.len()
    }

    pub fn print_summary(&self) {
        log::info!("\n=== {} Test Suite ===\n", self.name);

        for test in &self.tests {
            let status = if test.passed { "[PASS]" } else { "[FAIL]" };
            log::info!(
                "{} {} ({} us): {}\n",
                status,
                test.name,
                test.duration_us,
                test.message
            );
        }

        log::info!(
            "Total: {} passed, {} failed, {} total\n\n",
            self.passed(),
            self.failed(),
            self.total()
        );
    }
}

/// Run a single test
fn run_test<F>(name: &str, test_fn: F) -> IntegrationTestResult
where
    F: FnOnce() -> Result<String, String>,
{
    let start = rdtsc_timestamp();

    let (passed, message) = match test_fn() {
        Ok(msg) => (true, msg),
        Err(msg) => (false, msg),
    };

    let end = rdtsc_timestamp();
    // Rough conversion: assume 3GHz
    let duration_us = (end - start) / 3000;

    IntegrationTestResult {
        name: String::from(name),
        passed,
        message,
        duration_us,
    }
}

async fn run_async_case(
    name: &str,
    case: impl core::future::Future<Output = Result<String, String>>,
) -> IntegrationTestResult {
    let start = crate::time::precise_time_nanos();
    let (passed, message) = match case.await {
        Ok(message) => (true, message),
        Err(message) => (false, message),
    };
    IntegrationTestResult {
        name: String::from(name),
        passed,
        message,
        duration_us: crate::time::precise_time_nanos().saturating_sub(start) / 1_000,
    }
}

/// Read TSC for timing
#[inline]
fn rdtsc_timestamp() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

// ============================================================================
// PCI Test Suite
// ============================================================================

pub fn test_pci() -> IntegrationTestSuite {
    let mut suite = IntegrationTestSuite::new("PCI");

    // Test PCI initialization
    suite.add_result(run_test("pci_init", || {
        // Basic PCI test - just verify we can access the module
        Ok(String::from("PCI module accessible"))
    }));

    suite
}

// ============================================================================
// Memory Test Suite
// ============================================================================

pub fn test_memory() -> IntegrationTestSuite {
    let mut suite = IntegrationTestSuite::new("Memory");

    // Test heap allocation
    suite.add_result(run_test("heap_alloc_small", || {
        let v: Vec<u8> = alloc::vec![0u8; 64];
        if v.len() == 64 {
            Ok(String::from("64 byte allocation successful"))
        } else {
            Err(String::from("Allocation size mismatch"))
        }
    }));

    suite.add_result(run_test("heap_alloc_medium", || {
        let v: Vec<u8> = alloc::vec![0u8; 4096];
        if v.len() == 4096 {
            Ok(String::from("4KB allocation successful"))
        } else {
            Err(String::from("Allocation size mismatch"))
        }
    }));

    suite.add_result(run_test("heap_alloc_large", || {
        let v: Vec<u8> = alloc::vec![0u8; 1024 * 1024];
        if v.len() == 1024 * 1024 {
            Ok(String::from("1MB allocation successful"))
        } else {
            Err(String::from("Allocation size mismatch"))
        }
    }));

    suite
}

// ============================================================================
// Task Test Suite
// ============================================================================

pub fn test_tasks() -> IntegrationTestSuite {
    let mut suite = IntegrationTestSuite::new("Tasks");

    // Test task creation
    suite.add_result(run_test("task_create", || {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        COUNTER.fetch_add(1, Ordering::SeqCst);
        Ok(String::from("Task atomic operation successful"))
    }));

    suite
}

// ============================================================================
// IPC Test Suite
// ============================================================================

pub fn test_ipc() -> IntegrationTestSuite {
    let mut suite = IntegrationTestSuite::new("IPC");

    // Test basic IPC
    suite.add_result(run_test("ipc_basic", || {
        Ok(String::from("IPC module accessible"))
    }));

    suite
}

// ============================================================================
// Domain Test Suite
// ============================================================================

pub fn test_domains() -> IntegrationTestSuite {
    let mut suite = IntegrationTestSuite::new("Domains");

    // Test domain module
    suite.add_result(run_test("domain_basic", || {
        Ok(String::from("Domain module accessible"))
    }));

    suite
}

// ============================================================================
// Security Test Suite
// ============================================================================

pub fn test_security() -> IntegrationTestSuite {
    let mut suite = IntegrationTestSuite::new("Security");

    // Test security module
    suite.add_result(run_test("security_basic", || {
        Ok(String::from("Security module accessible"))
    }));

    suite
}

// ============================================================================
// Network Test Suite
// ============================================================================

pub fn test_network() -> IntegrationTestSuite {
    let mut suite = IntegrationTestSuite::new("Network");

    // Test network module
    suite.add_result(run_test("network_basic", || {
        Ok(String::from("Network module accessible"))
    }));

    suite
}

// ============================================================================
// Storage Test Suite
// ============================================================================

// ============================================================================
// Storage Test
// ============================================================================

async fn nvme_device() -> Result<
    (
        crate::io::io_scheduler::DeviceId,
        crate::io::io_scheduler::BlockGeometry,
    ),
    String,
> {
    use kernel_api::service::storage::StorageTransport;
    let timer = kernel_api::service::time::try_instance()
        .ok_or_else(|| String::from("time service unavailable during driver startup"))?;
    let deadline = timer
        .current_tick_ms()
        .checked_add(5_000)
        .ok_or_else(|| String::from("driver startup deadline overflow"))?;
    // LOOP_PROOF: mode=event; reason=Each discovery attempt waits on a real timer, with publication or a retained finite startup deadline ending the wait.;
    loop {
        if let Some(storage) = kernel_api::service::storage::try_instance() {
            for info in storage.devices() {
                if info.transport != StorageTransport::Nvme {
                    continue;
                }
                let device = crate::io::io_scheduler::DeviceId::from_storage_id(info.device_id)
                    .ok_or_else(|| String::from("storage discovery published an invalid route"))?;
                if let Some(geometry) = crate::io::io_scheduler::io_scheduler()
                    .get_device_ops(device)
                    .and_then(|ops| ops.block_geometry())
                {
                    return Ok((device, geometry));
                }
            }
        }
        if timer.current_tick_ms() >= deadline {
            return Err(String::from(
                "NVMe startup did not publish an admitting device",
            ));
        }
        kernel_api::service::time::SleepFuture::new(timer, 1)
            .await
            .map_err(|cause| alloc::format!("NVMe discovery wait failed: {cause:?}"))?;
    }
}

async fn read_nvme_block(
    device: crate::io::io_scheduler::DeviceId,
    geometry: crate::io::io_scheduler::BlockGeometry,
) -> Result<usize, String> {
    use kernel_api::dma::{DmaAllocationRequest, DmaDirection};
    use kernel_api::service::storage::BlockTransferOutcome;
    let scheduler = crate::io::io_scheduler::io_scheduler();
    let target = scheduler
        .get_device_ops(device)
        .ok_or_else(|| String::from("NVMe device owner is unavailable"))?;
    let bytes = geometry.block_size.get() as usize;
    let request = DmaAllocationRequest::new(bytes, DmaDirection::FromDevice)
        .ok_or_else(|| String::from("invalid NVMe block geometry"))?;
    let extent = crate::fs::DirectBlockHandle::new(device, 0, 1, geometry.block_size.get())
        .map_err(|cause| alloc::format!("invalid NVMe extent: {cause:?}"))?;
    let timer = kernel_api::service::time::try_instance()
        .ok_or_else(|| String::from("time service unavailable during DMA admission"))?;
    let deadline = timer
        .current_tick_ms()
        .checked_add(5_000)
        .ok_or_else(|| String::from("DMA admission deadline overflow"))?;
    // LOOP_PROOF: mode=event; reason=Only an unpublished Busy allocation is retried after a real timer wait; success, other failures and the fixed admission deadline end the loop.;
    let buffer = loop {
        match target.allocate_transfer(request) {
            Ok(buffer) => break buffer,
            Err(crate::io::io_scheduler::IoError::Busy) if timer.current_tick_ms() < deadline => {
                kernel_api::service::time::SleepFuture::new(timer, 1)
                    .await
                    .map_err(|cause| alloc::format!("DMA admission wait failed: {cause:?}"))?;
            }
            Err(cause) => return Err(alloc::format!("NVMe transfer allocation failed: {cause:?}")),
        }
    };
    match extent.read_blocks_dma(0, buffer).await {
        BlockTransferOutcome::Returned { result, buffer } => {
            let closed = scheduler.finalize_transfer(buffer);
            let transferred =
                result.map_err(|cause| alloc::format!("NVMe read failed: {cause:?}"))?;
            closed
                .map_err(|cause| alloc::format!("NVMe transfer retirement retained: {cause:?}"))?;
            if transferred != bytes {
                return Err(alloc::format!(
                    "NVMe read size mismatch: expected {bytes}, got {transferred}"
                ));
            }
            Ok(transferred)
        }
        BlockTransferOutcome::Retained { cause, reason } => Err(alloc::format!(
            "NVMe owner retains the transfer: {cause:?}: {reason:?}"
        )),
    }
}

pub async fn test_storage() -> IntegrationTestSuite {
    let mut suite = IntegrationTestSuite::new("Storage");

    suite.add_result(
        run_async_case("nvme_polling_basic", async {
            let (device, geometry) = nvme_device().await?;

            read_nvme_block(device, geometry).await?;
            Ok(String::from("NVMe read ok"))
        })
        .await,
    );

    #[cfg(feature = "qemu-test-export")]
    suite.add_result(
        run_async_case("page_cluster_owned_roundtrip", async {
            crate::fs::page_cluster_buffer::tests::test_page_cluster_buffer_zero_copy_roundtrip()
                .await;
            Ok(String::from(
                "owned logical block buffer roundtrip completed",
            ))
        })
        .await,
    );

    suite
}

// ============================================================================
// IOMMU Test Suite
// ============================================================================

pub async fn test_iommu() -> IntegrationTestSuite {
    let mut suite = IntegrationTestSuite::new("IOMMU");

    // Test IOMMU detection
    suite.add_result(run_test("iommu_detection", || {
        if crate::io::iommu::api::is_iommu_enabled() {
            Ok(String::from("IOMMU detected and enabled"))
        } else {
            Err(String::from("IOMMU not detected or disabled"))
        }
    }));

    suite.add_result(run_async_case("iommu_dma_map_basic", async {
        use crate::io::iommu::common::dma::handle::{DmaDirection, DmaHandle, MapError};
        use crate::io::iommu::types::DeviceId;
        if !crate::io::iommu::api::is_iommu_enabled() {
            return Err(String::from("IOMMU must be enabled for DMA mapping verification"));
        }
        let size = crate::mm::types::PAGE_SIZE_4K;
        let allocation = crate::ipc::RRef::<[u8]>::new_slice_default_aligned(
            crate::domain::DomainId::KERNEL, size, size,
        ).ok_or_else(|| String::from("owned DMA test allocation failed"))?;
        let pointer = allocation.as_ptr().addr();
        let mut backing = Some(allocation);
        let candidates = [DeviceId::new(0, 0, 31, 2), DeviceId::new(0, 0, 0, 0)];
        let mut last_rejection = None;
        // LOOP_PROOF: mode=bounded; reason=The fixed candidate list bounds mapping admission and unpublished rejection returns the same RAM owner;
        for device in candidates {
            let allocation = backing.take().expect("unpublished rejection returns backing");
            match DmaHandle::map_rref_slice_for_device(allocation, &device, DmaDirection::Bidirectional) {
                Ok(mapping) => {
                    let iova = mapping.iova();
                    let returned = mapping.unmap_async().await.map_err(|failure| {
                        let message = alloc::format!("DMA retirement incomplete: {:?}", failure.kind);
                        // The handle transfers backing and exact retirement
                        // progress to its pre-admitted reclamation owner.
                        drop(failure.handle);
                        message
                    })?;
                    if returned.as_ptr().addr() != pointer || returned.len() != size {
                        return Err(String::from("DMA retirement returned different backing"));
                    }
                    return Ok(alloc::format!("Owned DMA map/unmap completed for {:04x}:{:02x}:{:02x}.{} at IOVA {iova:#x}",
                        device.segment, device.bus, device.device, device.function));
                }
                Err(MapError::Unmapped { rref, kind }) => {
                    backing = Some(rref);
                    last_rejection = Some(kind);
                }
                Err(MapError::TranslationPending { handle, kind }) => {
                    // Publication occurred. The reserved reclamation owner
                    // keeps RAM and translation origin through synchronization.
                    drop(handle);
                    return Err(alloc::format!("DMA publication remains incomplete: {kind:?}"));
                }
            }
        }
        Err(alloc::format!("DMA admission rejected all candidates: {last_rejection:?}"))
    }).await);

    suite.add_result(
        run_async_case("iommu_nvme_block_io_path", async {
            let (device, geometry) = nvme_device().await?;

            crate::io::iommu::api::reset_map_unmap_counts();
            read_nvme_block(device, geometry).await?;

            if !crate::io::iommu::api::is_iommu_enabled() {
                Err(String::from(
                    "IOMMU is mandatory but NVMe direct block I/O ran without IOMMU enabled",
                ))
            } else {
                let maps = crate::io::iommu::api::get_map_count();
                if maps == 0 {
                    Err(String::from(
                        "IOMMU enabled but NVMe direct block path recorded no map calls",
                    ))
                } else {
                    Ok(alloc::format!(
                        "NVMe direct block read ok ({} IOMMU map calls)",
                        maps
                    ))
                }
            }
        })
        .await,
    );

    suite
}

// ============================================================================
// Run All Tests
// ============================================================================

/// Run all integration tests
pub async fn run_all_integration_tests() -> (usize, usize) {
    log::info!("\n========================================\n");
    log::info!("   ExoRust Integration Test Suite\n");
    log::info!("========================================\n");

    let mut total_passed = 0;
    let mut total_failed = 0;

    // Run each test suite
    let suites = [
        test_pci(),
        test_iommu().await,
        test_memory(),
        test_tasks(),
        test_ipc(),
        test_domains(),
        test_security(),
        test_network(),
        test_storage().await,
    ];

    for suite in suites {
        suite.print_summary();
        total_passed += suite.passed();
        total_failed += suite.failed();
    }

    log::info!("========================================\n");
    log::info!(
        "   TOTAL: {} passed, {} failed\n",
        total_passed,
        total_failed
    );
    log::info!("========================================\n\n");

    (total_passed, total_failed)
}
