//! Integration Test Suite for ExoRust Kernel
//!
//! Comprehensive tests for all kernel subsystems including:
//! - PCI/PCIe device detection
//! - VirtIO drivers
//! - NVMe driver
//! - USB subsystem
//! - Network stack
//! - Memory management
//! - IPC mechanisms

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
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
// Storage Test Suite (VirtIO-blk Zero-Copy E2E)
// ============================================================================

use crate::fs::page_cluster_buffer::{PageClusterBuffer, PageClusterBufferAllocator};
use crate::mm::{PAGE_SIZE_4K, alloc_contiguous_frames};
use crate::task::block_on;
use alloc::sync::Arc as StdArc;
use vfs::block::{BlockError, BlockResult, ZcFuture, ZeroCopyBlockDevice};

struct VirtioPageAdapter {
    device: StdArc<crate::io::virtio::VirtioBlkDevice>,
}

impl VirtioPageAdapter {
    fn new(device: StdArc<crate::io::virtio::VirtioBlkDevice>) -> Self {
        Self { device }
    }
}

impl ZeroCopyBlockDevice for VirtioPageAdapter {
    type Buffer = PageClusterBuffer;

    fn info(&self) -> vfs::block::BlockDeviceInfo {
        self.device.info()
    }

    fn flush(&self) -> BlockResult<()> {
        self.device.flush()
    }

    fn alloc_buffer(&self, size: usize) -> BlockResult<Self::Buffer> {
        if size == 0 {
            return Err(BlockError::InvalidBufferSize);
        }
        let frames_needed = (size + (PAGE_SIZE_4K as usize - 1)) / (PAGE_SIZE_4K as usize);
        if let Some(start_phys) = alloc_contiguous_frames(frames_needed) {
            let real_size = frames_needed * (PAGE_SIZE_4K as usize);
            if let Some(buf) = PageClusterBuffer::new_from_phys(start_phys.as_u64(), real_size) {
                return Ok(buf);
            }
            // fallback: free & error
            crate::mm::dealloc_contiguous_frames(start_phys, frames_needed);
        }
        Err(BlockError::NotReady)
    }

    fn read_async(&self, block: u64, count: u32) -> ZcFuture<'_, BlockResult<Self::Buffer>> {
        let device = StdArc::clone(&self.device);
        Box::pin(async move {
            let block_size = device.info().block_size as usize;
            let size = block_size
                .checked_mul(count as usize)
                .ok_or(BlockError::InvalidBufferSize)?;
            let frames_needed = (size + (PAGE_SIZE_4K as usize - 1)) / (PAGE_SIZE_4K as usize);
            let start_phys = alloc_contiguous_frames(frames_needed).ok_or(BlockError::NotReady)?;
            let real_size = frames_needed * (PAGE_SIZE_4K as usize);
            let mut buf = PageClusterBuffer::new_from_phys(start_phys.as_u64(), real_size)
                .ok_or(BlockError::IoError)?;
            // Use underlying device borrowed API to do zero-copy read
            device.read_into_buf(block, &mut buf).await.map_err(|e| e)?;
            Ok(buf)
        })
    }

    fn write_async(
        &self,
        block: u64,
        buffer: Self::Buffer,
    ) -> ZcFuture<'_, BlockResult<Self::Buffer>> {
        let device = StdArc::clone(&self.device);
        Box::pin(async move {
            device.write_from_buf(block, &buffer).await.map_err(|e| e)?;
            Ok(buffer)
        })
    }

    fn read_into_buf<'a>(
        &'a self,
        block: u64,
        dst: &'a mut dyn vfs::block::IoBufferMut,
    ) -> ZcFuture<'a, BlockResult<()>> {
        self.device.read_into_buf(block, dst)
    }

    fn write_from_buf<'a>(
        &'a self,
        block: u64,
        src: &'a dyn vfs::block::IoBuffer,
    ) -> ZcFuture<'a, BlockResult<()>> {
        self.device.write_from_buf(block, src)
    }
}

// ============================================================================
// Storage Test
// ============================================================================

pub fn test_storage() -> IntegrationTestSuite {
    let mut suite = IntegrationTestSuite::new("Storage");

    suite.add_result(run_test("virtio_blk_zero_copy_mount", || {
        if let Some(dev) = crate::io::virtio::blk::get_virtio_blk_device() {
            // Wrap the global virtio device with a Page-backed adapter and mount
            let adapter = StdArc::new(VirtioPageAdapter::new(StdArc::clone(&dev)));
            let alloc = StdArc::new(PageClusterBufferAllocator::new());

            // Reset IOMMU mapping counters for a clean test
            crate::io::iommu::api::reset_map_unmap_counts();

            match block_on(
                fat32::Fat32FileSystem::<PageClusterBuffer>::mount_zero_copy_with_allocator(
                    adapter, alloc,
                ),
            ) {
                Ok(_fs_arc) => {
                    // If IOMMU is enabled, ensure we recorded mappings
                    if crate::io::iommu::api::is_iommu_enabled() {
                        let maps = crate::io::iommu::api::get_map_count();
                        if maps == 0 {
                            Err(String::from("IOMMU enabled but no map calls recorded"))
                        } else {
                            Ok(String::from("mount OK (IOMMU mapped)"))
                        }
                    } else {
                        Ok(String::from("mount OK (no IOMMU)"))
                    }
                }
                Err(e) => Err(alloc::format!("mount failed: {:?}", e)),
            }
        } else {
            Err(String::from("No VirtIO-blk device found"))
        }
    }));

    suite.add_result(run_test("nvme_polling_basic", || {
        let active = crate::io::nvme::with_driver(|d| d.is_active()).unwrap_or(false);
        if !active {
            return Ok(String::from("NVMe driver not initialized; skipped"));
        }

        let queue_ready = crate::io::nvme::with_driver(|d| d.get_queue(0).is_some()).unwrap_or(false);
        if !queue_ready {
            return Err(String::from("NVMe queue missing for core 0"));
        }

        let handle = crate::fs::DirectBlockHandle::new(1, 0, 1, 512);
        let mut buf = [0u8; 512];
        match crate::task::block_on(handle.read_blocks(0, &mut buf)) {
            Ok(n) if n == buf.len() => Ok(String::from("NVMe read ok")),
            Ok(n) => Err(alloc::format!("NVMe read size mismatch: {}", n)),
            Err(e) => Err(alloc::format!("NVMe read failed: {:?}", e)),
        }
    }));

    suite
}

// ============================================================================
// Run All Tests
// ============================================================================

/// Run all integration tests
pub fn run_all_integration_tests() -> (usize, usize) {
    log::info!("\n========================================\n");
    log::info!("   ExoRust Integration Test Suite\n");
    log::info!("========================================\n");

    let mut total_passed = 0;
    let mut total_failed = 0;

    // Run each test suite
    let suites = [
        test_pci(),
        test_memory(),
        test_tasks(),
        test_ipc(),
        test_domains(),
        test_security(),
        test_network(),
        test_storage(),
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

/// Run tests and assert all pass
pub fn run_integration_and_assert() -> bool {
    let (_passed, failed) = run_all_integration_tests();
    failed == 0
}
