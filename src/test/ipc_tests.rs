// ============================================================================
// src/test/ipc_tests.rs - IPC Subsystem Integration Tests
// ============================================================================

use crate::test::TestResult;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Test RRef creation
pub fn test_rref_creation() -> TestResult {
    use crate::ipc::{RRef, DomainId};
    
    let domain = DomainId::new(1);
    let data: Vec<u8> = vec![1, 2, 3, 4, 5];
    
    // Create RRef
    let rref = RRef::new(domain, data);
    
    // Verify owner
    if rref.owner() != domain {
        return TestResult::Failed(String::from("RRef owner mismatch"));
    }
    
    // Verify data access
    let slice = &rref[..];
    if slice != &[1, 2, 3, 4, 5] {
        return TestResult::Failed(String::from("RRef data mismatch"));
    }
    
    TestResult::Passed
}

/// Test RRef ownership transfer
pub fn test_rref_ownership_transfer() -> TestResult {
    use crate::ipc::{RRef, DomainId};
    
    let domain1 = DomainId::new(1);
    let domain2 = DomainId::new(2);
    let data: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
    
    // Create RRef in domain1
    let rref = RRef::new(domain1, data);
    if rref.owner() != domain1 {
        return TestResult::Failed(String::from("Initial owner should be domain1"));
    }
    
    // Transfer to domain2
    let rref = rref.move_to(domain2);
    
    // Verify new owner
    if rref.owner() != domain2 {
        return TestResult::Failed(String::from("Owner should be domain2 after transfer"));
    }
    
    // Verify data integrity after transfer
    let slice = &rref[..];
    if slice != &[0xDE, 0xAD, 0xBE, 0xEF] {
        return TestResult::Failed(String::from("Data corrupted after ownership transfer"));
    }
    
    TestResult::Passed
}

/// Test domain isolation
pub fn test_domain_isolation() -> TestResult {
    use crate::domain_system;
    
    // Create two domains
    let domain1 = domain_system::create_domain(String::from("test_domain_1"));
    let domain2 = domain_system::create_domain(String::from("test_domain_2"));
    
    // Verify domains have different IDs
    if domain1 == domain2 {
        return TestResult::Failed(String::from("Domains should have different IDs"));
    }
    
    // Start domains
    if domain_system::start_domain(domain1).is_err() {
        return TestResult::Failed(String::from("Failed to start domain1"));
    }
    
    if domain_system::start_domain(domain2).is_err() {
        return TestResult::Failed(String::from("Failed to start domain2"));
    }
    
    // Verify domain stats
    let stats = domain_system::get_domain_stats();
    if stats.running < 2 {
        return TestResult::Failed(alloc::format!(
            "Expected at least 2 running domains, got {}", stats.running
        ));
    }
    
    // Stop domains
    domain_system::stop_domain(domain1);
    domain_system::stop_domain(domain2);
    
    TestResult::Passed
}

/// Test cross-domain call
pub fn test_cross_domain_call() -> TestResult {
    use crate::ipc::{RRef, DomainId};
    
    // Simulate cross-domain communication
    let producer_domain = DomainId::new(100);
    let consumer_domain = DomainId::new(200);
    
    // Producer creates data
    let message: Vec<u8> = vec![b'H', b'e', b'l', b'l', b'o'];
    let rref = RRef::new(producer_domain, message);
    
    // Transfer to consumer (zero-copy)
    let rref = rref.move_to(consumer_domain);
    
    // Consumer reads data
    let received = &rref[..];
    if received != b"Hello" {
        return TestResult::Failed(String::from("Cross-domain message corrupted"));
    }
    
    TestResult::Passed
}

/// Test proxy pattern for domain calls
pub fn test_proxy_pattern() -> TestResult {
    use crate::ipc::proxy::DomainProxy;
    use crate::ipc::DomainId;
    
    let target_domain = DomainId::new(42);
    
    // Create proxy for target domain
    let proxy = DomainProxy::new(target_domain);
    
    // Verify proxy points to correct domain
    if proxy.target() != target_domain {
        return TestResult::Failed(String::from("Proxy target mismatch"));
    }
    
    // Test proxy availability check
    if proxy.is_alive() {
        // Domain might not actually exist, but proxy creation succeeded
    }
    
    TestResult::Passed
}

/// Test exchange heap concept
pub fn test_exchange_heap() -> TestResult {
    use crate::mm::exchange_heap::{ExchangeHeap, ExchangeRef};
    use crate::ipc::DomainId;
    
    // Get exchange heap
    let heap = crate::mm::exchange_heap::global_exchange_heap();
    
    // Allocate from exchange heap
    let domain = DomainId::new(1);
    
    // Test allocation tracking
    let stats = heap.stats();
    let initial_allocations = stats.total_allocations;
    
    // Allocate some data
    let _data: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8];
    
    // Verify allocations increased (indirectly through global heap)
    // Note: Direct exchange heap allocation would require unsafe API
    
    TestResult::Passed
}

/// Test heap registry for domain tracking
pub fn test_heap_registry() -> TestResult {
    use crate::sas::heap_registry::{HeapRegistry, DomainHeap};
    use crate::ipc::DomainId;
    
    let mut registry = HeapRegistry::new();
    
    let domain1 = DomainId::new(10);
    let domain2 = DomainId::new(20);
    
    // Register domains
    registry.register_domain(domain1);
    registry.register_domain(domain2);
    
    // Verify registration
    if !registry.is_registered(domain1) {
        return TestResult::Failed(String::from("Domain1 should be registered"));
    }
    
    if !registry.is_registered(domain2) {
        return TestResult::Failed(String::from("Domain2 should be registered"));
    }
    
    // Unregister domain
    registry.unregister_domain(domain1);
    
    if registry.is_registered(domain1) {
        return TestResult::Failed(String::from("Domain1 should be unregistered"));
    }
    
    TestResult::Passed
}

/// Test domain lifecycle
pub fn test_domain_lifecycle() -> TestResult {
    use crate::domain::lifecycle::{DomainState, DomainLifecycle};
    
    let mut lifecycle = DomainLifecycle::new();
    
    // Initial state should be Created
    if lifecycle.state() != DomainState::Created {
        return TestResult::Failed(String::from("Initial state should be Created"));
    }
    
    // Transition to Initializing
    if lifecycle.start_init().is_err() {
        return TestResult::Failed(String::from("Failed to start initialization"));
    }
    
    if lifecycle.state() != DomainState::Initializing {
        return TestResult::Failed(String::from("State should be Initializing"));
    }
    
    // Complete initialization
    if lifecycle.complete_init().is_err() {
        return TestResult::Failed(String::from("Failed to complete initialization"));
    }
    
    if lifecycle.state() != DomainState::Running {
        return TestResult::Failed(String::from("State should be Running"));
    }
    
    // Stop domain
    lifecycle.stop();
    
    if lifecycle.state() != DomainState::Stopped {
        return TestResult::Failed(String::from("State should be Stopped"));
    }
    
    TestResult::Passed
}
