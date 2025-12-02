// ============================================================================
// src/test/mod.rs - Integration Test Framework
// Phase 6: Integration Tests & Validation
// ============================================================================

// Integration test suite for comprehensive kernel testing
pub mod integration;

// Note: Individual test modules are disabled until API stabilization
// pub mod memory_tests;
// pub mod task_tests;
// pub mod network_tests;
// pub mod ipc_tests;
// pub mod benchmark;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;

/// Test result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestResult {
    /// Test passed
    Passed,
    /// Test failed with message
    Failed(String),
    /// Test was skipped
    Skipped(String),
}

impl TestResult {
    pub fn is_passed(&self) -> bool {
        matches!(self, TestResult::Passed)
    }
    
    pub fn is_failed(&self) -> bool {
        matches!(self, TestResult::Failed(_))
    }
}

/// Test case descriptor
pub struct TestCase {
    /// Test name
    pub name: &'static str,
    /// Test category
    pub category: &'static str,
    /// Test function
    pub func: fn() -> TestResult,
}

/// Test runner
pub struct TestRunner {
    /// All registered test cases
    tests: Mutex<Vec<TestCase>>,
    /// Passed count
    passed: AtomicU64,
    /// Failed count
    failed: AtomicU64,
    /// Skipped count
    skipped: AtomicU64,
    /// Stop on first failure
    stop_on_failure: AtomicBool,
}

/// Global test runner (using spin::Once for safe initialization)
static TEST_RUNNER: spin::Once<TestRunner> = spin::Once::new();

impl TestRunner {
    /// Create new test runner
    pub fn new() -> Self {
        TestRunner {
            tests: Mutex::new(Vec::new()),
            passed: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
            stop_on_failure: AtomicBool::new(false),
        }
    }
    
    /// Register a test case
    pub fn register(&self, name: &'static str, category: &'static str, func: fn() -> TestResult) {
        self.tests.lock().push(TestCase { name, category, func });
    }
    
    /// Set stop on failure mode
    pub fn set_stop_on_failure(&self, stop: bool) {
        self.stop_on_failure.store(stop, Ordering::SeqCst);
    }
    
    /// Run all tests
    pub fn run_all(&self) -> TestSummary {
        crate::log!("\n");
        crate::log!("================================================================================\n");
        crate::log!("                          ExoRust Integration Test Suite\n");
        crate::log!("================================================================================\n\n");
        
        let tests = self.tests.lock();
        let total = tests.len();
        let mut results = Vec::new();
        
        for (i, test) in tests.iter().enumerate() {
            crate::log!("[{}/{}] Running test: {}::{}\n", i + 1, total, test.category, test.name);
            
            let result = (test.func)();
            
            match &result {
                TestResult::Passed => {
                    self.passed.fetch_add(1, Ordering::SeqCst);
                    crate::log!("  [PASS] {}\n", test.name);
                }
                TestResult::Failed(msg) => {
                    self.failed.fetch_add(1, Ordering::SeqCst);
                    crate::log!("  [FAIL] {}: {}\n", test.name, msg);
                    
                    if self.stop_on_failure.load(Ordering::SeqCst) {
                        crate::log!("\n[ABORT] Stopping test run due to failure\n");
                        break;
                    }
                }
                TestResult::Skipped(reason) => {
                    self.skipped.fetch_add(1, Ordering::SeqCst);
                    crate::log!("  [SKIP] {}: {}\n", test.name, reason);
                }
            }
            
            results.push((test.name, test.category, result));
        }
        drop(tests);
        
        let passed = self.passed.load(Ordering::SeqCst);
        let failed = self.failed.load(Ordering::SeqCst);
        let skipped = self.skipped.load(Ordering::SeqCst);
        
        crate::log!("\n");
        crate::log!("================================================================================\n");
        crate::log!("                              Test Summary\n");
        crate::log!("================================================================================\n");
        crate::log!("  Total:   {}\n", total);
        if total > 0 {
            crate::log!("  Passed:  {} ({}%)\n", passed, (passed * 100) / total as u64);
        } else {
            crate::log!("  Passed:  {}\n", passed);
        }
        crate::log!("  Failed:  {}\n", failed);
        crate::log!("  Skipped: {}\n", skipped);
        crate::log!("================================================================================\n\n");
        
        TestSummary {
            total: total as u64,
            passed,
            failed,
            skipped,
            results,
        }
    }
    
    /// Run tests for a specific category
    pub fn run_category(&self, category: &str) -> TestSummary {
        let tests = self.tests.lock();
        let filtered: Vec<_> = tests.iter()
            .filter(|t| t.category == category)
            .collect();
        
        crate::log!("\n[TEST] Running {} tests in category '{}'\n\n", filtered.len(), category);
        
        let mut results = Vec::new();
        
        for test in &filtered {
            crate::log!("  Running: {}\n", test.name);
            let result = (test.func)();
            
            match &result {
                TestResult::Passed => {
                    self.passed.fetch_add(1, Ordering::SeqCst);
                    crate::log!("    [PASS]\n");
                }
                TestResult::Failed(msg) => {
                    self.failed.fetch_add(1, Ordering::SeqCst);
                    crate::log!("    [FAIL] {}\n", msg);
                }
                TestResult::Skipped(reason) => {
                    self.skipped.fetch_add(1, Ordering::SeqCst);
                    crate::log!("    [SKIP] {}\n", reason);
                }
            }
            
            results.push((test.name, test.category, result));
        }
        
        TestSummary {
            total: filtered.len() as u64,
            passed: self.passed.load(Ordering::SeqCst),
            failed: self.failed.load(Ordering::SeqCst),
            skipped: self.skipped.load(Ordering::SeqCst),
            results,
        }
    }
    
    /// Reset counters
    pub fn reset(&self) {
        self.passed.store(0, Ordering::SeqCst);
        self.failed.store(0, Ordering::SeqCst);
        self.skipped.store(0, Ordering::SeqCst);
    }
}

/// Test summary
pub struct TestSummary {
    pub total: u64,
    pub passed: u64,
    pub failed: u64,
    pub skipped: u64,
    pub results: Vec<(&'static str, &'static str, TestResult)>,
}

impl TestSummary {
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }
}

/// Initialize test framework
pub fn init() {
    TEST_RUNNER.call_once(|| {
        let runner = TestRunner::new();
        
        // Register basic tests
        runner.register("arithmetic", "basic", test_arithmetic);
        runner.register("heap_alloc", "basic", test_heap_alloc);
        runner.register("vec_ops", "basic", test_vec_ops);
        runner.register("atomic_ops", "basic", test_atomic_ops);
        
        runner
    });
    
    crate::log!("[TEST] Test framework initialized\n");
}

/// Get test runner
pub fn runner() -> &'static TestRunner {
    TEST_RUNNER.get().expect("Test runner not initialized")
}

/// Basic arithmetic test
fn test_arithmetic() -> TestResult {
    let a = 10u64;
    let b = 20u64;
    if a + b != 30 { return TestResult::Failed(alloc::string::String::from("10+20!=30")); }
    if a * b != 200 { return TestResult::Failed(alloc::string::String::from("10*20!=200")); }
    TestResult::Passed
}

/// Heap allocation test
fn test_heap_alloc() -> TestResult {
    use alloc::boxed::Box;
    let b = Box::new(42u64);
    if *b != 42 { return TestResult::Failed(alloc::string::String::from("Box deref failed")); }
    TestResult::Passed
}

/// Vec operations test
fn test_vec_ops() -> TestResult {
    use alloc::vec;
    let v = vec![1u64, 2, 3, 4, 5];
    if v.len() != 5 { return TestResult::Failed(alloc::string::String::from("Vec len wrong")); }
    if v.iter().sum::<u64>() != 15 { return TestResult::Failed(alloc::string::String::from("Vec sum wrong")); }
    TestResult::Passed
}

/// Atomic operations test
fn test_atomic_ops() -> TestResult {
    let counter = AtomicU64::new(0);
    counter.fetch_add(5, Ordering::SeqCst);
    if counter.load(Ordering::SeqCst) != 5 {
        return TestResult::Failed(alloc::string::String::from("Atomic add failed"));
    }
    TestResult::Passed
}

/// Run all tests
pub fn run_all() -> TestSummary {
    runner().reset();
    runner().run_all()
}

/// Run tests by category
pub fn run_category(category: &str) -> TestSummary {
    runner().reset();
    runner().run_category(category)
}

// ============================================================================
// Test assertion helpers
// ============================================================================

/// Assert equal
#[macro_export]
macro_rules! assert_test_eq {
    ($left:expr, $right:expr) => {
        if $left != $right {
            return $crate::test::TestResult::Failed(
                alloc::format!("assertion failed: {} != {} (left: {:?}, right: {:?})", 
                    stringify!($left), stringify!($right), $left, $right)
            );
        }
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        if $left != $right {
            return $crate::test::TestResult::Failed(
                alloc::format!($($arg)+)
            );
        }
    };
}

/// Assert true
#[macro_export]
macro_rules! assert_test {
    ($cond:expr) => {
        if !$cond {
            return $crate::test::TestResult::Failed(
                alloc::format!("assertion failed: {}", stringify!($cond))
            );
        }
    };
    ($cond:expr, $($arg:tt)+) => {
        if !$cond {
            return $crate::test::TestResult::Failed(
                alloc::format!($($arg)+)
            );
        }
    };
}

/// Assert not equal
#[macro_export]
macro_rules! assert_test_ne {
    ($left:expr, $right:expr) => {
        if $left == $right {
            return $crate::test::TestResult::Failed(
                alloc::format!("assertion failed: {} == {}", stringify!($left), stringify!($right))
            );
        }
    };
}

/// Assert result is Ok
#[macro_export]
macro_rules! assert_test_ok {
    ($result:expr) => {
        match $result {
            Ok(_) => {},
            Err(e) => {
                return $crate::test::TestResult::Failed(
                    alloc::format!("expected Ok, got Err: {:?}", e)
                );
            }
        }
    };
}

/// Assert option is Some
#[macro_export]
macro_rules! assert_test_some {
    ($option:expr) => {
        match $option {
            Some(_) => {},
            None => {
                return $crate::test::TestResult::Failed(
                    alloc::format!("expected Some, got None")
                );
            }
        }
    };
}
