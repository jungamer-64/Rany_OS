// ============================================================================
// src/test/memory_tests.rs - Memory Subsystem Integration Tests
// ============================================================================

use crate::test::TestResult;
use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::vec;
use alloc::string::String;

/// Test basic heap allocation
pub fn test_heap_allocation() -> TestResult {
    // Allocate a small block
    let data: Box<[u8; 256]> = Box::new([0xAA; 256]);
    
    // Verify contents
    for byte in data.iter() {
        if *byte != 0xAA {
            return TestResult::Failed(String::from("Memory corruption detected"));
        }
    }
    
    // Allocate multiple blocks
    let mut blocks: Vec<Box<[u8; 64]>> = Vec::new();
    for i in 0..10 {
        let block = Box::new([i as u8; 64]);
        blocks.push(block);
    }
    
    // Verify each block
    for (i, block) in blocks.iter().enumerate() {
        for byte in block.iter() {
            if *byte != i as u8 {
                return TestResult::Failed(String::from("Block corruption detected"));
            }
        }
    }
    
    // Clean up happens automatically
    TestResult::Passed
}

/// Test heap reallocation (Vec growth)
pub fn test_heap_reallocation() -> TestResult {
    let mut data = Vec::with_capacity(16);
    
    // Fill initial capacity
    for i in 0..16u8 {
        data.push(i);
    }
    
    // Force reallocation
    for i in 16..64u8 {
        data.push(i);
    }
    
    // Verify all data preserved
    for (i, &byte) in data.iter().enumerate() {
        if byte != i as u8 {
            return TestResult::Failed(alloc::format!(
                "Data corruption after realloc at index {}: expected {}, got {}", 
                i, i, byte
            ));
        }
    }
    
    TestResult::Passed
}

/// Test large allocation
pub fn test_large_allocation() -> TestResult {
    // Allocate 1MB
    const SIZE: usize = 1024 * 1024;
    let mut data = Vec::with_capacity(SIZE);
    
    // Fill with pattern
    for i in 0..SIZE {
        data.push((i & 0xFF) as u8);
    }
    
    // Verify pattern
    let mut errors = 0;
    for (i, &byte) in data.iter().enumerate() {
        if byte != (i & 0xFF) as u8 {
            errors += 1;
            if errors > 10 {
                return TestResult::Failed(String::from("Too many corruption errors in large allocation"));
            }
        }
    }
    
    if errors > 0 {
        return TestResult::Failed(alloc::format!("{} corruption errors found", errors));
    }
    
    TestResult::Passed
}

/// Test memory fragmentation handling
pub fn test_memory_fragmentation() -> TestResult {
    let mut handles: Vec<Option<Box<[u8; 128]>>> = Vec::new();
    
    // Allocate 100 blocks
    for i in 0..100 {
        handles.push(Some(Box::new([i as u8; 128])));
    }
    
    // Free every other block (create fragmentation)
    for i in (0..100).step_by(2) {
        handles[i] = None;
    }
    
    // Allocate new blocks (should reuse freed space)
    for i in (0..100).step_by(2) {
        handles[i] = Some(Box::new([0xFF; 128]));
    }
    
    // Verify odd blocks still intact
    for i in (1..100).step_by(2) {
        if let Some(ref block) = handles[i] {
            for byte in block.iter() {
                if *byte != i as u8 {
                    return TestResult::Failed(String::from("Fragmentation caused corruption"));
                }
            }
        } else {
            return TestResult::Failed(String::from("Block unexpectedly freed"));
        }
    }
    
    // Verify new blocks
    for i in (0..100).step_by(2) {
        if let Some(ref block) = handles[i] {
            for byte in block.iter() {
                if *byte != 0xFF {
                    return TestResult::Failed(String::from("New block has wrong value"));
                }
            }
        }
    }
    
    TestResult::Passed
}

/// Test Box allocation and drop
pub fn test_box_allocation() -> TestResult {
    // Nested boxes
    let inner = Box::new(42u64);
    let outer = Box::new(inner);
    
    if **outer != 42 {
        return TestResult::Failed(String::from("Nested Box has wrong value"));
    }
    
    // Box with struct
    #[derive(Debug)]
    struct TestStruct {
        a: u32,
        b: u64,
        c: [u8; 16],
    }
    
    let data = Box::new(TestStruct {
        a: 0x12345678,
        b: 0xDEADBEEFCAFEBABE,
        c: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    });
    
    if data.a != 0x12345678 {
        return TestResult::Failed(String::from("Struct field 'a' corrupted"));
    }
    if data.b != 0xDEADBEEFCAFEBABE {
        return TestResult::Failed(String::from("Struct field 'b' corrupted"));
    }
    for (i, &byte) in data.c.iter().enumerate() {
        if byte != (i + 1) as u8 {
            return TestResult::Failed(String::from("Struct field 'c' corrupted"));
        }
    }
    
    TestResult::Passed
}

/// Test Vec growth patterns
pub fn test_vec_growth() -> TestResult {
    let mut vec: Vec<u32> = Vec::new();
    let mut capacities: Vec<usize> = vec![vec.capacity()];
    
    // Push elements and track capacity changes
    for i in 0..1000 {
        vec.push(i);
        let new_cap = vec.capacity();
        if capacities.last() != Some(&new_cap) {
            capacities.push(new_cap);
        }
    }
    
    // Verify vector contents
    for (i, &val) in vec.iter().enumerate() {
        if val != i as u32 {
            return TestResult::Failed(alloc::format!(
                "Vec corruption at index {}: expected {}, got {}", i, i, val
            ));
        }
    }
    
    // Verify capacity grew (should have reallocated at least a few times)
    if capacities.len() < 3 {
        return TestResult::Failed(String::from("Vec did not grow as expected"));
    }
    
    // Test shrink
    vec.shrink_to_fit();
    if vec.capacity() < vec.len() {
        return TestResult::Failed(String::from("shrink_to_fit made capacity smaller than length"));
    }
    
    TestResult::Passed
}

/// Test memory alignment
pub fn test_memory_alignment() -> TestResult {
    // Aligned struct
    #[repr(align(64))]
    struct Aligned64 {
        data: [u8; 64],
    }
    
    let aligned = Box::new(Aligned64 { data: [0; 64] });
    let ptr = &*aligned as *const _ as usize;
    
    if ptr % 64 != 0 {
        return TestResult::Failed(alloc::format!(
            "64-byte aligned struct not aligned: address 0x{:x}", ptr
        ));
    }
    
    // Test various alignments
    #[repr(align(16))]
    struct Aligned16([u8; 16]);
    
    let a16 = Box::new(Aligned16([0; 16]));
    let ptr = &*a16 as *const _ as usize;
    
    if ptr % 16 != 0 {
        return TestResult::Failed(alloc::format!(
            "16-byte aligned struct not aligned: address 0x{:x}", ptr
        ));
    }
    
    TestResult::Passed
}
