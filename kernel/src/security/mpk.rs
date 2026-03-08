// SPDX-License-Identifier: MIT
// ExoRust Kernel - Memory Protection Keys (MPK/PKEYs) Management
#![allow(dead_code)]

use crate::sync::{PoisonLock, PoisonLockGuard};
use core::sync::atomic::{AtomicBool, Ordering};

const MAX_PKEYS: usize = 16;

pub struct MpkManager {
    used: [bool; MAX_PKEYS],
}

impl MpkManager {
    pub const fn new() -> Self {
        // pkey 0 is the default domain; keep it reserved.
        let mut used = [false; MAX_PKEYS];
        used[0] = true;
        Self { used }
    }

    pub fn init(&mut self) {
        self.used = [false; MAX_PKEYS];
        self.used[0] = true;
    }

    pub fn allocate(&mut self) -> Option<u8> {
        for i in 1..MAX_PKEYS {
            if !self.used[i] {
                self.used[i] = true;
                return Some(i as u8);
            }
        }
        None
    }

    pub fn free(&mut self, pkey: u8) {
        let idx = pkey as usize;
        if idx == 0 || idx >= MAX_PKEYS {
            return;
        }
        self.used[idx] = false;
    }

    pub fn is_used(&self, pkey: u8) -> bool {
        let idx = pkey as usize;
        idx < MAX_PKEYS && self.used[idx]
    }

    pub fn reset_for_test(&mut self) {
        self.init();
    }
}

static PKU_ENABLED: AtomicBool = AtomicBool::new(false);
static MPK_MANAGER: PoisonLock<MpkManager> = PoisonLock::new(MpkManager::new());

pub fn mpk_manager() -> PoisonLockGuard<'static, MpkManager> {
    MPK_MANAGER.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn is_pku_enabled() -> bool {
    PKU_ENABLED.load(Ordering::Relaxed)
}

pub fn init() {
    crate::io::log::early_print("[MPKDBG] init(): before lock\n");
    let mut manager = MPK_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    crate::io::log::early_print("[MPKDBG] init(): after lock\n");
    manager.init();
    PKU_ENABLED.store(true, Ordering::Relaxed);
    crate::io::log::early_print("[MPKDBG] init(): after manager.init\n");
}

pub fn allocate_protection_key() -> Option<u8> {
    if !is_pku_enabled() {
        return None;
    }
    MPK_MANAGER.lock().unwrap_or_else(|e| e.into_inner()).allocate()
}

pub fn free_protection_key(pkey: u8) {
    MPK_MANAGER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .free(pkey);
}

pub fn is_pkey_used(pkey: u8) -> bool {
    MPK_MANAGER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_used(pkey)
}

pub fn test_reset_pkey_allocator() {
    MPK_MANAGER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .reset_for_test();
    PKU_ENABLED.store(true, Ordering::Relaxed);
}
