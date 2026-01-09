// Minimal task-scoped IO shims for tests
// Provides a small NVMe shim to satisfy `crate::task::io::nvme` references


pub mod nvme {
    #[derive(Clone, Copy, Debug)]
    pub struct NvmeCompletion {
        pub cid: u16,
        pub status: u16,
    }

    impl NvmeCompletion {
        pub fn is_success(&self) -> bool { (self.status & 0x1) != 0 }
        pub fn command_id(&self) -> u16 { self.cid }
    }

    pub mod defs {
        #[derive(Debug)]
        pub enum NvmeError {
            InitializationFailed(&'static str),
            Timeout,
            QueueFull,
            InvalidParameter(&'static str),
            CommandFailed(&'static str),
            OutOfMemory,
            DeviceNotFound,
            ControllerFatalError,
            IoError(&'static str),
        }
    }

    #[derive(Debug)]
    pub struct NvmePollingDriver;

    #[derive(Clone, Copy, Debug)]
    pub struct SglDescriptor {
        pub addr: u64,
        pub length: u32,
        pub type_specific: u8,
    }

    impl NvmePollingDriver {
        pub fn new() -> Self { NvmePollingDriver }

        /// Submit a read command. Minimal test implementation: returns Ok(0).
        /// Safety: matches the real driver's safety contract (caller ensures core and PRP validity)
        pub unsafe fn submit_read(
            &self,
            _core_id: u32,
            _nsid: u32,
            _lba: u64,
            _blocks: u16,
            _prp1: u64,
            _prp2: u64,
        ) -> Result<u16, defs::NvmeError> {
            Ok(0)
        }

        /// Submit a read command (SGL). Minimal test implementation: returns Ok(0).
        pub unsafe fn submit_read_sgl(
            &self,
            _core_id: u32,
            _nsid: u32,
            _lba: u64,
            _blocks: u16,
            _sgl: SglDescriptor,
        ) -> Result<u16, defs::NvmeError> {
            Ok(0)
        }

        /// Submit a write command. Minimal test implementation: returns Ok(0).
        pub unsafe fn submit_write(
            &self,
            _core_id: u32,
            _nsid: u32,
            _lba: u64,
            _blocks: u16,
            _prp1: u64,
            _prp2: u64,
        ) -> Result<u16, defs::NvmeError> {
            Ok(0)
        }

        /// Submit a write command (SGL). Minimal test implementation: returns Ok(0).
        pub unsafe fn submit_write_sgl(
            &self,
            _core_id: u32,
            _nsid: u32,
            _lba: u64,
            _blocks: u16,
            _sgl: SglDescriptor,
        ) -> Result<u16, defs::NvmeError> {
            Ok(0)
        }

        /// SGL max entries. Minimal test implementation: None.
        pub fn sgl_max_entries(&self) -> Option<usize> {
            None
        }

        /// Submit a flush command. Minimal test implementation: returns Ok(0).
        pub unsafe fn submit_flush(
            &self,
            _core_id: u32,
            _nsid: u32,
        ) -> Result<u16, defs::NvmeError> {
            Ok(0)
        }

        /// Submit a dataset management command. Minimal test implementation: returns Ok(0).
        pub unsafe fn submit_dataset_management(
            &self,
            _core_id: u32,
            _nsid: u32,
            _nr: u8,
            _prp1: u64,
        ) -> Result<u16, defs::NvmeError> {
            Ok(0)
        }

        /// Check completion by CID. Minimal test implementation: always return None.
        pub fn check_completion(&self, _core_id: u32, _cid: u16) -> Option<NvmeCompletion> {
            None
        }

        /// Take completion by CID. Minimal test implementation: always return None.
        pub fn take_completion(&self, _core_id: u32, _cid: u16) -> Option<NvmeCompletion> {
            None
        }

        /// Poll loop for completions. Minimal test implementation: returns 0.
        pub unsafe fn poll_loop(&self, _core_id: u32) -> usize {
            0
        }

        /// Interrupt mode flag. Minimal test implementation: false.
        pub fn interrupt_mode(&self) -> bool {
            false
        }

        /// Namespace block size (bytes). Minimal test implementation: 512.
        pub fn namespace_block_size(&self, _nsid: u32) -> u32 {
            512
        }

        /// Register a Waker for a CID. No-op in test shim.
        pub fn register_waker(&self, _core_id: u32, _cid: u16, _waker: core::task::Waker) {}
    }
}
