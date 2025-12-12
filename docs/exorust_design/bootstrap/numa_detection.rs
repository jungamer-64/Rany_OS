//! 早期NUMAトポロジ検出
//!
//! 設計書セクション 11 Phase 1 参照

/// NUMAノード情報
#[derive(Clone, Copy)]
pub struct NumaNode {
    pub memory_ranges: [(u64, u64); 4], // (base, length) pairs
    pub memory_count: usize,
    pub cpus: [u32; 64], // APIC IDs
    pub cpu_count: usize,
}

impl NumaNode {
    pub const fn empty() -> Self {
        Self {
            memory_ranges: [(0, 0); 4],
            memory_count: 0,
            cpus: [0; 64],
            cpu_count: 0,
        }
    }

    pub fn add_memory_range(&mut self, base: u64, length: u64) {
        if self.memory_count < 4 {
            self.memory_ranges[self.memory_count] = (base, length);
            self.memory_count += 1;
        }
    }

    pub fn add_cpu(&mut self, apic_id: u32) {
        if self.cpu_count < 64 {
            self.cpus[self.cpu_count] = apic_id;
            self.cpu_count += 1;
        }
    }
}

/// ブートストラップ用NUMA情報
pub struct BootstrapNumaInfo {
    pub nodes: [NumaNode; 8],
    pub count: usize,
}

/// 早期のNUMAトポロジ検出
/// 
/// 動的アロケータなしでACPI SRATを解析し、NUMAトポロジを取得
pub fn detect_numa_topology_early(rsdp_addr: u64) -> BootstrapNumaInfo {
    // 16KB静的バッファ
    static mut ACPI_BUFFER: [u8; 16384] = [0; 16384];
    
    // SRATテーブルをバッファにコピー
    let srat = unsafe { read_srat_to_buffer(&mut ACPI_BUFFER, rsdp_addr) };
    
    // NUMAノード情報を抽出（最大8ノード、静的配列）
    let mut nodes = [NumaNode::empty(); 8];
    let mut node_count = 0;
    
    for entry in srat.entries() {
        match entry {
            SratEntry::Memory { base, length, proximity_domain, .. } => {
                let node_idx = proximity_domain as usize;
                if node_idx < 8 {
                    nodes[node_idx].add_memory_range(base, length);
                    if node_idx >= node_count {
                        node_count = node_idx + 1;
                    }
                }
            }
            SratEntry::Processor { apic_id, proximity_domain, .. } => {
                let node_idx = proximity_domain as usize;
                if node_idx < 8 {
                    nodes[node_idx].add_cpu(apic_id);
                    if node_idx >= node_count {
                        node_count = node_idx + 1;
                    }
                }
            }
        }
    }
    
    BootstrapNumaInfo { nodes, count: node_count }
}

// 以下はプレースホルダー
struct Srat;
impl Srat {
    fn entries(&self) -> impl Iterator<Item = SratEntry> {
        core::iter::empty()
    }
}

enum SratEntry {
    Memory { base: u64, length: u64, proximity_domain: u32 },
    Processor { apic_id: u32, proximity_domain: u32 },
}

unsafe fn read_srat_to_buffer(_buffer: &mut [u8], _rsdp_addr: u64) -> Srat {
    Srat
}
