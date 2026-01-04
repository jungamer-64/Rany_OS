# IOMMU実装状況と不足部分の調査報告

## 更新履歴
- **2026-01-04**: Per-CPU Magazine, Per-Domain IOVA, DmaResourceRegistry, Async Unmap実装完了
- **2025-xx-xx**: AMD-Vi基本サポート追加、セキュリティ監視統合

---

## 実装済み機能

### 1. デュアルバックエンド対応 ✅
- **Intel VT-d**: フル機能対応
- **AMD-Vi**: 基本機能対応 (`kernel/src/io/iommu/amd/mod.rs`)
- **IommuBackend enum**: 静的ディスパッチによるゼロアロケーション

### 2. ページテーブル管理 ✅
- **PageTablePool**: NUMA-awareなページテーブルリサイクル
- **Per-CPU Magazine** (2026-01-04追加): O(1)ロックフリー割り当て
  - 3層アーキテクチャ: Per-CPU Magazine → NUMA Depot → Physical Allocator
  - `kernel/src/mm/per_cpu.rs`: `PtMagazine`構造体
  - `kernel/src/io/iommu/page_table_pool.rs`: `acquire_fast()`, `release_fast()`

### 3. IOVAアロケーション ✅
- **Tree-based allocator**: O(log n) Best-Fit割り当て
- **Per-Domain IOVA** (2026-01-04追加): ドメイン間のロック競合を排除
  - `kernel/src/io/iommu/domain.rs`: `new_with_iova()`, `allocate_iova()`, `free_iova()`
  - グローバルアロケータとPer-Domainアロケータの選択可能

### 4. DMAハンドル管理 ✅
- **DmaHandle<T>**: 所有権ベースのDMAバッファ管理
- **DmaResourceRegistry** (2026-01-04追加): SAS環境でのリソースリーク防止
  - `kernel/src/io/iommu/domain.rs`: `DmaResourceRegistry`構造体
  - ドメイン破棄時の強制unmapサポート: `force_unmap_all_dma()`
- **Async Unmap Default** (2026-01-04追加): 遅延IOTLB無効化
  - `kernel/Cargo.toml`: `async_unmap_default` feature flag
  - 高スループット環境向けの遅延無効化モード

### 5. セキュリティ機能 ✅
- **SecurityNotifier**: ISR-safeなセキュリティイベント通知
- **Fault Storm Detection**: デバイス毎のフォールトレート制限
- **ATS Security Policy**: 信頼レベルベースのATS有効化制御
  - `DeviceTrustLevel`: Trusted/Partial/Untrusted
- **Device Isolation**: ポリシー違反デバイスの自動分離

### 6. Queued Invalidation ✅
- **Intel QI**: コマンドキューベースの非同期無効化
- **AMD Command Buffer**: AMD-Vi用コマンドバッファ
- **Async IOTLB Invalidation**: Futureベースの非同期待機

---

## 未実装・改善が必要な機能

### 1. IOMMU Grouping / ACS (Access Control Services) ⚠️ (セキュリティリスク)
PCIeデバイスのトポロジーに基づいた **IOMMU Grouping** のロジックが実装されていません。

*   **現状:** `setup_iommu_for_pci_device` 関数にて、検出された全てのPCIデバイスに対して個別に新しいIOMMUドメイン（`IommuDomain`）を作成・割り当てています。
*   **問題点:** PCIeスイッチやブリッジの下にあるデバイスが **ACS (Access Control Services)** をサポートしていない場合、P2P通信などでトランザクションの発信元ID（Requester ID）が正しく分離されず、同一のドメインに所属させる必要があります（IOMMU Group）。
*   **リスク:** 適切にグルーピングを行わずに個別のドメインを割り当てると、あるデバイスが別のデバイスのIDを偽装してメモリにアクセスする（DMAエイリアシング攻撃）可能性があり、セキュリティ上の分離が不完全になります。

### 2. BTreeMapからRadix Treeへの移行 📋 (パフォーマンス)
- **現状**: IOVA範囲管理に`BTreeMap`を使用
- **問題**: IOMMUワークロードではキャッシュミス率が高い
- **計画**: 専用のRadix Tree実装への移行
- **参照**: `docs/LRU_BLOCK_CACHE.md`に設計ドキュメントあり

### 3. PASID (Process Address Space ID) サポート 📋
- **現状**: 未実装
- **用途**: SVM (Shared Virtual Memory)、プロセス毎のIOVA空間
- **優先度**: 低（現在のSASアーキテクチャでは必須ではない）

### 4. Nested Translation 📋
- **現状**: 未実装
- **用途**: 仮想化環境でのゲストIOMMU
- **優先度**: 低（ベアメタル運用が主ターゲット）

---

## Feature Flags

| フラグ | 説明 |
|--------|------|
| `async_unmap_default` | `DmaHandle::unmap()`をデフォルトで遅延無効化モードにする |
| `unsafe_iommu_bypass` | Identity Mapping (IOVA=物理アドレス) を許可（デバッグ用） |

---

## 推奨される対応

1.  ~~**AMD-Viの実装**~~ ✅ 完了
2.  **IOMMU Groupingの実装:** PCIバススキャン時にACS機能をチェックし、分離不可能なデバイス群を同一のIOMMUドメインに割り当てるロジックの追加。
3.  **Radix Tree移行**: 高頻度IOVA操作のパフォーマンス改善
