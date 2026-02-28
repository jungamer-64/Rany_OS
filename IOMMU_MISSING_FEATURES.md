# IOMMU実装状況と不足部分の調査報告

## 更新履歴
- **2026-02-28**: IOMMUセキュリティ脆弱性の修正完了
    - **Multifunction ACS Fix**: 多機能デバイスの全ての機能でACSをチェックするようにグルーピングロジックを強化。
    - **Posted Interrupt SID Fix**: Intel Posted IRTEにSource ID検証(SVT/SQ)を追加し、割り込みスプーフィングを防止。
    - **Command Queue Protection**: Intel QIおよびAMD-ViコマンドバッファをDMA保護レジストリに登録し、デバイスによる改ざんを防止。
    - **Invalidation Error Handling**: IOTLB無効化失敗時のエラーハンドリングを厳格化し、不整合状態での動作を防止。
    - **Buffer Resource Management**: Invalidation Queue等のハードウェアバッファにDrop実装を追加し、メモリリークと保護解除漏れを解消。
    - **Page Table Reuse Fix**: `flush`時にドメイン全体のIOTLB無効化を強制し、ページ構造キャッシュによる脆弱性を解消。
- **2026-02-27**: IOMMU Grouping / ACS (Access Control Services) 実装追加
- **2025-xx-xx**: AMD-Vi基本サポート追加、セキュリティ監視統合

---

## 実装済み機能

### 1. デュアルバックエンド対応 ✅
- **Intel VT-d**: フル機能対応
- **AMD-Vi**: フル機能対応 (`kernel/src/io/iommu/vendors/amd/mod.rs`)
- **IommuBackend enum**: 静的ディスパッチによるゼロアロケーション

### 2. IOMMU Grouping / ACS (Access Control Services) ✅ (2026-02-27追加)
PCIeトポロジーに基づいた **IOMMU Grouping** ロジックの実装完了。
- **ACS Isolation**: PCIeブリッジのACSケイパビリティをチェックし、分離不可能なデバイスを同一グループにマージ
- **Multifunction Grouping**: 多機能デバイスのファンクション間でのアイソレーションが不完全な場合の自動グルーピング
- **Generic Backend Support**: Intel VT-d / AMD-Vi の両方でグルーピングをサポート

### 3. セキュリティ強化: カーネル・リソース保護 ✅ (2026-02-27更新)
- **Kernel Image Protection**: すべてのDMAマッピング要求に対し、カーネル物理アドレス範囲との重複を厳格にチェック。非連続マッピングへの対応を強化。
- **Dynamic Resource Protection**:
  - **IOMMU Page Tables**: `PageTablePool`経由で割り当てられたすべてのページテーブルを自動的にDMA保護
  - **CPU Page Tables**: `PageTableManager`経由で割り当てられたすべてのページテーブルを自動的にDMA保護
  - **Kernel Stacks**: タスク作成時に割り当てられたカーネルスタックを自動的にDMA保護
  - **Hardware Tables**: Root Table, Context Table, Interrupt Remapping Tableを自動的にDMA保護
- **Bitmap-based Validation**: 物理ページビットマップ（最大64GB対応）によるO(1)の高速DMAバリデーション
- **Interrupt Remapping Security**: Source ID検証（SVT/SQ）により、デバイスによる他デバイス割り込みの偽装を防止
- **Security Module Integration**: `security::dma` モジュールへの保護ロジックの集約と一貫したバリデーションの適用

### 4. ページテーブル管理 ✅
- **PageTablePool**: NUMA-awareなページテーブルリサイクル
- **Per-CPU Magazine** (2026-01-04追加): O(1)ロックフリー割り当て
  - 3層アーキテクチャ: Per-CPU Magazine → NUMA Depot → Physical Allocator
  - `kernel/src/mm/per_cpu.rs`: `PtMagazine`構造体
  - `kernel/src/io/iommu/common/dma/page_table_pool.rs`: `acquire_fast()`, `release_fast()`

### 3. IOVAアロケーション ✅
- **Tree-based allocator**: O(log n) Best-Fit割り当て
- **Per-Domain IOVA** (2026-01-04追加): ドメイン間のロック競合を排除
  - `kernel/src/io/iommu/common/domain/domain_impl.rs`: `new_with_iova()`, `allocate_iova()`, `free_iova()`
  - グローバルアロケータとPer-Domainアロケータの選択可能

### 4. DMAハンドル管理 ✅
- **DmaHandle<T>**: 所有権ベースのDMAバッファ管理
- **DmaResourceRegistry** (2026-01-04追加): SAS環境でのリソースリーク防止
  - `kernel/src/io/iommu/common/domain/mod.rs`: `DmaResourceRegistry`構造体
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

### 1. BTreeMapからRadix Treeへの移行 📋 (パフォーマンス)
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
