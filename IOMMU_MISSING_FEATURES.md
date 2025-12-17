# IOMMU実装状況と不足部分の調査報告

現在のコードベース（`kernel/src/io/iommu.rs` および関連ファイル）を調査した結果、以下の主要な機能が未実装または不十分であることが判明しました。

## 1. AMD-Vi (AMD IOMMU) サポートの欠如 (重要)
現在のIOMMU実装は **Intel VT-d (Vendor-Independent Virtualization Technology for Directed I/O)** に特化しており、AMDプラットフォーム向けの **AMD-Vi (I/O Virtualization Technology)** が完全に未実装です。

*   **ACPIテーブル:** `drivers/acpi/src/dmar.rs` (Intel DMAR) は存在しますが、AMD用の `IVRS` テーブルのパーサーが存在しません。
*   **レジスタ定義:** `kernel/src/io/iommu.rs` 内の `regs` モジュールは Intel VT-d 仕様のレジスタオフセット（`VER`, `CAP`, `ECAP` 等）のみを定義しています。AMD IOMMUのレジスタマップとは互換性がありません。
*   **初期化ロジック:** `init_iommu_from_acpi` 関数は DMAR テーブルのみを探しており、IVRS テーブルを無視します。

**設計書との乖離:** `Rustカーネル設計案作成.md` では「IOMMU（Intel VT-d / AMD-Vi）を必須で有効化」とされていますが、現状ではAMD環境で起動するとIOMMUが見つからず、パニックするか（`IOMMU_REQUIRED=true`の場合）、保護なしで動作することになります。

## 2. IOMMU Grouping / ACS (Access Control Services) の未実装 (セキュリティリスク)
PCIeデバイスのトポロジーに基づいた **IOMMU Grouping** のロジックが実装されていません。

*   **現状:** `setup_iommu_for_pci_device` 関数にて、検出された全てのPCIデバイスに対して個別に新しいIOMMUドメイン（`IommuDomain`）を作成・割り当てています。
*   **問題点:** PCIeスイッチやブリッジの下にあるデバイスが **ACS (Access Control Services)** をサポートしていない場合、P2P通信などでトランザクションの発信元ID（Requester ID）が正しく分離されず、同一のドメインに所属させる必要があります（IOMMU Group）。
*   **リスク:** 適切にグルーピングを行わずに個別のドメインを割り当てると、あるデバイスが別のデバイスのIDを偽装してメモリにアクセスする（DMAエイリアシング攻撃）可能性があり、セキュリティ上の分離が不完全になります。

## 3. Intel VT-d の一部機能の実装状況
以下の機能については、コード上にメソッドは存在しますが、ハードウェアサポート確認(`supports_*`)を行っており、サポートがない場合は `NotSupported` を返します。これらは実装不足というよりは「ハードウェア依存の機能」として扱われています。

*   Interrupt Remapping (`init_interrupt_remapping`)
*   Posted Interrupts (`init_posted_interrupts`)
*   Page Request Interface (`init_page_request`)
*   Performance Monitoring (`perfmon_*`)

ただし、これらの機能が実機で正しく動作するかは、エミュレータ（QEMU）の設定や実機環境に依存します。

## 推奨される対応

1.  **AMD-Viの実装:** `drivers/acpi/src/ivrs.rs` の作成と、IOMMUドライバへのAMDバックエンドの追加（`IommuController` のトレイト化または抽象化が必要になる可能性があります）。
2.  **IOMMU Groupingの実装:** PCIバススキャン時にACS機能をチェックし、分離不可能なデバイス群を同一のIOMMUドメインに割り当てるロジックの追加。
