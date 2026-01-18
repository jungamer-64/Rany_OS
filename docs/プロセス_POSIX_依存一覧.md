# プロセス / POSIX 依存の完全リスト (コード参照マップ)

📌 目的：ExoRust の設計方針（SAS / SPL / Async-First）に照らし、"プロセス/POSIX" に依存する既存実装の**完全なコード依存一覧**をリポジトリ内から収集して docs に保存しました。移行・機能フラグ化・削除の計画立案に使ってください。⚠️

---

## 概要（要点）
- 収集対象シンボル（代表）: `ProcessId`, `ProcFs`/`procfs`, `Signal` (`SignalQueue` 等), `ProcessAddressSpace` (ASID/CR3 系), `mmap` / `MemoryMapping`。
- 最新: ShellServices / ExoShell は Domain API 化済み。Process/Signal の公開は `task::compat::{process,signal}`（`feature = "posix-compat"`）に限定。
- 出力場所: `docs/プロセス_POSIX_依存一覧.md`（このファイル）
- 使い方: 各エントリは「ファイル:行番号 → 依存の要約 / 影響 / 推奨アクション」を示します。

---

## 生成方法（再現コマンド）
- 高レベル検索（リポジトリルートで実行）:
  - rg "ProcessId|procfs|SIGCHLD|SignalQueue|ProcessAddressSpace|page_table_root|mmap|MemoryMapping" -S
  - git grep -n "ProcessId\|procfs\|SIGCHLD\|ProcessAddressSpace"
- 本ドキュメントはワークスペース内のシンボル検索結果（ソースのライトウェイト静的解析）を元に作成しています。

---

## 重要シンボル別サマリ（短く）
- `ProcessId` / `Process*` 系: **広範に参照**（高影響） — コア実装は残るが、公開面は `task::compat::process` に隔離済み。
- `procfs` (`ProcFs`, `/proc/*`): **多数の管理／デバッグ経路**（中〜高影響）。
- `Signal` 系: **タスク間通知／レガシー API**（中影響）— 公開は `task::compat::signal` に限定。
- `ProcessAddressSpace` / ASID / per-process page-table: **設計と衝突**（高影響）。
- `mmap` / `MemoryMapping`: **一部は保持**（ファイル→メモリ primitive は維持、プロセス語義は要見直し）。

---

## 依存一覧（カテゴリ別・主要ファイル）
表は「ファイル」「代表的行番号」「依存内容の要約」「影響度」「初期対応案」を示します。

### プロセスコア（最優先で移行/隔離検討）
| ファイル | 行番号（代表） | 依存内容 | 影響度 | 推奨アクション |
|---|---:|---|---:|---|
| `kernel/src/task/process.rs` | def @ l46; uses @ l27,35,381,420,528,650,890… | PID/PPID/ProcessInfo/rlimit/資格情報/プロセスマネージャ | 高 | 公開面は `task::compat::process` に集約済み。`DomainId` shim を用意して段階移行 |
| `kernel/src/task/signal.rs` | def @ l19; uses @ l71,103,295,568,700… | POSIX ライクなシグナル実装（多くのシグナル定義・キュー） | 高 | 公開面は `task::compat::signal` に集約済み。内部通知のみ core に残す |
| `kernel/src/task/mod.rs` | compat @ l93〜 | `task::compat::process` / `task::compat::signal` の再export窓口 | 中 | compat の入口をここに集約（`feature = "posix-compat"`） |
| `kernel/src/fs/procfs.rs` | def @ l1; proc/[pid] 実装多数 (l378〜, l1188〜1852 テスト含む) | `/proc/[pid]` ツリー、デバッグ/管理インターフェース | 高 | `/proc/system/*` は保持、`/proc/[pid]` を `sys/cell` に置換 or feature-gate |

### メモリ・アドレス空間（高影響）
| ファイル | 行番号（代表） | 依存内容 | 影響度 | 推奨アクション |
|---|---:|---|---:|---|
| `kernel/src/mm/address_space.rs` | def @ l286; impl/use @ l309,563,1050… | per-process page-table, ASID, fork/exec 支援 | 高 | ガードページ / global mapping は維持。CR3/ASID 切替・fork/exec は互換層へ移行 |
| `kernel/src/mm/mmap.rs` | def @ l129; uses @ l405,552,606,645 | file-backed / anon mmap（プロセス語義含む） | 中 | file→memory primitives を残し、per-process semantics を Domain-aware にリファクタ |
| `kernel/src/mm/thp_promotion.rs` | uses `ProcessAddressSpace` (複数箇所) | Transparent Huge Page 関連で AS 概念を参照 | 中 | 参照を global-mapping API に置換可能か確認 |

### 公開 API / SDK（互換面で重要）
| ファイル | 行番号 | 依存内容 | 影響度 | 推奨アクション |
|---|---:|---|---:|---|
| `interfaces/kernel_api/src/kapi.rs` | モジュール全体 | アプリ向け公開 API（task/mem/net/fs など） | 中 | 現状 Process API は露出していない。互換 API を足すなら `feature = "posix-compat"` 下で隔離 |
| `libs/app_sdk/src/sdk.rs` | sleep/yield 実装 | アプリ側の慣習的 API | 中 | API は維持するが実装の依存（proc/process）を切り離す |

### シェル / 管理ツール / サービス（利用側）
| ファイル | 行番号 | 依存内容 | 影響度 | 推奨アクション |
|---|---:|---|---:|---|
| `kernel/src/shell/exoshell/namespaces/cap.rs` | 多数（`/proc/*` 権限マッピング） | `/proc/*` に基づく capability 名称・マッピング | 中 | `/proc/*` 権限を `sys/cell` にマップするか feature-gate |
| `kernel/src/service_impl.rs` | 〜 | ShellServices は Domain API 化済み。ProcessId 参照はテストのみ | 低 | 実装面のプロセス依存は除去済み（テスト側は互換の範囲で残置） |
| `kernel/src/fs/devfs.rs` | l433-436, l740-741 | `/dev/stdin` → `/proc/self/fd/0` 等の symlink | 低→中 | 必要に応じて `/proc/self` を `sys/self` に置換 |

### ネットワーク / IPC / その他の依存（波及箇所）
- `kernel/src/ipc/shared_mem.rs` (l1149,1152) — プロセスID を参照するコードあり
- `kernel/src/net/udp.rs` (l879-880) — デバッグ情報に PID/プロセス参照
- `kernel/src/fs/mod.rs` — `ProcFs` の公開 (exports)
- 各種テスト & ユーティリティ (`kernel/src/fs/procfs.rs` のテスト群, `kernel/src/lib.rs` の procfs テストスタブ)

---

## 完全ヒット一覧（機械可読／シンボル別）
> 以下はリポジトリから抽出したヒットのフル一覧（ツール出力に基づく）。まずは**シンボル別**に並べ、次節でファイル単位の要約を示します。

### `ProcessId`（代表的ヒット）
- `kernel/src/fs/devfs.rs`: l433–l436 (stdin/stdout/stderr symlink), l741–l742
- `kernel/src/fs/procfs.rs`: l13, l409–l1065, l1220–l1846 (多数の `/proc/[pid]` 実装とテスト)
- `kernel/src/ipc/shared_mem.rs`: l1149–1203
- `kernel/src/net/udp.rs`: l879–913
- `kernel/src/service_impl.rs`: l1730–1781（テストのみ）
- `kernel/src/shell/exoshell/namespaces/cap.rs`: l370–563（テストのみ）
- `kernel/src/shell/exoshell/namespaces/shell.rs`: l311–381（テストのみ）
- `kernel/src/task/mod.rs`: l93–121（`task::compat` 再export）
- `kernel/src/task/process.rs`: def @ l46; uses @ l27,35,38,40,61,62,381,383,411,420,444,449,464,496,518–519,528,538,550,556,564,584–586,646,660,690,711,773,777,790,801,811,829,855,890,896,901,906,941,949,962,975
- `kernel/src/lib.rs`: l1371–1432（テスト用スタブ）

### `Signal` / `SignalQueue`（代表的ヒット）
- `kernel/src/task/signal.rs`: def @ l19; uses @ l57–l107, l161, l295, l344, l371, l394, l453, l567, l600, l638, l653–l701
- `kernel/src/task/mod.rs`: l92–117（`task::compat::signal` 再export）

### `ProcessAddressSpace` / ASID / page-table
- `kernel/src/mm/address_space.rs`: def @ l286; impl/use @ l309,563,1050,1056,1120,1136
- `kernel/src/mm/thp_promotion.rs`: uses @ l36, l199, l274, l301, l318, l345, l400–l430
- `kernel/src/mm/mod.rs`: l150, l373

### `mmap` / `MemoryMapping`
- `kernel/src/mm/mmap.rs`: def @ l129; impl @ l150; uses @ l405, l552, l606, l645, l751
- `kernel/src/mm/mod.rs`: l150

### `procfs` / `/proc/*`（grep 出力要約）
- `kernel/src/fs/procfs.rs`: 定義と `/proc/*` 全体（/proc/version, /proc/uptime, /proc/meminfo, /proc/[pid]/status, /proc/[pid]/maps, /proc/[pid]/fd, /proc/sys/* 等） — 多数の実装とテスト（l1〜l1852 に広く存在）
- `kernel/src/fs/devfs.rs`: `/dev/stdin` → `/proc/self/fd/0` などの symlink (l433–l436)
- `kernel/src/shell/exoshell/namespaces/cap.rs`: `/proc/*` に基づく capability マッピング（複数箇所）
- `kernel/src/mm/memory_compaction.rs`: `/proc/buddyinfo` 相当のメトリクス参照 (l662)

---

## ファイル単位の短い影響コメント（抜粋）
- `kernel/src/task/process.rs` — **コア**。ProcessId とその周辺型／API が集中。移行の中心。 (除去・隔離の最初の標的)
- `kernel/src/task/mod.rs` — compat の入口。Process/Signal の公開は `task::compat::*` のみに限定する。
- `kernel/src/task/signal.rs` — POSIX風シグナルが多数定義されている。公開は互換レイヤに寄せる。
- `kernel/src/fs/procfs.rs` — 管理用の表層 API が多く、デバッグやツールで参照される。
- `interfaces/kernel_api/src/kapi.rs` / `libs/app_sdk` — アプリ互換境界。Process API は露出していない。追加する場合は `posix-compat` で隔離。
- `kernel/src/shell/exoshell/*` — Domain API 化済み。`/proc` 依存は主に `cap` のマッピングとテストに残る。

---

## 推奨次アクション（短期・中期）
1. short-term: `/proc/[pid]` と `/dev/stdin` などの互換経路を `posix-compat` に隔離し、`sys/cell` への置換を開始（`cap` のマッピングも更新）。
2. medium-term: `ipc/shared_mem` / `net/udp` / `kernel/src/lib.rs` の ProcessId 参照を DomainId へ置換 or feature-gate（小PR化）。
3. long-term: `kernel/src/task/process.rs` / `kernel/src/mm/address_space.rs` / `/proc/[pid]` の段階的移行・削除（互換OFF での稼働を確認後）。

---

## 付録 A — 生データ（簡易 CSV 形式）
ファイルパス, 行番号(代表), 要約
kernel/src/task/process.rs,46,Process 型定義と多数の参照
kernel/src/task/signal.rs,19,Signal 定義とシグナルキュー
kernel/src/task/mod.rs,93,task::compat の再export窓口（posix-compat）
kernel/src/fs/procfs.rs,1,/proc 実装全般（/proc/[pid] 含む）
kernel/src/mm/address_space.rs,286,per-process ページテーブル / ASID
kernel/src/mm/mmap.rs,129,MemoryMapping 定義
kernel/src/shell/exoshell/namespaces/cap.rs,54,/proc/* に対する capability マッピング
kernel/src/fs/devfs.rs,433,/proc/self/fd symlink
kernel/src/ipc/shared_mem.rs,1149,shared mem のプロセス依存処理
kernel/src/net/udp.rs,879,ネットワークデバッグにおけるプロセス参照
kernel/src/lib.rs,1371,procfs テストスタブ（ProcessId）
interfaces/kernel_api/src/kapi.rs,1,アプリ向け公開 API（Process API は露出なし。追加する場合は feature-gate）
libs/app_sdk/src/sdk.rs,1,アプリ用ユーティリティ（sleep/yield）

---

## 最後に（短く）
- ドキュメントを `docs/プロセス_POSIX_依存一覧.md` に保存しました。✅
- 次の作業候補（推奨順）: 1) `/proc/[pid]` と `/dev/stdin` の互換隔離＋`sys/cell` 置換 2) `ipc/shared_mem` / `net/udp` の ProcessId 置換 3) `task/process` / `mm/address_space` の互換移行。

必要なら、今すぐ **(B) procfs 互換分割 PR** を作成します。どれを優先しますか？
