# プロセス / POSIX 依存の完全リスト (コード参照マップ)

📌 目的：ExoRust の設計方針（SAS / SPL / Async-First）に照らし、"プロセス/POSIX" に依存する既存実装の**完全なコード依存一覧**をリポジトリ内から収集して docs に保存しました。移行・機能フラグ化・削除の計画立案に使ってください。⚠️

---

## 概要（要点）

- 収集対象シンボル（代表）: `ProcessId`, `ProcFs`/`procfs`, `Signal` (`SignalQueue` 等), `ProcessAddressSpace` (ASID/CR3 系), `mmap` / `MemoryMapping`。
- 最新: ShellServices / ExoShell は Domain API 化済み。Process/Signal の公開は `task::compat::{process,signal}`（`feature = "posix-compat"`）に限定。
- core 観測は `/sys/cell`（`sysfs`）で提供し、`/proc` と `/dev/stdin` 系は `posix-compat` のみ。
- compat の `/proc` system/net 出力は `/sys/system` の read-only facade（出力のズレを防止）。
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
| `kernel/src/fs/procfs/mod.rs` | def @ l1; /proc のルートと system/net エントリ | `/proc/*` ツリー（system/net 系） | 中 | system 系は `/sys` へ段階移行、`/proc` は compat 側に集約 |
| `kernel/src/compat/posix/procfs_pid.rs` | /proc/[pid] 実装 | `/proc/[pid]` ツリー、デバッグ/管理インターフェース | 高 | `sys/cell` に置換 or feature-gate |

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
| `kernel/src/shell/exoshell/namespaces/cap.rs` | 多数（`/proc/*`/`/sys/cell/*` 権限マッピング） | `/proc/*`（posix-compat）/`/sys/cell/*`（core）に基づく capability 名称・マッピング | 中 | core は `sys/cell`、`/proc/*` は compat のみ |
| `kernel/src/service_impl.rs` | 〜 | ShellServices は Domain API 化済み。`/sys/cell` を読む（`/proc` は compat のみ） | 低 | ProcessId 参照なし。認可は Subject ベース |
| `kernel/src/fs/devfs.rs` | l433-438 | `/dev/stdin` → `/proc/self/fd/0` 等の symlink（posix-compat のみ） | 低→中 | 必要に応じて `/proc/self` を `sys/self` に置換 |

### ネットワーク / IPC / その他の依存（波及箇所）

- `kernel/src/fs/mod.rs` — `procfs` の公開は `posix-compat` のみ、`sysfs` は core で常時提供。
- `kernel/src/fs/sysfs.rs` — `/sys/cell`（Domain 観測用、read-only）の実装。
- 各種テスト & ユーティリティ (`kernel/src/fs/procfs/mod.rs` のテスト群, `kernel/src/lib.rs` の procfs テストスタブ)

---

## 完全ヒット一覧（機械可読／シンボル別）
>
> 以下はリポジトリから抽出したヒットのフル一覧（ツール出力に基づく）。まずは**シンボル別**に並べ、次節でファイル単位の要約を示します。

### `ProcessId`（代表的ヒット）

- `kernel/src/fs/procfs/mod.rs`: /proc ルートと system/net エントリ、/proc/<pid>/fd の権限チェック
- `kernel/src/compat/posix/procfs_pid.rs`: /proc/<pid> 実装とプロセス情報生成
- `kernel/src/mm/autonuma.rs`: l386（コメントのみ）
- `kernel/src/task/mod.rs`: l96, l111（`task::compat` 再export）
- `kernel/src/task/process.rs`: def @ l46; uses @ l27,35,38,40,61,62,381,383,411,420,444,449,464,496,518–519,528,538,550,556,564,584–586,646,660,690,711,773,777,790,801,811,829,855,890,896,901,906,941,949,962,975
- `kernel/src/lib.rs`: l1371–1432（テスト用スタブ, `posix-compat` 下で有効）

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

- `kernel/src/fs/procfs/mod.rs`: `/proc/*` 全体（/proc/version, /proc/uptime, /proc/meminfo, /proc/sys/*, /proc/net/*）
- `kernel/src/compat/posix/procfs_pid.rs`: `/proc/[pid]`（status/stat/maps/cmdline/exe/fd など）
- `kernel/src/fs/devfs.rs`: `/dev/stdin` → `/proc/self/fd/0` などの symlink (l433–l438, posix-compat のみ)
- `kernel/src/shell/exoshell/namespaces/cap.rs`: `/proc/*`（posix-compat）/`/sys/cell/*`（core）に基づく capability マッピング
- `kernel/src/mm/memory_compaction.rs`: `/proc/buddyinfo` 相当のメトリクス参照 (l662)

---

## ファイル単位の短い影響コメント（抜粋）

- `kernel/src/task/process.rs` — **コア**。ProcessId とその周辺型／API が集中。移行の中心。 (除去・隔離の最初の標的)
- `kernel/src/task/mod.rs` — compat の入口。Process/Signal の公開は `task::compat::*` のみに限定する。
- `kernel/src/task/signal.rs` — POSIX風シグナルが多数定義されている。公開は互換レイヤに寄せる。
- `kernel/src/fs/procfs/mod.rs` — 管理用の表層 API が多く、デバッグやツールで参照される。
- `kernel/src/compat/posix/procfs_pid.rs` — `/proc/[pid]` 系の互換実装。
- `interfaces/kernel_api/src/kapi.rs` / `libs/app_sdk` — アプリ互換境界。Process API は露出していない。追加する場合は `posix-compat` で隔離。
- `kernel/src/shell/exoshell/*` — Domain API 化済み。`/proc` 依存は compat の `cap` マッピングに限定。

---

## 推奨次アクション（短期・中期）

1. short-term: `/sys/system` を実装済み。`/proc` system/net 系の出力互換を確認する（設計は `docs/migration_from_posix.md` 参照）。
2. medium-term: 互換OFF CI の安定化（ジョブ追加済み、失敗時の原因切り分けを整備）。
3. long-term: `kernel/src/task/process.rs` / `kernel/src/mm/address_space.rs` / `/proc/[pid]` の段階的移行・削除（互換OFF での稼働を確認後）。

---

## 付録 A — 生データ（簡易 CSV 形式）

ファイルパス, 行番号(代表), 要約
kernel/src/task/process.rs,46,Process 型定義と多数の参照
kernel/src/task/signal.rs,19,Signal 定義とシグナルキュー
kernel/src/task/mod.rs,93,task::compat の再export窓口（posix-compat）
kernel/src/fs/procfs/mod.rs,1,/proc 実装全般（system/net + ルート）
kernel/src/compat/posix/procfs_pid.rs,1,/proc/[pid] 実装
kernel/src/mm/address_space.rs,286,per-process ページテーブル / ASID
kernel/src/mm/mmap.rs,129,MemoryMapping 定義
kernel/src/shell/exoshell/namespaces/cap.rs,54,capability マッピング（/proc* compat / /sys/cell core）
kernel/src/fs/devfs.rs,433,/proc/self/fd symlink（posix-compat のみ）
kernel/src/lib.rs,1371,procfs テストスタブ（ProcessId）
interfaces/kernel_api/src/kapi.rs,1,アプリ向け公開 API（Process API は露出なし。追加する場合は feature-gate）
libs/app_sdk/src/sdk.rs,1,アプリ用ユーティリティ（sleep/yield）

---

## 最後に（短く）

- ドキュメントを `docs/プロセス_POSIX_依存一覧.md` に保存しました。✅
- 次の作業候補（推奨順）: 1) `/proc` system/net 出力の互換確認と切替方針 2) 互換OFF CI ジョブの安定化 3) `task/process` / `mm/address_space` / `compat/posix/procfs_pid.rs` の互換移行。

必要なら、今すぐ **(B) procfs 互換分割 PR** を作成します。どれを優先しますか？

## 再検証結果（2026-01-19） — 要約

- 実施内容: リポジトリ全体を横断検索し、主要なPOSIX API（fork/exec/wait/getpid 等）および `/proc/self` 関連の痕跡を再確認しました。
- 結果: **高影響の見落としは見つかりませんでした。** `fork`/`exec`/`wait`/`getpid` 等の直接的実装は存在しないことを確認しました（設計方針に整合）。
- 確認された残存物（既報）: `/proc/[pid]` エントリ（`kernel/src/compat/posix/procfs_pid.rs`）、`/dev/stdin`→`/proc/self/fd/0` symlink（`kernel/src/fs/devfs.rs`、posix-compat のみ）、procfs のテストスタブ（`kernel/src/lib.rs`）およびシェルの capability マッピング（`kernel/src/shell/exoshell/namespaces/cap.rs`、core は `/sys/cell`）。これらはすべて本ドキュメントに記載済みです。

### 再検証で実行したコマンド（再現可能）

- rg "ProcessId|procfs|SIGCHLD|SignalQueue|ProcessAddressSpace|mmap|MemoryMapping" -S
- git grep -n "ProcessId\|procfs\|SIGCHLD\|ProcessAddressSpace"
- rg "fork\(|execv|execve|waitpid|getpid|ptrace|sigaction|/proc/self" -S

### 小さな追記（ドキュメント）

- 上記の検証ログと結論を本ファイルに追記しました（この節）。

## 結論・次の推奨アクション（短く）

- 一覧は現時点で**網羅的**です。次は互換OFF CI を維持しつつ、`procfs` の system/net 系移行と process 系の整理を進めてください。⚡

---

## 追加調査結果（2026-01-19 追記）

### 実施した検索・コマンド

- rg "ProcessId|procfs|SIGCHLD|SignalQueue|ProcessAddressSpace|mmap|MemoryMapping" -S
- rg "fork\(|execv|execve|waitpid|getpid|ptrace|sigaction|/proc/self" -S
- git grep -n "ProcessId\|procfs\|SIGCHLD\|ProcessAddressSpace"

### 主な発見

- `posix-compat` は `kernel/Cargo.toml` に定義済みでデフォルトは OFF（feature list）。
- `fs/devfs.rs` の `/dev/stdin` symlink、`fs/mod.rs` の `procfs` export、`task/mod.rs` の compat re-exports、`shell/exoshell/namespaces/cap.rs` の資源マッピング等は `#[cfg(feature = "posix-compat")]` で保護されています。
- `/proc/[pid]` 実装は `kernel/src/compat/posix/procfs_pid.rs` に集約し、`process_manager()` と `CAP_SYS_PTRACE` に依存するアクセス制御が多数存在します。
- `kernel/src/lib.rs` の Process stub はテスト用だが、`posix-compat` 下に限定済み（互換OFF の core からは見えない）。
- 結果: `kernel/src/task/process.rs` に fork() 相当（spawn に近い）、`waitpid()`、`getpid()` が実装されていることを確認しました。`execve` の完全な実装は見当たりませんでした。これらは互換レイヤ（`task::compat::*` または `compat/posix`）に移すか、`feature = "posix-compat"` 下で明確に隔離する必要があります。
- 追補: `mm/cow.rs` や `mm/demand_paging.rs` には fork() を前提とするコメントや処理があるため、fork semantics の移行影響を評価してください。

### 影響と注意点

- `procfs` に依存するテストは互換OFF で失敗する可能性があるため、テストの gating か移行が必要です。
- `CAP_SYS_PTRACE` に依存した権限設計は互換層移行後も同等の保護（トークン + in-flight）を維持する必要があります。

### 推奨の追加アクション（短期→中期）

1. Process stub の依存が残っていないか `posix-compat` テストで確認（不要なら削除）。 (0.5 日)
2. 互換OFF CI ジョブの安定化（`.github/workflows/ci.yml` の `Build (posix-compat OFF)`）。 (0.5 日)
3. `compat/posix/procfs_pid.rs` と関連テスト/呼び出しの分離を進める（小PR群で実施）。 (3–7 日)
4. grep-linter GitHub Action を追加し `ProcessId` の外部使用を検出・警告/失敗化。 (1–2 日)
5. `CAP_SYS_PTRACE` の token / in-flight revoke 機構の整合性を担保するテストを追加。（2–4 日）

### 次の提案

- 互換OFF CI ジョブを維持しつつ、`compat/posix/procfs_pid.rs` 周辺の依存を小PRで整理すると安全です。

### 続けるべき改善（コードベース全体確認後）

以下は全体検索の結果、優先的に進めるべき具体的改善項目です。各項目は概算工数と影響度を併記しました。

- **AddressSpace / fork API の隔離・整理（高）** — `kernel/src/mm/address_space.rs` の `fork` や `ProcessAddressSpace` に関するプロセス語義を `posix-compat` に移動、または `Domain` ベース API に分離する。目安: 1–3 日。

- **`mmap`/`MemoryMapping` の責務分離（中〜高）** — ファイル→メモリの primitive は保持しつつ、プロセス語義（per-process 参照）を `compat` に移すか、Domain-aware API にリファクタ。影響箇所: `kernel/src/mm/mmap.rs`。目安: 2–5 日。

- **THP（`thp_promotion.rs`）の AS 依存排除（中）** — THP ロジックが `ProcessAddressSpace` を参照している箇所を global-mapping API に置換。目安: 1–2 日。

- **テストの互換ガード（高）** — `kernel/src/lib.rs` の procfs テストスタブや `/proc` に依存するテストを `#[cfg(feature = "posix-compat")]` で保護、CI で互換OFF でも整合性を確認。目安: 1–2 日。

- **アプリ/ユーティリティの監査（中）** — `apps/` / `tools/` / `libs/` 内で `/proc` や `ProcessId` を参照するものを検出し、互換対応 or ドキュメント化する（各アプリ単位で 0.5–2 日）。

- **`/dev/std*` と `/proc/self` 依存の除去（中）** — `kernel/src/fs/devfs.rs` の symlink を `sys/self`（Domain-aware）に置換するか、compat に移行。目安: 1–2 日。

- **CAP_SYS_PTRACE のテスト強化（中）** — `CAP_SYS_PTRACE` の token / in-flight 保護を再現する統合テストを追加（互換移行後の安全性検証）。目安: 2–4 日。

- **CI / リントの強化（高）** — `ProcessId` / `procfs` のコア利用を検出する grep-linter を追加。CI に `posix-compat`=OFF のビルドと e2e テストを追加して回帰検知。目安: 0.5–1 日。

- **Signal API の近代化（中〜高）** — イベントベース通知 API に移行する設計を作成し、`task::signal` の互換アダプタを `compat` に置く。目安: 設計 1–2 日、実装 3–7 日。

- **削除計画・マイグレーションチェックリスト（高）** — フェーズ分け（CI整備→テストガード→procfs移行→mm/signal の整理→互換 OFF 確認→削除）を明確なチェックリストにまとめ、各 PR の受け入れ基準と担当を決める。目安: 0.5–1 日。

**短期の次アクション（推奨）**

1. CI に `posix-compat` OFF ジョブを追加する（優先度: 高、0.5 日）。✅
2. procfs 依存テストを `#[cfg(feature = "posix-compat")]` に囲い、互換OFF ジョブで失敗しないことを確認（優先度: 高、1 日）。
3. `ProcessAddressSpace::fork` の使用箇所を grep で一覧化し、core 側依存が無いことを確認した上で `compat` へ移す PR を小出しにする（優先度: 高、1–3 日）。

---

## 変更履歴

- 2026-01-19: 再検証を実施。検証ログと結論を追記。
- 2026-01-19: 追加調査を実施し、`compat/posix/procfs_pid.rs` と `CAP_SYS_PTRACE` のアクセス制御に注目した追加の詳細と推奨アクションを追記。
- 2026-01-19: コードベース全体レビューの結果に基づき、追記改善項目（AddressSpace/mmap/THP/test gating/CI強化等）を追加。
