# プロセス / POSIX 依存：詳細コードレビュー

🔍 目的：`docs/プロセス_POSIX_依存一覧.md` の結果を受け、カーネル内の各実装（`process`, `signal`, `procfs`, `address_space`, `mmap`, `mm/*` 等）を**詳細に確認**し、正確な関数一覧・ガード状況・テスト依存・推奨アクションをまとめます。

---

## 概要（結論・短く）
- **発見**: `ProcessId`/プロセス API は `kernel/src/task/process.rs` に実装。公開面は `task::compat::process`（`posix-compat`）経由で再エクスポートされるが、モジュール自体は core で常時ビルドされ、`mm/autonuma` や `signal` で内部利用がある。✅
- **重要**: `ProcessAddressSpace::fork()` は実装済み (`kernel/src/mm/address_space.rs` l564) だが呼び出し箇所は未検出。`exec_reset()` は Drop でのみ使用。互換層への移動・ガード化候補。⚠️
- **procfs/テスト**: `procfs` は `kernel/src/fs/mod.rs` の `#[cfg(feature = "posix-compat")]` で丸ごとガード。`/proc` system は `/sys/system` に委譲し、`/proc/[pid]` は `compat/posix/procfs_pid.rs` に集約。テストは `#[cfg(all(test, feature = "std"))]` で `posix-compat` ON 時のみ。✅

---

## レビュー方法（再現コマンド）
- 主要検索:
  - rg "\bProcessId\b|\bProcessInfo\b|\bgetpid\b|waitpid|spawn_with_caps|fork\(|/proc/self" -S kernel/src || true
  - git grep -n "posix-compat" || true
- CI/検証（ローカル）:
  - bash scripts/check-posix-compat.sh  (結果: ProcessId usage limited to allowlist.)
  - cargo build -p rany_kernel --no-default-features  (結果: rustc ICE / `rustc-ice-2026-01-20T07_36_00-39165.txt`)

---

## モジュール別詳細

### 1) `kernel/src/task/process.rs` (コア実装)
- 代表的関数・シンボル（行番号はリポジトリ）:
  - set_current_process/get_current_process (l28, l36)
  - pub struct `ProcessId(u64)` (l47) + `DomainId` 変換 (l62)
  - `ProcessInfo` / `ProcessManager`（プロセスマネージャ）(l380, l495)
  - `spawn` (l691) / `spawn_with_caps` (l709)
  - `exit`/`waitpid`/`getpid`/`getppid`/`getuid`/`getgid`/`get_current_process_memcg_id` (l882, l891, l897, l902, l912, l922, l932)
  - `setpriority`/`getpriority` (l942, l950)
- ガード状況:
  - 実装本体は core に常駐。外部公開は `task::compat::process` 経由（`task/mod.rs` の `#[cfg(feature="posix-compat")]`）。
- 依存/結合:
  - `mm/autonuma.rs` が `ProcessInfo` の `numa_scan_addr` を利用（`scan_task`）。Domain/Task コンテキストへの移動候補。
- テスト:
  - `#[cfg(test)]` の `tests`（spawn_with_caps 系）と `unit_tests`（create/exit）を保持。`posix-compat` とは無関係に実行される。
- 推奨アクション:
  - `ProcessId` → `DomainId` shim を活かし、公開 API を段階的に Domain ベースへ移行。
  - `numa_scan_addr` は `TaskContext` or Domain スコープへ移し、`ProcessInfo` 依存を削減。

### 2) `kernel/src/task/signal.rs` (シグナル)
- 代表的関数・シンボル（行番号はリポジトリ）:
  - `Signal` (l20), `SignalQueue` (l237), `SignalContext` (l343), `SignalManager` (l532)
  - `kill` (l639) / `raise` (l644) / `signal`(handler) (l654) / `sigignore` (l660) / `sigdefault` (l666)
- ガード状況:
  - 公開面は `task::compat::signal` 経由（`task/mod.rs` の `#[cfg(feature="posix-compat")]`）。
- 補足:
  - 送信元 PID は `SignalManager::send_with_data` 内で `process::get_current_process()` から取得（`sender_pid: Option<u64>`）。
- テスト:
  - `#[cfg(test)]` の `test_signal_mask` / `test_signal_queue` が存在。
- 推奨アクション:
  - POSIX 互換用途の API は `posix-compat` 下に集約。core は内部通知（SIGWAKE/SIGDOMAIN）中心へ縮小。
  - `sender_pid` を Domain-aware にするなら `DomainId` への置換を検討。

### 3) `kernel/src/fs/procfs/mod.rs` と `kernel/src/compat/posix/procfs_pid.rs`
- 内容（行番号はリポジトリ）:
  - `ProcFs` (l152) と `init_static_entries` (l174) が `/proc/*` の system 出力を `/sys/system` に委譲
  - `ProcFs::read_with_token` (l341) が `/proc/<pid>/fd/<n>` を特別扱いし、`CAP_FOWNER`/`CAP_SYS_PTRACE`/`CAP_SYS_ADMIN` or token を検証
  - `ProcFileHandle::open_with_token` (l438) / `ProcDirHandle::opendir_with_token` (l593) が token の in-flight を管理
  - `/proc/[pid]` は `compat/posix/procfs_pid.rs` に集約（`add_process` l27, `generate_process_*` l115/l192/l227/l258/l285）
- ガード状況:
  - `kernel/src/fs/mod.rs` で `#[cfg(feature = "posix-compat")]` により `procfs` を丸ごと feature-gate。`procfs_pid.rs` も同条件でビルド。
- テスト:
  - `kernel/src/fs/procfs/mod.rs` は `#[cfg(all(test, feature = "std"))]` のみで実行。
  - `kernel/src/lib.rs` の procfs 用 process スタブも `#[cfg(feature = "posix-compat")]`。
- 推奨アクション:
  - `/proc` system 系は現状の `/sys/system` 委譲を維持し、互換層のみで公開。
  - `/proc/[pid]` は `sys/cell` マッピング or 互換限定のどちらかに統一し、Domain 観測経路を一本化。

### 4) `kernel/src/mm/address_space.rs` (アドレス空間)
- 代表的シンボル（行番号はリポジトリ）:
  - `ProcessAddressSpace` (l287)
  - `mmap`/`munmap`/`mprotect` (l422, l458, l470)
  - `brk`/`set_brk` (l510, l515)
  - `fork` (l564)
  - `exec_reset`/`load_segment`/`setup_stack` (l626, l658, l679)
- ガード状況:
  - `mm/mod.rs` で `ProcessAddressSpace` が常時 re-export。`posix-compat` ではガードされていない。
- 状況:
  - `fork()` の呼び出し箇所は未検出。`exec_reset()` は Drop (l1057) からのみ使用。
  - `mm/thp_promotion.rs` は `ProcessAddressSpace` を前提に THP 処理を実装。
  - `mm/cow.rs` / `mm/demand_paging.rs` は fork 前提のコメントのみ。
- テスト:
  - `#[cfg(test)]` で `Protection`/`MemoryRegion` の単体テストのみ。
- 推奨アクション:
  - `fork`/`exec_reset` を互換層へ移すか、Domain-aware API へ置換。
  - core の mapping primitive と POSIX 語義を分離する設計整理を進める。

### 5) `kernel/src/mm/mmap.rs` / `MemoryMapping`
- 代表的シンボル（行番号はリポジトリ）:
  - `MemoryMapping` (l130), `MmapManager` (l404)
  - `mmap`/`mmap_file`/`munmap`/`mprotect`/`msync` (l835, l845, l857, l862, l871)
- 状況:
  - file mapping は `memfs::read_file_content` を使用（擬似的）。flags は POSIX 由来の語義が含まれる。
- テスト:
  - `#[cfg(test)]` の `test_anonymous_mmap` / `test_mapping_read_write` が存在。
- 推奨:
  - primitive は保持し、per-process semantics は Domain-aware に段階移行。

### 6) Shell / Service / DevFS（利用側）
- `kernel/src/shell/exoshell/namespaces/cap.rs` は `/proc/*` と `/sys/cell/*` を feature-gate で切り分け済み
- `kernel/src/fs/devfs.rs` の `/dev/stdin` symlink は `#[cfg(feature = "posix-compat")]` で制御済み
- `kernel/src/service_impl.rs` の file handle registry が `/proc/<pid>/fd` の参照元（Domain 所有者付き）
- `kernel/src/fs/sysfs.rs` は `/sys/system` を提供し、`/proc` 互換の system 出力を生成
- 推奨: capability マッピングとシェルのドキュメントを更新して、`/proc` へ直接依存しないようにする

---

## CI とテストの現状
- `scripts/check-posix-compat.sh` : **ProcessId usage limited to allowlist.** を確認（ローカル実行済み）
- `.github/workflows/ci.yml` に `compat-off` ジョブが存在（`no-default-features` ビルド）
- `cargo build -p rany_kernel --no-default-features` は rustc ICE で停止（`rustc-ice-2026-01-20T07_36_00-39165.txt` を生成）
- `procfs` の unit tests は `#[cfg(all(test, feature = "std"))]` かつ `posix-compat` でのみコンパイルされるため、compat-off のテスト失敗要因にはなりにくい

---

## リスク＆優先度（短く）
- 高リスク: `ProcessAddressSpace::fork()`/`exec_reset()` が core に残ることで、後続リファクタで想定外の呼び出しが発生し得る → **互換層への移行優先**
- 中リスク: `mm/autonuma` が `ProcessInfo` に依存（`numa_scan_addr`）し、Domain 移行の足かせになる
- 中リスク: `compat-off` ビルドが rustc ICE で停止（CI の安定性リスク）
- 低リスク: Signal API の公開（互換下のまま短縮）

---

## 推奨次アクション（実務、優先順）
1. CI: `compat-off` の rustc ICE を解消（nightly の pin/更新 or ICE 回避策の適用、短期）。
2. 移行: `ProcessAddressSpace::fork()`/`exec_reset()` を `compat/posix` へ移動 or feature ガード化（中期、1–3 日）。
3. 依存整理: `mm/autonuma` の `numa_scan_addr` を Domain/Task コンテキストへ移行（中期、1–2 日）。
4. リント: `scripts/check-posix-compat.sh` の拡張（`ProcessInfo`/`procfs` 系の検出や allowlist の明文化）で回帰検知を強化（短期）。
5. ドキュメント: `docs/migration_from_posix.md` に今回の詳細差分を反映（短期）。

---

## 結論（短く）
- 現時点で**高影響の未検出レガシー参照は見つかりません**。`ProcessId` は allowlist 内に限定され、`posix-compat` を使った隔離が進んでいます。🎯
- 次の優先作業は **compat-off ビルドの ICE 解消**、`fork/exec_reset` の互換層移行、`mm/autonuma` の依存整理です。⚡

---

必要なら、上記の**(1) compat-off ICE 対応 / (2) fork/exec_reset → compat 移行 / (3) mm/autonuma 依存整理**のどれから着手しますか？
