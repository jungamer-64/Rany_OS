# Legacy Interface Migration Status (Completed)

更新日: 2026-03-03

この文書は、互換インターフェース撤廃後の最終状態を記録する。

## 1. 現在の運用方針

- 管理と観測の入口は ExoShell の `domain.*` と `sys.*` のみ。
- ディレクトリベース管理層は提供しない。
- 旧互換 feature gate は廃止済み。
- 互換 syscall 風ラッパは提供しない。

## 2. 主要な撤廃項目

- `/proc` 互換層を削除。
- IPC 互換ラッパ（`pipe2`, `mkfifo`, `shmget`, `shmat`, `shm_open` など）を削除。
- VM 公開 API 名を非POSIX命名へ統一。

| 旧公開名 | 現在の公開名 |
|---|---|
| `mmap` | `map_anonymous_region` / `map_file_region` |
| `munmap` | `unmap_region` |
| `mprotect` | `protect_region` |
| `msync` | `sync_region` |

## 3. 運用上の移行先

- ドメイン一覧: `domain.list()`
- ドメイン詳細: `domain.info(id)`
- ドメイン停止: `domain.kill(id)`

## 4. CI・再導入防止

- `scripts/check-no-posix-apis.sh` を標準ガードとして使用。
- 旧識別子の再導入は CI で fail させる。

## 5. 補足

本リポジトリは one-shot の破壊的移行を完了しており、互換期間は設けない。
