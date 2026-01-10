# Capabilities (Design & API) — ExoRust / ExoShell

💡 概要

ExoRust のケイパビリティモデルは「最小権限（least privilege）」と「言語ベース分離」を実践するための基盤です。シェル（ExoShell）からは権限の付与・剥奪・委譲・監査が行えるようにし、危険 API（例: `cell.swap`, `mmio.write`）は必ずケイパビリティでガードします。

目的: 安全で実用的な `cap.grant` / `cap.revoke` / `cap.list` と、シェル側での限定的な委譲（子シェル生成）を MVP として実装します。

---

## 用語

- Capability (ビット): カーネル内部のフラグ（`CAP_SYS_ADMIN`, `CAP_NET_BIND` 等）
- CapabilitySet: ドメイン（プロセス/シェル）が持つ capability の集合（effective, permitted 等）
- Grant Token: 付与操作のメタ情報（付与者・対象・有効期限・委譲可能フラグ）を持つエントリ。`cap.grant` の結果として返却される識別子を持ちます。

---

## 高レベルポリシー

- `cap.grant` を呼べるのは以下のいずれか:
  - 呼び出し元が `CAP_SYS_ADMIN` を持つ
  - 呼び出し元の `permitted` が付与しようとする capability の subset を含む

- `revoke` の方針（合意）:
  - デフォルト: 新しい操作は即時拒否（effective/permitted を取り除く）
  - 既存の in-flight 操作は EBR（Epoch-based Reclamation）により安全にドレインされることを期待する。MVP では即時拒否と監査ログ、回収確認 API を提供します。

- 委譲（delegation）は明示的で、デフォルトは False。TTL（expires）による一時付与をサポート。もし `delegatable=true` の場合、受け取ったドメインは自身の `permitted` 範囲のサブセットをさらに他に付与できます（ただし、親よりも強い権限に昇格できません）。

---

## API：カーネル（CapabilityManager）

（MVP 実装）

- grant_capability_with_opts(caller_domain: u64, target_domain: u64, cap: Capability, expires: Option<u64>, delegatable: bool) -> Result<token_id: u64, CapabilityError>
  - 返り値はトークン ID。トークンは監査・後続 revoke に使える。
  - 実行: `target.permitted |= cap; target.effective |= cap;` を行い、トークンテーブルに登録。

- revoke_grant(caller_domain: u64, token_id: u64, force: bool) -> Result<(), CapabilityError>
  - `force = false`: 新規操作は即時拒否（drop_permanently を行う）。in-flight の扱いは EBR によって安全にドレインされることを期待。
  - `force = true`: 強制撤回（将来的にはより強い介入を行うオプション）。

- list_grants(domain_id: u64) -> Vec<GrantToken>
  - ドメインに対して与えられたトークン一覧を返す。

- expire_tokens() (内部): 現在時刻を基に期限切れトークンを削除し、対応 capability を剥奪。

- Audit: grant / revoke / failed attempts は監査ログへ出力される。

---

## API：ExoShell（REPL 側 名前空間）

cap 名前空間（既存）を拡張します。

- cap.list() -> 現在の CapabilitySet を列挙（既存機能）
- cap.tokens() -> 現在のドメインに関連する GrantToken の一覧（新設）
- cap.grant(resource: &str, ops: &["read"|"write"|...], target: u64, options?: Map) -> Capability
  - options = { expires: <timestamp>, delegatable: <bool> }
  - 成功時に `ExoValue::Capability` を返す（`id` = token_id）
  - 失敗時は Error を返す

- cap.revoke(token_id: u64) -> bool
  - token 所有者か CAP_SYS_ADMIN のみが呼べる（呼び出し側チェック）

例:

- 単純付与:
  - `cap.grant("/net/bind", ["execute"], 200)`
- TTL と委譲可能を指定:
  - `cap.grant("/net/bind", ["execute"], 200, {expires: 1700000000, delegatable: true})`

---

## API：Shell Proxy（`shell.spawn()`）

MVP では `shell.spawn()` により**限定的な子シェル表現 (ShellProxy)** を生成できます。ShellProxy は `Map` として返り、以下のメソッドが利用できます。

- `spawn()` -> ShellProxy
- `proxy.with_cap(resource, ops, options?)` -> ShellProxy  (チェーン可能)
- `proxy.revoke(resource_or_cap_bit)` -> ShellProxy
- `proxy.list_caps()` -> Array(Capability)
- `proxy.run(name)` -> spawn a child process with the proxy's CapabilitySet (MVP: create process and assign caps; actual binary load may be out of scope)

実装はまずプロキシ上で CapabilitySet を保持し、`run()` では `process::create_with_caps` を呼んで新プロセスに CapabilitySet を適用します。`create_with_caps` は親ドメインの許可範囲を超える権限を与えられないようチェックします。

---

## 受け入れ基準（MVP）

1. `cap.grant` が操作可能（`expires`, `delegatable` オプションを受け付ける）
2. Manager 側にトークン登録（ID 返却）と `revoke_grant` が存在する
3. `cap.tokens()` でドメインのトークンが列挙できる
4. `shell.spawn()` で `ShellProxy` が作成でき、`with_cap`/`revoke` でプロキシの CapabilitySet を調整できる
5. `process::spawn_with_caps` で指定した CapabilitySet を新規プロセスへ適用できる（親の許可範囲を超えられない）
6. 基本的なユニットテストと監査ログ出力が追加される

---

## 安全上の注意点

- 危険 API (`cell.swap`, `mmio.write`, `driver.update`, など) は **必ず** `CAP_SYS_ADMIN` か明示的な capability チェックを通す。公開前に確認すること。
- `delegatable` を持つトークンは強力なので、デフォルト `false` を維持する。

---

## 実装ノート / 次フェーズ

- EBR を用いた in-flight drain の自動可視化（`cap.reclamation_status(token_id)` など）を追加
- `short-lived tokens` を発行する一時トークン API（`issue_temp_token(duration)`）
- process::spawn_with_caps によって作成されたトークンは、その子プロセスのライフタイム中に **in-flight** としてカウントされます。子プロセスの終了（reap）の際に in-flight カウントは減少し、これにより `revoke` の直後でも in-flight カウントが 0 になるまで `reclaim` が保留されることが保証されます（例: `spawn_with_caps(...)` 内で `increment_in_flight(token)` を呼び、プロセス回収時に `decrement_in_flight(token)` を呼ぶ）。
- ネットワークのバインドのような長期保持リソースもトークンと紐付けられます（例: `net.bind(port, token_id)`）。この場合、`bind(..., token)` は内部で `increment_in_flight(token)` を呼び、`unbind(...)` やソケットのクローズ時に `decrement_in_flight(token)` を呼び戻します。
- NVMe のダイレクトブロックハンドルもトークンと紐付け可能です（例: `nvme.open_direct_with_token(device, start, count, token)`）。`open` は `increment_in_flight(token)` を呼び、`close`（`nvme.close_direct(handle)`）は `decrement_in_flight(token)` を呼び戻します。
- デバイスファイルハンドル（例: `/dev/null` 等）もトークンと紐付け可能です（例: `DevFileHandle::open_with_token("null", Some(token_id))`）。`open_with_token` は `increment_in_flight(token)` を呼び、`Drop` 時に `decrement_in_flight(token)` を呼び戻します。
- ファイルのオープン（ファイルハンドル）もトークンと紐付け可能です（例: `fs.open_with_token(path, mode, Some(token_id))`）。`open_with_token` は `increment_in_flight(token)` を呼び、`fs_close`（`fs.close(handle)`）は `decrement_in_flight(token)` を呼び戻します。
- 共有メモリのアタッチもトークンと紐付け可能です（例: `shmat_with_token(shm_id, Some(token_id))`）。`shmat_with_token` は内部で `increment_in_flight(token)` を呼び、`shmdt`（`ShmHandle::detach`）やハンドルの破棄時に `decrement_in_flight(token)` を呼び戻します。
- `/proc/<pid>/mem` のようなプロセスメモリへのアクセスは `CAP_SYS_PTRACE`（または同等のトークン）で保護されます。`ProcFileHandle::open_with_token("<pid>/mem", Some(token))` のようにトークンでのオープンをサポートしており、`open_with_token` は `increment_in_flight(token)` を呼び、`Drop` 時に `decrement_in_flight(token)` を呼び戻します。これにより `revoke` の直後でも in-flight が 0 になるまで `reclaim` は保留されます。
- GUI 統合: grant/revoke の結果を ExoGUI で可視化

---

追記: 具体的な関数シグネチャとテスト骨子はリポジトリ内に追加します（`libs/security`, `kernel/src/security/capability.rs`, `kernel/src/shell/exoshell/namespaces/cap.rs`, `kernel/src/shell/exoshell/namespaces/shell.rs`）。
