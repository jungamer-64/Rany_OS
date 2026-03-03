# ECDH鍵交換実装計画書

## 概要

TLS 1.2/1.3での楕円曲線ディフィー・ヘルマン（ECDH）鍵交換実装。
X25519には `ed25519-compact` クレート（`x25519` feature）を活用し、
Montgomery Ladder等の低レベル演算を自前実装せずに済ませる。

---

## 現状分析

### 既存コード

| ファイル | 状態 |
|---|---|
| [kernel/src/net/tls.rs](../kernel/src/net/tls.rs) | ECDHE暗号スイート定義済み、`process_server_key_exchange()`はランダムpre-master secretで仮実装 |
| [kernel/Cargo.toml](../kernel/Cargo.toml) | `ed25519-compact = { version = "2", default-features = false }` — **`x25519` feature 未有効** |

### `ed25519-compact` X25519 API（v2.2.0）

```rust
// ed25519_compact::x25519 モジュール（feature = "x25519" で有効化）
pub struct SecretKey([u8; 32]);    // 秘密鍵（スカラー）
pub struct PublicKey([u8; 32]);    // 公開鍵（u座標）
pub struct DHOutput([u8; 32]);     // 共有秘密（非均一、要ハッシュ）
pub struct KeyPair { pk, sk }      // 鍵ペア

impl SecretKey {
    fn new(sk: [u8; 32]) -> Self;
    fn from_slice(sk: &[u8]) -> Result<Self, Error>;
    fn clamped(&self) -> SecretKey;              // RFC 7748 クランプ処理
    fn recover_public_key(&self) -> Result<PublicKey, Error>;
    // Ed25519秘密鍵からの変換（disable-signaturesでなければ利用可）
    fn from_ed25519(edsk: &EdSecretKey) -> Result<Self, Error>;
}

impl PublicKey {
    fn new(pk: [u8; 32]) -> Self;
    fn from_slice(pk: &[u8]) -> Result<Self, Error>;
    fn base_point() -> PublicKey;                // Curve25519ベースポイント
    fn dh(&self, sk: &SecretKey) -> Result<DHOutput, Error>;  // ★ ECDH共有秘密
    fn clear_cofactor(&self) -> Result<[u8; 32], Error>;
}

impl KeyPair {
    #[cfg(feature = "random")]
    fn generate() -> KeyPair;                    // ランダム鍵生成
}
```

**重要**: `DHOutput` は非均一出力のため、TLS pre-master secretとして使用する際は
そのまま `derive_master_secret()` に渡す（TLS PRFがハッシュ処理を行う）。

---

## 実装計画

### Phase 1: X25519 ECDH（`ed25519-compact` 活用）

#### Step 1.1: Cargo.toml — `x25519` feature 有効化

```toml
# kernel/Cargo.toml
ed25519-compact = { version = "2", default-features = false, features = ["x25519"] }
```

#### Step 1.2: `kernel/src/net/ecdh.rs` — ECDH抽象化レイヤー

```rust
// kernel/src/net/ecdh.rs
use alloc::vec::Vec;
use ed25519_compact::x25519::{
    PublicKey as X25519PublicKey,
    SecretKey as X25519SecretKey,
    KeyPair as X25519KeyPair,
};

/// サポートする名前付きグループ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcdhGroup {
    X25519,
    // 将来: Secp256r1, X448, etc.
}

/// ECDH一時鍵ペア（グループごとの抽象層）
pub enum EcdhKeyPair {
    X25519 {
        sk: X25519SecretKey,
        pk: X25519PublicKey,
    },
}

impl EcdhKeyPair {
    /// 鍵ペア生成（RDRANDベース）
    pub fn generate(group: EcdhGroup) -> Result<Self, EcdhError> {
        match group {
            EcdhGroup::X25519 => {
                // 1. RDRAND で32バイト生成（tls.rs の generate_random() を利用）
                // 2. SecretKey::new() でラップ
                // 3. recover_public_key() で公開鍵導出
                let random_bytes = super::tls::generate_random_bytes();
                let sk = X25519SecretKey::new(random_bytes);
                let pk = sk.recover_public_key()
                    .map_err(|_| EcdhError::KeyGenerationFailed)?;
                Ok(EcdhKeyPair::X25519 { sk, pk })
            }
        }
    }

    /// 公開鍵をバイト列として取得（TLSワイヤーフォーマット用）
    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            EcdhKeyPair::X25519 { pk, .. } => pk.as_ref().to_vec(),
        }
    }

    /// ピアの公開鍵と共有秘密を計算
    pub fn shared_secret(&self, peer_public: &[u8]) -> Result<Vec<u8>, EcdhError> {
        match self {
            EcdhKeyPair::X25519 { sk, .. } => {
                let peer_pk = X25519PublicKey::from_slice(peer_public)
                    .map_err(|_| EcdhError::InvalidPeerKey)?;
                let dh_output = peer_pk.dh(sk)
                    .map_err(|_| EcdhError::SharedSecretFailed)?;
                Ok(dh_output.as_ref().to_vec())
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum EcdhError {
    KeyGenerationFailed,
    InvalidPeerKey,
    SharedSecretFailed,
    UnsupportedGroup,
}
```

#### Step 1.3: `tls.rs` — `process_server_key_exchange()` 更新

現在のプレースホルダー実装を実際のECDH計算に置き換える。

```rust
fn process_server_key_exchange(&mut self, data: &[u8]) -> TlsResult<()> {
    if data.len() < 4 {
        return Err(TlsError::DecodeError);
    }

    let curve_type = data[0];
    if curve_type != 0x03 { // named_curve
        return Err(TlsError::UnsupportedCipherSuite);
    }

    let named_curve = ((data[1] as u16) << 8) | (data[2] as u16);
    let pubkey_len = data[3] as usize;

    if data.len() < 4 + pubkey_len {
        return Err(TlsError::DecodeError);
    }

    let server_pubkey = &data[4..4 + pubkey_len];

    // NamedGroupからEcdhGroupへマッピング
    let group = match named_curve {
        0x001D => EcdhGroup::X25519,
        _ => return Err(TlsError::UnsupportedCipherSuite),
    };

    // ★ 実際のECDH鍵交換
    let local_keypair = EcdhKeyPair::generate(group)
        .map_err(|_| TlsError::CryptoError)?;

    // 共有秘密計算
    let shared_secret = local_keypair.shared_secret(server_pubkey)
        .map_err(|_| TlsError::CryptoError)?;

    // 公開鍵をClientKeyExchange用に保存
    self.local_ecdh_keypair = Some(local_keypair);

    // pre_master_secret = ECDH共有秘密
    self.pre_master_secret = shared_secret;

    // Master secret導出
    self.master_secret = derive_master_secret(
        &self.pre_master_secret,
        &self.client_random,
        &self.server_random,
    );

    Ok(())
}
```

#### Step 1.4: `TlsConnection` — フィールド追加 & ClientKeyExchange構築

```rust
pub struct TlsConnection {
    // 既存フィールド...

    /// ECDH一時鍵ペア（ClientKeyExchange送信用）
    local_ecdh_keypair: Option<EcdhKeyPair>,
}

impl TlsConnection {
    /// ClientKeyExchangeメッセージ構築（TLS 1.2 ECDHE）
    fn build_client_key_exchange(&self) -> Option<Vec<u8>> {
        let keypair = self.local_ecdh_keypair.as_ref()?;
        let pubkey_bytes = keypair.public_key_bytes();

        let mut msg = Vec::new();
        // EC point length prefix (1バイト)
        msg.push(pubkey_bytes.len() as u8);
        msg.extend_from_slice(&pubkey_bytes);

        // Handshakeヘッダ
        let mut handshake = vec![16u8]; // ClientKeyExchange type = 16
        let len = msg.len();
        handshake.push(0);
        handshake.push((len >> 8) as u8);
        handshake.push(len as u8);
        handshake.extend_from_slice(&msg);

        // RecordLayerヘッダ
        let mut record = vec![
            ContentType::Handshake as u8,
            0x03, 0x03, // TLS 1.2
            (handshake.len() >> 8) as u8,
            handshake.len() as u8,
        ];
        record.extend_from_slice(&handshake);

        Some(record)
    }
}
```

#### Step 1.5: ハンドシェイクフロー統合

`process_incoming()` 内のハンドシェイク終了後に ClientKeyExchange + ChangeCipherSpec + Finished を送信する流れを追加。

```
Client                          Server
------                          ------
ClientHello         →
                    ←           ServerHello
                    ←           Certificate
                    ←           ServerKeyExchange  ← ★ ECDH params
                    ←           ServerHelloDone
ClientKeyExchange   →           ← ★ クライアント公開鍵
ChangeCipherSpec    →
Finished            →
                    ←           ChangeCipherSpec
                    ←           Finished
[Application Data]  ↔           [Application Data]
```

---

### Phase 2: `generate_random()` 公開化

現在 `tls.rs` 内の `generate_random()` は private。ecdh.rs から呼べるようにする。

**方針A（推奨）**: `pub(crate) fn generate_random() -> [u8; 32]` に変更
**方針B**: ecdh.rs 内で独自にRDRAND呼び出し

---

### Phase 3: SECP256R1実装（将来）

`ed25519-compact` は SECP256R1 をサポートしないため、自前実装が必要。

```rust
// ecdh.rs に追加
pub enum EcdhKeyPair {
    X25519 { ... },
    P256 { sk: [u8; 32], pk: P256Point },   // 将来追加
}
```

必要な実装:
- GF(p) 有限体演算（256ビット mod p）
- Jacobian座標ポイント演算（加算・倍算）
- スカラー倍算（ウィンドウ法、定時間）
- ポイント圧縮/解凍

見積もり: ~600行

---

### Phase 4: X448実装（将来）

`ed25519-compact` は X448 をサポートしないため、自前実装が必要。

必要な実装:
- GF(2^448 - 2^224 - 1) 有限体演算
- Montgomery Ladder（a24 = 39081）

見積もり: ~400行

---

### Phase 5: TLS 1.3 KeyShare統合（将来）

TLS 1.3では ServerKeyExchange の代わりに KeyShare 拡張を使用。

```rust
// ClientHello extensions に KeyShare を追加
fn build_key_share_extension(&self) -> Vec<u8> {
    // X25519の場合:
    // extension_type = 51 (KEY_SHARE)
    // key_share_entry: NamedGroup(0x001D) + key_exchange(32 bytes)
}
```

---

## 変更ファイル一覧

| ファイル | 変更内容 |
|---|---|
| [kernel/Cargo.toml](../kernel/Cargo.toml) | `ed25519-compact` に `features = ["x25519"]` 追加 |
| kernel/src/net/ecdh.rs | **新規作成**: ECDH抽象化レイヤー |
| [kernel/src/net/mod.rs](../kernel/src/net/mod.rs) | `pub mod ecdh;` 追加 |
| [kernel/src/net/tls.rs](../kernel/src/net/tls.rs) | `process_server_key_exchange()` 更新、`local_ecdh_keypair` フィールド追加、`build_client_key_exchange()` 追加、`generate_random()` を `pub(crate)` に変更 |

---

## 実装サイズ見積もり

| コンポーネント | 行数 |
|---|---|
| ecdh.rs（X25519 wrapper） | ~120行 |
| tls.rs 変更（ECDH統合） | ~80行 |
| テスト | ~100行 |
| **Phase 1 合計** | **~300行** |

---

## セキュリティ考慮事項

### タイミング攻撃対策
- `ed25519-compact` の Montgomery Ladder は定時間実行（`Fe::cswap2` 使用）
- `DHOutput` の `Drop` 実装で秘密データを自動ワイプ（`Mem::wipe`）

### 弱い鍵の検出
- `PublicKey::dh()` は結果がゼロの場合 `Error::WeakPublicKey` を返す
- `PublicKey::from_slice()` は非正規表現を拒否（`Fe::reject_noncanonical`）

### ExoRust設計原則との整合
- **Safe Rust のみ**: `ed25519-compact` の内部 unsafe は Framework 層相当
- **Result でエラー伝播**: パニックなし
- **ゼロコピー意識**: `DHOutput` は `[u8; 32]` の薄いラッパー

---

## テスト戦略

```rust
#[cfg(test)]
mod tests {
    // 1. X25519 鍵交換対称性テスト
    //    Alice.shared_secret(Bob.pk) == Bob.shared_secret(Alice.pk)
    fn test_x25519_symmetry() { }

    // 2. RFC 7748 テストベクトル
    fn test_x25519_rfc7748_vectors() { }

    // 3. 弱い鍵拒否テスト（all-zero公開鍵）
    fn test_x25519_reject_weak_key() { }

    // 4. ServerKeyExchangeパース + ECDH計算の統合テスト
    fn test_process_server_key_exchange_x25519() { }

    // 5. ClientKeyExchange構築テスト
    fn test_build_client_key_exchange() { }
}
```

---

## 参考資料

- [RFC 7748 - Elliptic Curves for Security](https://tools.ietf.org/html/rfc7748)
- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446) (KeyShare)
- [ed25519-compact crate (x25519 module)](https://github.com/jedisct1/rust-ed25519-compact)
- [RFC 5246 - TLS 1.2](https://tools.ietf.org/html/rfc5246) (ServerKeyExchange format)
