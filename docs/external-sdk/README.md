# ExoRust External SDK Draft

- Status: Draft for future external repository extraction
- Audience: 使いやすい高水準 SDK の API 面を先に確認したい開発者

このディレクトリは、将来的に外部リポジトリとして切り出すことを想定した
SDK ドキュメント草案です。ここで説明する surface は core canonical spec ではなく、
packet-ownership を中心とする本体ネットワークモデルの上に構築される
**使いやすさ優先・高オーバーヘッド許容** の SDK を対象にしています。

## 方針

- stream-first の mental model を提供する
- `TcpStream` / `TcpListener` を前面に出す
- `AsyncRead` / `AsyncWrite` 相当の read/write を中心に説明する
- zero-copy helper は高速 path への escape hatch として残す
- core canonical docs の性能モデルや ownership vocabulary を、そのまま SDK の正規面にはしない

## 想定 API

### TCP ストリーム / リスナー

```rust
use exorust::net::tcp::{TcpListener, TcpStream};

let mut connection = TcpStream::dial(remote_addr).await?;
connection.write(b"hello").await?;

let mut buf = [0u8; 2048];
let n = connection.read(&mut buf).await?;

let listener = TcpListener::listen_on(local_addr).await?;
let (mut accepted, peer) = listener.next_connection().await?;
let packetish_chunk = accepted.read_zero_copy().await;
```

### RAW endpoint

```rust
use exorust::net::raw::RawEndpoint;

let endpoint = RawEndpoint::open(scope)?;
let payload = endpoint.recv_payload().await?;
endpoint.send_payload(payload).await?;
```

## 使い分け

- 一般アプリ、CLI、HTTP/TLS クライアント、テストコード:
  stream-first SDK surface を優先する
- packet ownership、mempool、driver queue、polling tuning、batching:
  core docs / core API を直接参照する

## 移行メモ

- POSIX 風の `socket()` / `bind()` / `listen()` を SDK の主要 narrative にしない
- 型付き `TcpStream` / `TcpListener` / `RawEndpoint` へ寄せる
- zero-copy は通常 read/write の代替ではなく、高速経路や specialized workload 向け補助として扱う

## 抽出前提

- この subtree は将来そのまま外部リポへ移動できるよう、main docs hub からの導線を持たない
- 現時点ではこの `README.md` 単独で読める最小構成にしている
