// ============================================================================
// kernel/src/net/services/http/server/index_html.rs - サービス / HTTP / サーバ / index html
// ============================================================================

pub(super) const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
    <title>ExoRust Kernel</title>
    <style>
        body { font-family: sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }
        h1 { color: #e94560; }
        .stats { background: #16213e; padding: 20px; border-radius: 8px; }
        .stat { margin: 10px 0; }
        a { color: #0f4c75; }
    </style>
</head>
<body>
    <h1>🦀 ExoRust Kernel HTTP Server</h1>
    <p>Welcome to the ExoRust zero-copy HTTP server!</p>

    <h2>Architecture Highlights</h2>
    <ul>
        <li><strong>Single Address Space (SAS)</strong> - No TLB flushes</li>
        <li><strong>Single Privilege Level (SPL)</strong> - Syscalls are function calls</li>
        <li><strong>Zero-Copy I/O</strong> - Data flows without copying</li>
        <li><strong>Async-First Design</strong> - Cooperative multitasking</li>
    </ul>

    <h2>Endpoints</h2>
    <ul>
        <li><a href="/">/</a> - This page</li>
        <li><a href="/stats">/stats</a> - Server statistics</li>
        <li><a href="/info">/info</a> - System information</li>
        <li><a href="/health">/health</a> - Health check</li>
        <li><a href="/memory">/memory</a> - Detailed memory information</li>
        <li><a href="/executors">/executors</a> - Per-core scheduler statistics</li>
        <li><a href="/logs">/logs</a> - Kernel log viewer</li>
        <li><a href="/echo">/echo</a> - POST Echo API</li>
    </ul>

    <p><em>Running on ExoRust v0.3.0</em></p>
</body>
</html>"#;
