#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

fail() {
  echo "check-network-zero-copy-guard: $1" >&2
  exit 1
}

if rg -n "payload_span_to_vec\\(" kernel/src/net >/dev/null; then
  fail "found removed DHCP payload_span_to_vec helper"
fi

if rg -n "hostname:\\s*Vec<u8>" kernel/src/net/l4/endpoint/event.rs >/dev/null; then
  fail "found Vec<u8> DHCP hostname event payload"
fi

if rg -n "domain_search:\\s*Vec<.*String>" kernel/src/net/l4/endpoint/event.rs >/dev/null; then
  fail "found Vec<String> DHCPv6 domain_search event payload"
fi

if rg -n "BTreeMap<String,\\s*DnsCacheEntry>" kernel/src/net/services/dns/mod.rs >/dev/null; then
  fail "found raw String DNS cache key"
fi

if rg -n "BTreeMap<String,\\s*MdnsCacheEntry>" kernel/src/net/services/mdns/mod.rs >/dev/null; then
  fail "found raw String mDNS cache key"
fi

prod_globs=(
  --glob '!**/tests/**'
  --glob '!**/tests.rs'
  --glob '!**/qemu_tests/**'
  --glob '!**/qemu_tests.rs'
)

if rg -n "vec_from_payload\\(" \
  kernel/src/net/runtime kernel/src/net/l3 kernel/src/net/l4 kernel/src/net/services kernel/src/net/security/tls \
  "${prod_globs[@]}" >/dev/null; then
  fail "found removed TLS payload flatten helper"
fi

if rg -n "packet_payload_from_slice\\(|packet_payload_from_parts\\(" \
  kernel/src/net/runtime kernel/src/net/l3 kernel/src/net/l4 kernel/src/net/services kernel/src/net/security/tls \
  "${prod_globs[@]}" >/dev/null; then
  fail "found removed TLS packet payload builder helper"
fi

if rg -n "payload_preview_bytes\\(" kernel/src/net/runtime/bridge/mlx5_bridge.rs >/dev/null; then
  fail "found removed mlx5 payload preview linearization"
fi

if rg -n "build_stack_payload\\(|enqueue_v6_send_bytes\\(" \
  kernel/src/net/services kernel/src/net/l4 \
  "${prod_globs[@]}" >/dev/null; then
  fail "found removed DHCP/mDNS byte-to-payload helper"
fi

if rg -n "\\bpayload_from_bytes\\(|\\bpacket_from_bytes\\(" \
  kernel/src/net/runtime/bridge kernel/src/net/runtime/stack kernel/src/net/l3/ipv6 kernel/src/net/services/dns kernel/src/net/services/mdns kernel/src/net/security/tls \
  "${prod_globs[@]}" >/dev/null; then
  fail "found production path raw byte-to-packet helper"
fi

if rg -n "to_owned_string\\(|to_lowercase_string\\(" kernel/src/net/services/mdns/mod.rs >/dev/null; then
  fail "found early text materialization in mDNS production path"
fi

echo "check-network-zero-copy-guard: ok"
