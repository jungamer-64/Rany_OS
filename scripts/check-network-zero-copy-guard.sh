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

echo "check-network-zero-copy-guard: ok"
