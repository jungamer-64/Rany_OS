#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

network_tree=(
  kernel/src/net
  kernel/src/net/security
)

fail() {
  echo "check-network-zero-copy-guard: $1" >&2
  exit 1
}

if rg -n "payload_span_to_vec\\(" "${network_tree[@]}" >/dev/null; then
  fail "found removed DHCP payload_span_to_vec helper"
fi

if rg -n "hostname:\\s*Vec<u8>" "${network_tree[@]}" >/dev/null; then
  fail "found Vec<u8> DHCP hostname event payload"
fi

if rg -n "domain_search:\\s*Vec<.*String>" "${network_tree[@]}" >/dev/null; then
  fail "found Vec<String> DHCPv6 domain_search event payload"
fi

if rg -n "BTreeMap<String,\\s*DnsCacheEntry>" "${network_tree[@]}" >/dev/null; then
  fail "found raw String DNS cache key"
fi

if rg -n "BTreeMap<String,\\s*MdnsCacheEntry>" "${network_tree[@]}" >/dev/null; then
  fail "found raw String mDNS cache key"
fi

if rg -n "vec_from_payload\\(" \
  "${network_tree[@]}" \
  >/dev/null; then
  fail "found removed TLS payload flatten helper"
fi

if rg -n "read_vec\\(" \
  "${network_tree[@]}" \
  >/dev/null; then
  fail "found removed read_vec-based parser or record path"
fi

if rg -n "packet_payload_from_slice\\(|packet_payload_from_parts\\(" \
  "${network_tree[@]}" \
  >/dev/null; then
  fail "found removed TLS packet payload builder helper"
fi

if rg -n "\\bOwnedPayloadRange\\b" "${network_tree[@]}" >/dev/null; then
  fail "found removed owned payload range abstraction"
fi

if rg -n "\\bpayload_span_from_slice\\(" "${network_tree[@]}" >/dev/null; then
  fail "found removed TLS slice-to-owned-payload helper"
fi

if rg -n "\\bcopy_all_into\\(" "${network_tree[@]}" >/dev/null; then
  fail "found removed full-payload copy helper"
fi

if rg -n "pub fn (copy_into|copy_range|as_contiguous_slice)\\(" \
  kernel/src/net/payload.rs interfaces/kernel_api/src/types.rs \
  >/dev/null; then
  fail "found removed generic payload linearization surface"
fi

if rg -n "payload_preview_bytes\\(" "${network_tree[@]}" >/dev/null; then
  fail "found removed mlx5 payload preview linearization"
fi

if rg -n "build_stack_payload\\(|enqueue_v6_send_bytes\\(" \
  "${network_tree[@]}" \
  >/dev/null; then
  fail "found removed DHCP/mDNS byte-to-payload helper"
fi

if rg -n "\\bpayload_as_contiguous_slice\\(|\\bpayload_from_packet_range\\(|\\bpayload_from_subslice\\(|\\bpayload_from_bytes\\(|\\bpacket_from_bytes\\(" \
  "${network_tree[@]}" \
  >/dev/null; then
  fail "found removed contiguous or packet extraction helper"
fi

if rg -n "PayloadSpan::from_bytes\\(|DnsNameView::from_labels\\(|DnsNameOwned::from_labels\\(|DnsTxtView::from_spans\\(" \
  "${network_tree[@]}" \
  >/dev/null; then
  fail "found removed payload span or DNS/TXT convenience constructor"
fi

if rg -n "to_owned_string\\(|to_lowercase_string\\(" "${network_tree[@]}" >/dev/null; then
  fail "found early text materialization in mDNS production path"
fi

if rg -n "DnsNameOwned::from_ascii_name|DnsNameOwned::from_view" "${network_tree[@]}" >/dev/null; then
  fail "found removed DNS owned-name string/view constructor"
fi

if rg -n "\\bprocess_single_record\\(|\\bdecrypt_record\\(|\\btls13_decrypt_record\\(" "${network_tree[@]}" >/dev/null; then
  fail "found removed TLS record ingress root"
fi

if rg -n -e "rsa_pkcs1_encrypt\\(|\\bmgf1\\(|\\bhash_compute\\(" \
  "${network_tree[@]}" \
  >/dev/null; then
  fail "found removed crypto owned-buffer helper"
fi

if rg -n -e "->\\s*(Option<)?Vec<u8>" \
  "${network_tree[@]}" \
  >/dev/null; then
  fail "found removed Vec-returning crypto surface"
fi

if rg -n "server_name:\\s*Option<String>|alpn_protocols:\\s*Vec<String>|ca_certs:\\s*Vec<Certificate>|VecDeque<SessionCacheEntry>" \
  "${network_tree[@]}" \
  >/dev/null; then
  fail "found removed Vec/String-based TLS config or session cache surface"
fi

if rg -n "packet\\.clone\\(|payload\\.clone\\(|PacketPayload::single\\(packet\\.clone\\)" \
  "${network_tree[@]}" \
  >/dev/null; then
  fail "found retained clone root in network/security tree"
fi

if rg -n "\\bZeroCopyBuffer\\b|\\bZeroCopyWriter\\b|\\bSgList\\b|\\bDmaSgEntry\\b|datapath::zero_copy|mod zero_copy|pub mod zero_copy" \
  kernel/src/net interfaces/kernel_api/src/netdev.rs interfaces/kernel_api/src/resource/net.rs interfaces/kernel_api/src/types.rs \
  >/dev/null; then
  fail "found removed zero_copy buffer facade"
fi

if rg -n "\\btransmit_bytes_internal\\b|\\btransmit_bytes_with_meta_internal\\b" \
  kernel/src/net \
  >/dev/null; then
  fail "found removed byte-slice TX runtime surface"
fi

if rg -n "PacketRef::from_vec|PacketPayload::from_vec|PacketPayload::into_vec|\\.to_vec\\(\\)" \
  kernel/src/net interfaces/kernel_api/src \
  >/dev/null; then
  fail "found removed test-only packet materializer"
fi

echo "check-network-zero-copy-guard: ok"
