// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace tether {

// Fold a transport payload over the RFC 8200 8.1 pseudo header.
// `source` and `destination` must each be 16 bytes.
uint16_t Ipv6Checksum(const uint8_t *source, const uint8_t *destination,
                      uint8_t nextHeader, const uint8_t *payload, size_t length);

// Build an ICMPv6 Destination Unreachable (type 1, code 1) answering `packet`.
//
// Returns false when the original must not be answered: a malformed packet, an
// ICMPv6 error report, or a multicast destination. RFC 4443 2.4 forbids those
// replies because they can amplify into a storm -- VPN start-up alone emits
// several MLD multicasts.
bool BuildIcmpv6Unreachable(const uint8_t *packet, size_t size, std::vector<uint8_t> *out);

}  // namespace tether
