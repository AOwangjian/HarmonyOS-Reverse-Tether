// SPDX-License-Identifier: Apache-2.0
#include "icmpv6.h"

#include <cstring>

namespace tether {
namespace {
constexpr size_t kIpv6HeaderLength = 40;
constexpr size_t kIcmpv6HeaderLength = 8;
// RFC 4443 3.1: an ICMPv6 error must not exceed the IPv6 minimum MTU.
constexpr size_t kMaxIcmpv6Packet = 1280;
constexpr uint8_t kNextHeaderIcmpv6 = 58;
}  // namespace

uint16_t Ipv6Checksum(const uint8_t *source, const uint8_t *destination,
                      uint8_t nextHeader, const uint8_t *payload, size_t length) {
    uint32_t sum = 0;
    for (size_t i = 0; i < 16; i += 2) {
        sum += (uint32_t(source[i]) << 8) | source[i + 1];
        sum += (uint32_t(destination[i]) << 8) | destination[i + 1];
    }
    sum += uint32_t(length >> 16);
    sum += uint32_t(length & 0xffff);
    sum += nextHeader;
    size_t i = 0;
    for (; i + 1 < length; i += 2) {
        sum += (uint32_t(payload[i]) << 8) | payload[i + 1];
    }
    if (i < length) sum += uint32_t(payload[i]) << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return uint16_t(~sum);
}

bool BuildIcmpv6Unreachable(const uint8_t *packet, size_t size, std::vector<uint8_t> *out) {
    if (size < kIpv6HeaderLength || (packet[0] >> 4) != 6) return false;
    // Never answer an existing ICMPv6 error report (type < 128).
    if (packet[6] == kNextHeaderIcmpv6 && size > kIpv6HeaderLength &&
        packet[kIpv6HeaderLength] < 128) {
        return false;
    }
    // Never answer traffic addressed to a multicast group.
    if (packet[24] == 0xff) return false;

    size_t quote = size;
    if (quote > kMaxIcmpv6Packet - kIpv6HeaderLength - kIcmpv6HeaderLength) {
        quote = kMaxIcmpv6Packet - kIpv6HeaderLength - kIcmpv6HeaderLength;
    }
    const size_t icmpLength = kIcmpv6HeaderLength + quote;

    out->assign(kIpv6HeaderLength + icmpLength, 0);
    uint8_t *raw = out->data();

    raw[0] = 0x60;
    raw[4] = uint8_t(icmpLength >> 8);
    raw[5] = uint8_t(icmpLength & 0xff);
    raw[6] = kNextHeaderIcmpv6;
    raw[7] = 64;  // hop limit
    // Answer travels back to the sender: swap the endpoints.
    std::memcpy(raw + 8, packet + 24, 16);
    std::memcpy(raw + 24, packet + 8, 16);

    uint8_t *icmp = raw + kIpv6HeaderLength;
    icmp[0] = 1;  // Destination Unreachable
    icmp[1] = 1;  // Communication with destination administratively prohibited
    std::memcpy(icmp + kIcmpv6HeaderLength, packet, quote);

    const uint16_t checksum = Ipv6Checksum(raw + 8, raw + 24, kNextHeaderIcmpv6, icmp, icmpLength);
    icmp[2] = uint8_t(checksum >> 8);
    icmp[3] = uint8_t(checksum & 0xff);
    return true;
}

}  // namespace tether
