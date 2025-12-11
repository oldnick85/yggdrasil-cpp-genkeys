#pragma once

#include <bit>

#include "ed25519_keys.h"
#include "ipv6_addr.h"

namespace yggdrasil_cpp_genkeys
{

static inline uint LeadingZeroBits(const PublicKey_t& key)
{
    uint count = 0;
    for (size_t i = 0; i < PublicKey_t::Size; ++i) {
        const auto bits = std::countl_zero(key.bytes[i]);
        count += bits;
        if (bits != 8) {
            break;
        }
    }

    return count;
}

static inline uint AddressZeroBlocks(const IPv6_Addr& addr)
{
    constexpr size_t BLOCKS_COUNT = 8;
    constexpr size_t BYTES_PER_BLOCK = 2;

    size_t max_consecutive_zeros = 0;
    size_t consecutive_zeros = 0;

    for (size_t i = 1; i < BLOCKS_COUNT; ++i) {
        const size_t byte_offset = i * BYTES_PER_BLOCK;

        const bool zero = (addr.bytes[byte_offset] == 0) and
                          (addr.bytes[byte_offset + 1] == 0);

        if (zero) {
            ++consecutive_zeros;
            max_consecutive_zeros =
                std::max(max_consecutive_zeros, consecutive_zeros);
        }
        else {
            consecutive_zeros = 0;
        }
    }

    return max_consecutive_zeros;
}

}  // namespace yggdrasil_cpp_genkeys