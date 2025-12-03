#pragma once

#include <bit>

#include "ed25519_keys.h"
#include "ipv6_addr.h"

namespace yggdrasil_cpp_genkeys
{

/**
 * @brief Compares two Ed25519 public keys to determine which is "better".
 * 
 * This function implements a custom comparison metric for public keys, 
 * evaluating them byte-by-byte from most significant to least significant.
 * A key is considered "better" if it has more leading zero bits in the
 * first differing byte when scanning from the beginning of the array.
 * 
 * @param key1 First public key to compare
 * @param key2 Second public key to compare
 * @return true if key1 is considered better than key2 according to the metric
 * @return false if key2 is better or equal to key1
 */
static inline bool IsBetter(const PublicKey_t& key1, const PublicKey_t& key2)
{
    for (size_t i = 0; i < PublicKey_t::Size; ++i) {
        // Count leading zeros in each byte (0-8 possible)
        const auto bits1 =
            std::countl_zero(key1.bytes[i]);  // leading bits for key 1
        const auto bits2 =
            std::countl_zero(key2.bytes[i]);  // leading bits for key 2
        if (bits1 > bits2) {
            return true;
        }
        else if (bits1 < bits2) {
            return false;
        }
        else if (bits1 != 8) {
            return false;
        }
    }

    return false;
}

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
        size_t byte_offset = i * BYTES_PER_BLOCK;

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