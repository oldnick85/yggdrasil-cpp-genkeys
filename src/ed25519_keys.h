#pragma once

#include <array>
#include <cassert>
#include <vector>

#include "bytes.h"
#include "ipv6_addr.h"

namespace yggdrasil_cpp_genkeys
{

/**
 * @brief Represents an Ed25519 public key (32 bytes / 256 bits).
 * 
 * Ed25519 public keys are 32-byte values derived from the corresponding
 * secret key through scalar multiplication on the elliptic curve.
 * This class provides type safety and clear semantics for public key operations.
 */
class PublicKey_t : public BaseKey_t<32U>
{
};

/**
 * @brief Represents an Ed25519 secret/private key (64 bytes / 512 bits).
 * 
 * In typical Ed25519, secret keys are 32 bytes, but some implementations
 * store them as 64 bytes (32-byte seed + 32-byte public key for performance).
 */
class SecretKey_t : public BaseKey_t<64U>
{
};

/**
 * @brief Represents an Ed25519 seed (32 bytes / 256 bits) with increment operation.
 * 
 * The seed is the random entropy used to generate Ed25519 key pairs.
 * The increment operator allows sequential seed generation for key search operations.
 */
class Seed_t : public BaseKey_t<32U>
{
   public:
    /**
     * @brief Increments the seed as a big-endian 256-bit unsigned integer.
     * 
     * This method implements increment-with-carry on the 32-byte seed,
     * treating it as a big-endian integer (most significant byte at index 0).
     * The operation is equivalent to: seed = seed + 1 (mod 2^256)
     * 
     * @return Seed_t& Reference to the incremented seed (*this)
     * 
     * @note When the seed reaches the maximum value (all 0xFF bytes),
     *       incrementing wraps around to all zeros (0x00).
     */
    Seed_t& operator++()
    {
        for (std::size_t i = Size; i-- > 0;) {
            if (bytes[i] != 0xFF) {
                ++bytes[i];
                return *this;
            }
            bytes[i] = 0;
        }
        return *this;
    }
};

/**
 * @brief Container for a complete Ed25519 key pair and its generating seed.
 * 
 * This struct groups together all components needed for key generation and
 * verification in the Yggdrasil key search algorithm.
 */
class Keys_t
{
   public:
    PublicKey_t public_key;
    SecretKey_t secret_key;
    Seed_t seed;
};

/**
 * @brief Returns the fixed prefix used for Yggdrasil IPv6 address generation.
 * 
 * Yggdrasil uses a specific prefix (0x02) for its IPv6 addresses to identify
 * them as belonging to the Yggdrasil mesh network. This prefix is part of the
 * IPv6 address construction algorithm.
 * 
 * @return constexpr std::array<uint8_t, 1> Single-byte array containing {0x02}
 */
constexpr std::array<uint8_t, 1> GetPrefix()
{
    return {0x02};
}

/**
 * @brief Generates a Yggdrasil IPv6 address from an Ed25519 public key.
 * 
 * This function implements the Yggdrasil addressing scheme which transforms
 * a cryptographic public key into a unique IPv6 address. The algorithm:
 * 1. Inverts all bits of the public key
 * 2. Counts leading ones in the inverted bitstream
 * 3. Encodes the count and remaining bits into an IPv6 address
 * 
 * @param public_key The Ed25519 public key to convert
 * @return IPv6_Addr The generated Yggdrasil IPv6 address 
 */
inline IPv6_Addr AddrForKey(const PublicKey_t& public_key)
{
    // Invert all bytes in the public key
    std::array<uint8_t, PublicKey_t::Size> inverted{};
    for (size_t i = 0; i < PublicKey_t::Size; ++i) {
        inverted[i] = ~public_key.bytes[i];
    }

    IPv6_Addr addr{};
    std::vector<uint8_t> temp;
    temp.reserve(PublicKey_t::Size);

    bool done = false;  // Flag to indicate we've passed the leading ones
    uint8_t ones = 0;   // Count of consecutive leading 1-bits
    uint8_t bits = 0;   // Accumulator for current byte being built
    int n_bits = 0;     // Number of bits accumulated in current byte

    // Process each bit of the inverted key
    for (int idx = 0; idx < 8 * static_cast<int>(inverted.size()); ++idx) {
        // Extract the current bit (idx/8 = byte index, idx%8 = bit position)
        // 0x80 >> (idx%8) creates a mask for the bit, 7-(idx%8) shifts it to LSB
        const uint8_t bit =
            (inverted[idx / 8] & (0x80 >> (idx % 8))) >> (7 - (idx % 8));

        // Count leading ones
        if (!done and (bit != 0)) {
            ++ones;
            continue;
        }

        // Found first zero, switch to collecting bits
        if (!done and (bit == 0)) {
            done = true;
            assert((ones <= 127) and "ones count exceeds 127");
            continue;
        }

        // Collect bits after the first zero
        bits = (bits << 1) | bit;
        ++n_bits;

        // When we have 8 bits, store the completed byte
        if (n_bits == 8) {
            n_bits = 0;
            temp.push_back(bits);
            bits = 0;
        }
    }

    // Construct the IPv6 address
    const auto prefix = GetPrefix();

    // Copy the fixed prefix (0x02) to the beginning of the address
    std::ranges::copy(prefix, addr.bytes.begin());

    // Store the leading ones count in the next byte
    addr.bytes[prefix.size()] = ones;

    // Calculate how much space remains in the address (16 total bytes)
    const size_t remaining_space = addr.size() - prefix.size() - 1;  // 14

    // Copy collected bits, but don't overflow the address
    const size_t copy_size = std::min(temp.size(), remaining_space);
    std::copy_n(temp.begin(), copy_size,
                addr.bytes.begin() + prefix.size() + 1);

    return addr;
}

}  // namespace yggdrasil_cpp_genkeys