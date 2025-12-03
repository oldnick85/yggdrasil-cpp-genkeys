#pragma once

#include "bytes.h"

namespace yggdrasil_cpp_genkeys
{

/**
 * @brief Represents an IPv6 address with 128 bits (16 bytes) of data.
 * 
 * This class extends BaseKey_t<16U> to provide IPv6-specific functionality,
 * particularly for converting the binary representation to a standard IPv6
 * colon-hexadecimal string format (e.g., "2001:0db8:85a3:0000:0000:8a2e:0370:7334").
 * 
 * The IPv6 address is stored as 16 consecutive bytes in network byte order (big-endian).
 */
class IPv6_Addr : public BaseKey_t<16U>
{
   public:
    /**
     * @brief Converts the internal byte representation to a standard IPv6 string.
     * 
     * The method splits the 16-byte array into 8 groups of 2 bytes (16 bits) each,
     * converts each group to a hexadecimal value, and formats them with colons.
     * 
     * @return std::string IPv6 address in standard format
     * 
     * @note Leading zeros in each 16-bit group are omitted (standard IPv6 representation).
     * @note This method does not implement IPv6 compression (replacing consecutive
     *       zero groups with "::") - it always outputs all 8 groups.
     */
    std::string ToString() const
    {
        std::array<uint16_t, 8> groups{};
        for (size_t i = 0; i < 8; ++i) {
            groups[i] = (bytes[2 * i] << 8) | bytes[2 * i + 1];
        }

        return std::format("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}", groups[0],
                           groups[1], groups[2], groups[3], groups[4],
                           groups[5], groups[6], groups[7]);
    }
};

}  // namespace yggdrasil_cpp_genkeys