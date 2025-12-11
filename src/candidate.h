#pragma once

#include "ed25519_keys.h"
#include "ipv6_addr.h"

namespace yggdrasil_cpp_genkeys
{

struct Candidate
{
    Keys_t keys{};
    IPv6_Addr addr{};
    uint zero_bits = 0;
    uint ipv6_zero_blocks = 0;

    [[nodiscard]] bool IsBetter(const Candidate& other, bool ipv6_nice) const
    {
        if (ipv6_nice) {
            if ((ipv6_zero_blocks > other.ipv6_zero_blocks) or
                ((ipv6_zero_blocks == other.ipv6_zero_blocks) and
                 (zero_bits > other.zero_bits))) {
                return true;
            }
        }
        else if (zero_bits > other.zero_bits) {
            return true;
        }
        return false;
    }
};

}  // namespace yggdrasil_cpp_genkeys