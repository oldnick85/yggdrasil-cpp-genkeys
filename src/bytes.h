#pragma once

#include <span>
#include <string>

namespace yggdrasil_cpp_genkeys
{

/**
 * @brief Converts bytes to hexadecimal string
 * @param bytes Span of bytes to convert
 * @return std::string hex string or error
 */
static inline std::string BytesToHex(std::span<const uint8_t> bytes)
{
    constexpr uint8_t MASK = 0x0F;
    std::string hex;
    hex.reserve(bytes.size() * 2);

    for (const uint8_t byte : bytes) {
        constexpr std::array<char, 16> hex_chars = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        hex.push_back(hex_chars[byte >> 4]);
        hex.push_back(hex_chars[byte & MASK]);
    }

    return hex;
}

template <size_t SIZE>
static inline std::array<uint8_t, SIZE> HexToBytes(std::string_view hex)
{
    std::array<uint8_t, SIZE> bytes{};

    for (size_t i = 0; i < SIZE; ++i) {
        if (2 * i + 1 < hex.length()) {
            const auto char_hi = hex[2 * i];
            const auto char_lo = hex[(2 * i) + 1];
            const uint8_t byte_hi =
                (char_hi >= 'a') ? char_hi - 'a' + 10 : char_hi - '0';
            const uint8_t byte_lo =
                (char_lo >= 'a') ? char_lo - 'a' + 10 : char_lo - '0';
            bytes[i] = byte_hi * 16 + byte_lo;
        }
        else {
            bytes[i] = 0;
        }
    }

    return bytes;
}

template <size_t SIZE>
class BaseKey_t
{
   public:
    static constexpr std::size_t Size = SIZE;
    std::array<uint8_t, Size> bytes;

    uint8_t* data() { return bytes.data(); }
    [[nodiscard]] std::size_t size() const { return bytes.size(); }
    [[nodiscard]] std::string ToHex() const { return BytesToHex(bytes); }
    void FromHex(std::string_view hex) { bytes = HexToBytes<Size>(hex); }
};

}  // namespace yggdrasil_cpp_genkeys