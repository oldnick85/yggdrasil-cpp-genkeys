#pragma once

#include <chrono>

namespace yggdrasil_cpp_genkeys
{

/**
 * @brief Configuration settings for the Yggdrasil cryptographic key generator.
 * 
 */
struct Settings
{
    size_t threads_count = 0;  ///< threads for parallel key generation.
    size_t max_duration = 0;   ///< execution time in seconds
    bool verbose = false;      ///< verbose output mode
    bool ipv6_nice = false;    ///< search nice-looking address
};

template <typename Rep, typename Period>
std::string format_duration_go_style(
    const std::chrono::duration<Rep, Period>& duration)
{
    using namespace std::chrono;

    const auto ns = duration_cast<nanoseconds>(duration);
    const auto total_ns = ns.count();

    if (total_ns == 0) {
        return "0s";
    }

    const bool negative = total_ns < 0;
    auto abs_ns = static_cast<uint64_t>(std::llabs(total_ns));

    constexpr uint64_t ns_per_sec = 1'000'000'000ULL;
    constexpr uint64_t ns_per_min = 60 * ns_per_sec;
    constexpr uint64_t ns_per_hour = 60 * ns_per_min;

    std::string result;

    auto add_fraction = [](uint64_t fraction, int precision) -> std::string
    {
        if (fraction == 0)
            return "";

        std::string frac_str;
        while (precision > 0 && fraction > 0) {
            auto digit = fraction % 10;
            if (!frac_str.empty() || digit != 0) {
                frac_str = std::to_string(digit) + frac_str;
            }
            fraction /= 10;
            --precision;
        }

        if (frac_str.empty())
            return "";
        return "." + frac_str;
    };

    if (negative) {
        result += "-";
    }

    if (abs_ns < 1000) {
        result = std::format("{}{}ns", negative ? "-" : "", abs_ns);
    }
    else if (abs_ns < 1'000'000) {
        uint64_t us = abs_ns / 1000;
        uint64_t fraction = abs_ns % 1000;
        result = std::format("{}{}{}µs", negative ? "-" : "", us,
                             add_fraction(fraction, 3));
    }
    else if (abs_ns < 1'000'000'000) {
        uint64_t ms = abs_ns / 1'000'000;
        uint64_t fraction = (abs_ns % 1'000'000) / 1000;
        result = std::format("{}{}{}ms", negative ? "-" : "", ms,
                             add_fraction(fraction, 3));
    }
    else if (abs_ns < 60 * ns_per_sec) {
        uint64_t s = abs_ns / ns_per_sec;
        uint64_t fraction = abs_ns % ns_per_sec;
        result = std::format("{}{}{}s", negative ? "-" : "", s,
                             add_fraction(fraction, 9));
    }
    else {
        std::string parts;

        if (abs_ns >= ns_per_hour) {
            uint64_t h = abs_ns / ns_per_hour;
            parts += std::format("{}h", h);
            abs_ns %= ns_per_hour;
        }

        if (abs_ns >= ns_per_min) {
            uint64_t m = abs_ns / ns_per_min;
            parts += std::format("{}m", m);
            abs_ns %= ns_per_min;
        }

        if (abs_ns >= ns_per_sec || parts.empty()) {
            uint64_t s = abs_ns / ns_per_sec;
            uint64_t fraction = abs_ns % ns_per_sec;
            parts += std::format("{}{}s", s, add_fraction(fraction, 9));
        }

        result = (negative ? "-" : "") + parts;
    }

    return result;
}

}  // namespace yggdrasil_cpp_genkeys