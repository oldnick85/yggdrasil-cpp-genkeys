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
    size_t threads_count = 0;   ///< threads for parallel key generation.
    uint64_t max_duration = 0;  ///< execution time in seconds
    bool verbose = false;       ///< verbose output mode
    bool ipv6_nice = false;     ///< search nice-looking address
};

inline std::string add_fraction(uint64_t fraction, int precision)
{
    if (fraction == 0) {
        return "";
    }

    std::string frac_str;
    while (precision > 0 && fraction > 0) {
        auto digit = fraction % 10;
        if (!frac_str.empty() || digit != 0) {
            frac_str.insert(0, std::to_string(digit));
        }
        fraction /= 10;
        --precision;
    }

    if (frac_str.empty()) {
        return "";
    }
    return "." + frac_str;
};

template <typename Rep, typename Period>
std::string format_duration_go_style(
    const std::chrono::duration<Rep, Period>& duration)
{
    using std::chrono::duration_cast;
    using std::chrono::nanoseconds;

    const auto nsec = duration_cast<nanoseconds>(duration);
    const auto total_ns = nsec.count();

    if (total_ns == 0) {
        return "0s";
    }

    const bool negative = total_ns < 0;
    auto abs_ns = static_cast<uint64_t>(std::llabs(total_ns));

    constexpr uint64_t sec_per_min = 60;
    constexpr uint64_t ns_per_sec = 1'000'000'000ULL;
    constexpr uint64_t ns_per_min = sec_per_min * ns_per_sec;
    constexpr uint64_t ns_per_hour = sec_per_min * ns_per_min;
    constexpr int us_precision = 3;
    constexpr int ms_precision = 3;
    constexpr int sec_precision = 9;

    std::string result;

    if (negative) {
        result += "-";
    }

    if (abs_ns < 1000) {
        result = std::format("{}{}ns", negative ? "-" : "", abs_ns);
    }
    else if (abs_ns < 1'000'000) {
        const uint64_t usec = abs_ns / 1000;
        const uint64_t fraction = abs_ns % 1000;
        result = std::format("{}{}{}µs", negative ? "-" : "", usec,
                             add_fraction(fraction, us_precision));
    }
    else if (abs_ns < 1'000'000'000) {
        const uint64_t msec = abs_ns / 1'000'000;
        const uint64_t fraction = (abs_ns % 1'000'000) / 1000;
        result = std::format("{}{}{}ms", negative ? "-" : "", msec,
                             add_fraction(fraction, ms_precision));
    }
    else if (abs_ns < sec_per_min * ns_per_sec) {
        const uint64_t sec = abs_ns / ns_per_sec;
        const uint64_t fraction = abs_ns % ns_per_sec;
        result = std::format("{}{}{}s", negative ? "-" : "", sec,
                             add_fraction(fraction, sec_precision));
    }
    else {
        std::string parts;

        if (abs_ns >= ns_per_hour) {
            const uint64_t hour = abs_ns / ns_per_hour;
            parts += std::format("{}h", hour);
            abs_ns %= ns_per_hour;
        }

        if (abs_ns >= ns_per_min) {
            const uint64_t minute = abs_ns / ns_per_min;
            parts += std::format("{}m", minute);
            abs_ns %= ns_per_min;
        }

        if (abs_ns >= ns_per_sec || parts.empty()) {
            const uint64_t sec = abs_ns / ns_per_sec;
            const uint64_t fraction = abs_ns % ns_per_sec;
            parts += std::format("{}{}s", sec,
                                 add_fraction(fraction, sec_precision));
        }

        result = (negative ? "-" : "") + parts;
    }

    return result;
}

}  // namespace yggdrasil_cpp_genkeys