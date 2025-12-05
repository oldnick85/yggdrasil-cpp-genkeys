/**
 * @file ed25519_keys_generator.h
 * @brief Header-only C++23 wrapper for Ed25519 key generation using libsodium
 * @author oldnick85
 * @date 2025
 */
#pragma once

#ifdef __cplusplus
extern "C"
{
#endif
#include <sodium.h>  // libsodium for cryptographic functions
#ifdef __cplusplus
}
#endif

#include <array>
#include <cassert>
#include <expected>
#include <format>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "ed25519_keys.h"

/**
 * @namespace yggdrasil_cpp_genkeys
 * @brief wrapper for Ed25519 key generation namespace
 */
namespace yggdrasil_cpp_genkeys
{

static_assert(PublicKey_t::Size == crypto_sign_ed25519_PUBLICKEYBYTES);
static_assert(SecretKey_t::Size == crypto_sign_ed25519_SECRETKEYBYTES);
static_assert(Seed_t::Size == crypto_sign_ed25519_SEEDBYTES);

class Ed25519_KeysGenerator
{
   private:
    Keys_t keys_{};             ///< keys storage
    bool initialized_ = false;  ///< Initialization flag

   public:
    Ed25519_KeysGenerator() { InitializeSodium(); }

    /**
     * @brief Destructor - securely cleans up sensitive data
     */
    ~Ed25519_KeysGenerator() { Cleanup(); }

    /**
     * @brief Generates key pair
     * 
     * @param crypto - use random seed for generating
     * 
     * @remark During the search process, we use a simple increment for 
     * the key generation seed, which speeds up the process. Since the seed 
     * was generated randomly at the very beginning, this is quite secure.
     */
    void Generate(bool crypto = false)
    {
        if (crypto) {
            GenerateRandomSeed();
        }
        else {
            ++keys_.seed;
        }
        Generate(keys_.seed);
    }

    void Generate(Seed_t& seed)
    {
        [[maybe_unused]] const auto result = crypto_sign_ed25519_seed_keypair(
            keys_.public_key.data(), keys_.secret_key.data(), seed.data());
        assert(result == 0);
    }

    void SetSeed(const Seed_t& seed) { keys_.seed = seed; }

    [[nodiscard]]
    const Keys_t& Keys() const
    {
        return keys_;
    }

   private:
    /**
     * @brief Generates a cryptographically secure random seed
     */
    void GenerateRandomSeed()
    {
        randombytes_buf(keys_.seed.bytes.data(), keys_.seed.bytes.size());
    }

    /**
     * @brief Initializes libsodium library
     * @return true if successful, false otherwise
     */
    static void InitializeSodium()
    {
        static std::once_flag init_flag;
        static int init_result;

        std::call_once(init_flag, []() { init_result = sodium_init(); });

        assert(init_result >= 0);
    }

    /**
     * @brief Securely cleans up sensitive data
     */
    void Cleanup() noexcept
    {
        sodium_memzero(keys_.secret_key.data(), keys_.secret_key.size());
        sodium_memzero(keys_.public_key.data(), keys_.public_key.size());
        sodium_memzero(keys_.seed.data(), keys_.seed.size());
    }
};

}  // namespace yggdrasil_cpp_genkeys