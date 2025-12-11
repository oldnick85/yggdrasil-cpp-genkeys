#pragma once

#include <print>

#include "common.h"
#include "thread_safe_queue.h"
#include "worker.h"

namespace yggdrasil_cpp_genkeys
{

/**
 * @brief Manages multiple Worker threads for parallel cryptographic key generation.
 * 
 * This class coordinates a pool of Worker threads that generate Ed25519 key pairs
 * and collectively search for "better" keys based on a custom comparison metric.
 * It handles thread lifecycle, result aggregation, and periodic best key updates.
 */
class WorkerManager
{
   public:
    /**
     * @brief Constructs a WorkerManager with specified runtime settings.
     * 
     * @param settings Configuration parameters including thread count and duration limits.
     */
    explicit WorkerManager(const Settings& settings) : settings_(settings) {}

    /**
     * @brief Main execution loop that runs workers and manages key evaluation.
     * 
     * This method:
     * 1. Starts all worker threads
     * 2. Periodically polls workers for their best keys
     * 3. Updates global best key when a better one is found
     * 4. Stops automatically when duration limit is reached
     * 5. Handles graceful thread termination
     */
    void Run()
    {
        RunWorkers();

        int count = 0;
        start_time_ = std::chrono::steady_clock::now();

        constexpr auto SYNC_PERIOD = std::chrono::milliseconds(100);

        // Main coordination loop
        while (not stop_) {
            ++count;
            std::this_thread::sleep_for(SYNC_PERIOD);

            bool new_best = false;
            auto best = queue_.try_pop_front();
            if (best.has_value()) {
                if ((*best).IsBetter(global_best_, settings_.ipv6_nice)) {
                    global_best_ = *best;
                    new_best = true;
                }
            }

            if (new_best) {
                PrintBest();
            }

            // Check duration limit if specified
            if (settings_.max_duration != 0) {
                const auto now = std::chrono::steady_clock::now();
                const auto elapsed = static_cast<uint64_t>(
                    duration_cast<std::chrono::duration<double>>(now -
                                                                 start_time_)
                        .count());
                if (elapsed > settings_.max_duration) {
                    Stop();
                }
            }

            // Check target leading zeros is reached
            if (settings_.target_leading_zeros != 0) {
                if (global_best_.zero_bits >= settings_.target_leading_zeros) {
                    Stop();
                }
            }
        }

        StopWorkers();
    }

    /**
     * @brief Signals the manager to stop processing.
     * 
     * Sets the stop flag which will cause the main loop to exit.
     * This can be called from another thread or from within the loop
     * (e.g., when duration limit is reached).
     */
    void Stop() { stop_ = true; }

   private:
    using WorkerPtr = std::unique_ptr<Worker>;

    Settings settings_;                  ///< runtime configuration parameters
    std::vector<WorkerPtr> workers_;     ///< managed worker instances
    std::vector<std::jthread> threads_;  ///< thread handles for workers
    Candidate global_best_;              ///< current global best
    std::atomic<bool> stop_ = false;     ///< flag to signal termination
    std::chrono::steady_clock::time_point start_time_;  ///< start time
    ThreadSafeQueue<Candidate> queue_;  ///< queue for best candidates

    /**
     * @brief Creates and starts worker threads.
     * 
     * Instantiates the specified number of Worker objects and launches
     * their process() methods in separate threads using std::jthread.
     */
    void RunWorkers()
    {
        for (size_t i = 0; i < settings_.threads_count; ++i) {
            workers_.push_back(std::make_unique<Worker>(settings_, i, &queue_));
        }

        for (auto& worker : workers_) {
            threads_.emplace_back(
                std::bind_front(&Worker::Process, worker.get()));
        }
    }

    /**
     * @brief Stops all worker threads gracefully.
     * 
     * Requests stop on all worker threads and waits briefly for them to finish.
     * Uses cooperative interruption via std::stop_token.
     */
    void StopWorkers()
    {
        for (auto& thread : threads_) {
            thread.request_stop();
        }

        constexpr auto WAIT_FOR_STOP = std::chrono::milliseconds(500);

        std::this_thread::sleep_for(WAIT_FOR_STOP);
    }

    /**
     * @brief Prints the current global best key and performance statistics.
     * 
     * Displays:
     * - Elapsed time and total keys generated
     * - Generation rate (keys per second)
     * - Best secret key in hex format
     * - Best public key in hex format
     * - Derived IP address for the key (if applicable)
     */
    void PrintBest()
    {
        uint64_t generated_keys_count = 0;

        for (auto& worker : workers_) {
            generated_keys_count += worker->GetGeneratedKeysCount();
        }

        const auto now = std::chrono::steady_clock::now();
        const auto duration =
            duration_cast<std::chrono::duration<double>>(now - start_time_);
        const auto elapsed = static_cast<uint64_t>(duration.count());
        if (elapsed > 0) {
            const auto rate = generated_keys_count / elapsed;
            std::println("----- {} --- {} keys tried",
                         format_duration_go_style(duration),
                         generated_keys_count);
            if (settings_.verbose) {
                std::println("----- generation speed {} keys per second", rate);
            }
        }

        std::println("Priv: {}", global_best_.keys.secret_key.ToHex());
        std::println("Pub: {}", global_best_.keys.public_key.ToHex());
        std::println("IP: {}",
                     AddrForKey(global_best_.keys.public_key).ToString());
    }
};

}  // namespace yggdrasil_cpp_genkeys