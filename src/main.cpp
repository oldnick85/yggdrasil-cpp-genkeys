#include <csignal>
#include <memory>
#include <print>
#include <sstream>
#include <thread>

#include <clipp.h>  // clipp for command-line parsing

#include "common.h"
#include "version.h"  // Generated version header
#include "worker_manager.h"

using yggdrasil_cpp_genkeys::Settings;
using yggdrasil_cpp_genkeys::WorkerManager;

namespace
{

/// Global pointer to WorkerManager for signal handler access
std::unique_ptr<WorkerManager> g_manager;

/**
 * @brief Signal handler for graceful shutdown on SIGINT (Ctrl+C).
 * 
 * When SIGINT is received, this handler signals the WorkerManager
 * to stop processing and initiate graceful shutdown of all worker threads.
 * 
 * @param signal The signal number (should be SIGINT = 2)
 */
void signal_handler(int signal)
{
    if ((signal == SIGINT) and (g_manager != nullptr)) {
        g_manager->Stop();
    }
}

}  // namespace

/**
 * @brief Main entry point for the Yggdrasil cryptographic key generator.
 * 
 * This program generates Ed25519 key pairs in parallel to find "better" keys
 * according to a custom metric. It supports multi-threading, duration limits,
 * and various search criteria for IPv6 address generation.
 * 
 * @param argc argument count
 * @param argv argument vector
 * @return exit code (0 on success, 1 on parsing error)
 */
int main(int argc, char* argv[])
{
    // Register signal handler for Ctrl+C (SIGINT) for graceful shutdown
    [[maybe_unused]] auto sighandler = std::signal(SIGINT, signal_handler);

    bool help = false;

    Settings settings;  ///< Application configuration settings

    auto cli =
        (clipp::option("-t", "--threads") &
             clipp::integer("N", settings.threads_count)
                 .doc("Number of worker threads (default: 0 - CPU-defined)"),
         clipp::option("-T", "--timeout") &
             clipp::integer("SEC", settings.max_duration)
                 .doc("Maximum execution time in seconds (default: 0 - no "
                      "limit)"),
         clipp::option("-v", "--verbose")
             .set(settings.verbose)
             .doc("Enable verbose output with additional statistics"),
         clipp::option("--ipv6-nice")
             .set(settings.ipv6_nice)
             .doc("Search for zero blocks in IPv6 address"),
         clipp::option("-h", "--help").set(help).doc("Show this help message"));

    if (!clipp::parse(argc, argv, cli) || help) {
        auto man_page = clipp::make_man_page(cli, argv[0]);
        std::ostringstream oss;
        oss << man_page;
        std::println("{}\n\n{}", yggdrasil_cpp_genkeys::get_version_string(),
                     oss.str());
        return help ? 0 : 1;
    }

    // Set thread count to hardware concurrency if not specified
    if (settings.threads_count == 0) {
        settings.threads_count = std::thread::hardware_concurrency();
    }

    std::println("Threads: {}", settings.threads_count);

    // Create and initialize the worker manager
    g_manager = std::make_unique<WorkerManager>(settings);

    // Run the main processing loop (blocks until completion or signal)
    g_manager->Run();

    return 0;
}