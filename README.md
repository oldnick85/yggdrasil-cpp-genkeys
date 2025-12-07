# 🔑 YGGDRASIL-CPP-GENKEYS

A C++ port of the genkeys utility from the [yggdrasil-go](https://github.com/yggdrasil-network/yggdrasil-go) project, designed to generate cryptographic key pairs for the Yggdrasil networking protocol. 
This tool continuously searches for "better" key pairs based on specific criteria and outputs them when found.

## 📖 Overview

The original Go implementation generates cryptographic keys, printing a new set each time it finds a "better" one. By default, "better" means a higher NodeID (resulting in a higher IPv6 address). This optimization takes advantage of IPv6 address compression for leading 1s, increasing the number of usable ID bits in the address.

This C++ version maintains the same functionality while adding additional configuration options and performance optimizations.

## ✨ Features

 - Multi-threaded search: Leverages multiple CPU cores for faster key generation
 - Configurable search criteria:
   - Default: Higher NodeID (higher IPv6 address)
   - Optional: Search for zero blocks in IPv6 addresses
 - Flexible execution control:
   - Configurable timeout
   - Verbose output mode
   - Automatic thread count detection
 - Cross-platform: Built with standard C++23 and portable dependencies

## ⚠️ Security Warning: Key Independence

Important Security Notice: Keys generated within the same program execution run may be cryptographically linked due to shared random number generator state or similar initialization vectors.

 - ❌ Do NOT use multiple key pairs from the same program run
 - ✅ One key pair per run: use only one key pair from each program execution

## 🛠️ Building

### 📋 Prerequisites

 - CMake 3.15 or higher
 - C++23 compatible compiler
 - Conan package manager

### 📦 Dependencies

The project uses:

 - libsodium 1.0.20
 - clipp 1.2.3
 - gtest 1.17.0 (optional, for tests)

### 🔧 Using Conan

The project uses [Conan](https://conan.io/) for dependency management. 
Dependencies are specified in conanfile.txt and automatically handled by [CMake](https://cmake.org/) when using the provided toolchain.
Install Conan:
```bash
pip install conan
conan profile detect --force
```

### 🚀 Build Steps

1. Clone the repository:
```bash
git clone <repository-url>
cd yggdrasil-cpp-genkeys
```

2. Prepare dependencies:
```bash
conan install . --output-folder=build --build=missing
```

3. Navigate to a build directory:
```bash
cd build
```

4. Configure with CMake:
```bash
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
```

5. Build the project:
```bash
cmake --build .
```

The executable will be available at src/yggdrasil-cpp-genkeys.

## 🐋 Docker Compose Development Workflow

### 📋 Overview

This project uses Docker Compose to provide a consistent development environment for building, testing, and analyzing the C++ codebase. 
All development tasks can be performed through standardized Docker commands, ensuring consistent results across different machines.

**⚠️ Important Warning! Always execute commands from the project's root directory to ensure proper path resolution.**

### 🚀 Available Commands

🔨 Build the Project
```bash
docker compose -f scripts/docker/docker-compose.yml run --rm linux-build
```

🧪 Run Tests
```bash
docker compose -f scripts/docker/docker-compose.yml run --rm linux-test
```

🎨 Check Code Formatting
```bash
docker compose -f scripts/docker/docker-compose.yml run --rm linux-format
```

🔍 Static Code Analysis
```bash
docker compose -f scripts/docker/docker-compose.yml run --rm linux-tidy
```

## 🎮 Usage

### 🏁 Basic Usage

Run the program without arguments to start searching for keys with default settings:
```bash
./yggdrasil-cpp-genkeys
```

### ⚙️ Command Line Options

| Option            | Description                                                     |
|-------------------|-----------------------------------------------------------------|
| -t, --threads N   | Number of worker threads (default: 0 = CPU core count)          |
| -T, --timeout SEC | Maximum execution time in seconds (default: 0 = no limit)       |
| -v, --verbose     | Enable verbose output with additional statistics                |
| -n, --ipv6-nice   | Search for zero blocks in IPv6 address instead of higher NodeID |
| -h, --help        | Show help message                                               |

### 📝 Examples

1. Search with 8 threads and a 60-second timeout:
```bash
./yggdrasil-cpp-genkeys --threads 8 --timeout 60
```

2. Search for IPv6 addresses with verbose output:
```bash
./yggdrasil-cpp-genkeys -v
```

3. Run with automatic thread detection and no time limit:
```bash
./yggdrasil-cpp-genkeys --threads 0
```

## 🔬 How It Works

The tool generates Ed25519 key pairs using libsodium, compares public keys and selects keys with "higher" values.
Each time a "better" key pair is found according to the current criteria, it's printed to stdout.

## 🧪 Testing

Tests are optional and can be enabled with the BUILD_TESTS CMake option:
```bash
cmake .. -DBUILD_TESTS=ON
cmake --build .
ctest
```

## ⚡ Performance Considerations

 - The search process is CPU-intensive and scales with available cores
 - Memory usage is minimal as only the best-found keys are stored
 - Using the -z flag may significantly change search performance characteristics

## 📄 License

This project is licensed under the MIT license.

## 🙏 Acknowledgments

 - The original yggdrasil-go project and its contributors
 - libsodium for cryptographic primitives
 - clipp for command-line argument parsing
 - gtest for amazing testing instrument

## 🤝 Contributing

Contributions are welcome! Please ensure code follows C++23 standards and includes appropriate tests when applicable.