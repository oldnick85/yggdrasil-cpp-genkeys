#!/bin/bash
set -e

# Parse command line arguments
ACTION=${1:-"build"}
BUILD_TYPE=${2:-"Release"}
BUILD_DIR=${3:-"build-linux"}

echo "Action: $ACTION, Build type: $BUILD_TYPE, Build directory: $BUILD_DIR"

case $ACTION in
    "build")
        echo "Building project for Linux (Ubuntu 25.10)..."

        conan profile detect

        cd /workspace

        # Create build directory and navigate to it
        mkdir -p $BUILD_DIR
        
        # Install Conan dependencies
        conan install . \
            --build=missing \
            --output-folder=$BUILD_DIR \
            -s compiler=gcc \
            -s compiler.version=15 \
            -s compiler.libcxx=libstdc++11 \
            -s build_type=$BUILD_TYPE \
            -s compiler.cppstd=23        

        cd $BUILD_DIR
        
        # Configure CMake project
        cmake .. \
            -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
            -DCMAKE_CXX_STANDARD=23 \
            -DCMAKE_CXX_STANDARD_REQUIRED=ON \
            -DCMAKE_CXX_EXTENSIONS=OFF \
            -DCMAKE_CXX_COMPILER=g++-15 \
            -DCMAKE_C_COMPILER=gcc-15
        
        # Build the project
        cmake --build . --config $BUILD_TYPE
        
        # Copy executables to bin directory
        #mkdir -p ../bin/linux
        #find . -name "*.exe" -o -name "yggdrasil*" -type f -executable -exec cp {} ../bin/linux/ \;
        ;;
    
    "test")
        echo "Running unit tests for Linux..."

        cd /workspace
        cd $BUILD_DIR
        
        # Run tests with CTest
        ctest --output-on-failure -C $BUILD_TYPE -V
        ;;
    
    "format")
        echo "Checking code formatting with clang-format..."
        
        # Check formatting without making changes
        find src test -name "*.cpp" -o -name "*.hpp" -o -name "*.h" | \
            xargs clang-format-20 --dry-run --Werror --style=file
        
        echo "✅ All files are properly formatted!"
        ;;
    
    "tidy")
        echo "Running static analysis with clang-tidy..."
        
        # Generate compile_commands.json
        cd /workspace

        cmake -B $BUILD_DIR -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_CXX_CLANG_TIDY="clang-tidy;--header-filter=.*"

        find src -name "*.cpp" | xargs clang-tidy -p $BUILD_DIR --config-file=.clang-tidy
        find test -name "*.cpp" | xargs clang-tidy -p $BUILD_DIR --config-file=.clang-tidy

        #cmake .. -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
        
        # Run clang-tidy on all source files
        #find ../src ../test -name "*.cpp" | \
        #    xargs -I {} clang-tidy-20 {} \
        #    -p $BUILD_DIR \
        #    --config-file=../.clang-tidy \
        #    --extra-arg=-std=c++23
        
        echo "✅ Static analysis completed successfully!"
        ;;
    
    "all")
        echo "Running full CI pipeline..."
        /usr/local/bin/entrypoint.sh format
        /usr/local/bin/entrypoint.sh build $BUILD_TYPE $BUILD_DIR
        /usr/local/bin/entrypoint.sh tidy
        /usr/local/bin/entrypoint.sh test $BUILD_TYPE $BUILD_DIR
        ;;
    
    *)
        echo "Available actions: build, test, format, tidy, all"
        echo "Usage: entrypoint.sh [action] [build_type] [build_dir]"
        exit 1
        ;;
esac