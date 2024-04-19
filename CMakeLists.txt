cmake_minimum_required(VERSION 3.10)

# Set your project name
project(cail)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Boost with required components
find_package(Boost 1.70 REQUIRED COMPONENTS system thread coroutine context)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add executable
add_executable(cail src/main.cpp)

# Include Boost and OpenSSL headers
target_include_directories(cail PRIVATE ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

# Link libraries
target_link_libraries(cail
    PRIVATE
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)
