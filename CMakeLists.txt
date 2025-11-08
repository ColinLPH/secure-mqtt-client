cmake_minimum_required(VERSION 3.10)
project(smqtt-client C)

set(CMAKE_C_STANDARD 11)

# Find libsodium
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

include_directories(${SODIUM_INCLUDE_DIRS})
link_directories(${SODIUM_LIBRARY_DIRS})

# Add the client executable, now pointing to src/main.c
add_executable(smqtt-client src/main.c)

# Link libsodium
target_link_libraries(smqtt-client ${SODIUM_LIBRARIES})
