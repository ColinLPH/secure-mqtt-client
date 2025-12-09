cmake_minimum_required(VERSION 3.10)
project(smqtt-client C)

set(CMAKE_C_STANDARD 11)

# Find libsodium using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Include directories for libsodium
include_directories(${SODIUM_INCLUDE_DIRS})

# Add the client executable, now pointing to src/main.c
add_executable(smqtt-client src/main.c)

# Link libsodium with the client executable
target_link_libraries(smqtt-client ${SODIUM_LIBRARIES})

# Link the necessary libraries for libsodium
target_link_libraries(smqtt-client ${SODIUM_LIBRARIES})

# If you're encountering linking issues with shared libs, add the following:
target_link_libraries(smqtt-client -L${SODIUM_LIBRARY_DIRS} -lsodium)
