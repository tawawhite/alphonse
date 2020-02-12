cmake_minimum_required(VERSION 3.10.0)
project(alphonse VERSION 0.1.0)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(macros)
include(projects)
include(packaging)

add_custom_target(alphonse ALL
    # COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR} && cargo build
    COMMAND echo "All the dependencies of alphonse are built successfully!"
)

find_library(libpcap_LIBRARY pcap
    HINTS "${CMAKE_CURRENT_BINARY_DIR}/install/lib"
    PATHS /usr/lib/x86_64-linux-gnu/
)

set(BUILD_LIBPCAP ON CACHE BOOL "")
if(NOT libpcap_LIBRARY OR BUILD_LIBPCAP)
    add_dependencies(alphonse libpcap)
endif()

# Currently DPDK is only for Linux, FreeBSD and Windows
# We only target for Linux in current stage
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_dependencies(alphonse dpdk)
endif()

add_dependencies(alphonse llhttp)

message(STATUS "  OFFLINE_ENVIRONMENT ..............: ${OFFLINE_ENVIRONMENT}")
message(STATUS "  BUILD_LIBPCAP ....................: ${OFFLINE_ENVIRONMENT}")
message(STATUS "")
