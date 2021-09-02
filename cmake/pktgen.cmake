if(OFFLINE_ENVIRONMENT)
    set(pktgen_url ${CMAKE_CURRENT_SOURCE_DIR}/third_party/pktgen-20.11.3.tar.gz)
else()
    set(pktgen_url https://github.com/pktgen/Pktgen-DPDK/archive/refs/tags/pktgen-20.11.3.tar.gz)
endif()

message(STATUS "${CMAKE_CURRENT_BINARY_DIR}/install/include/dpdk")
ExternalProject_Add(pktgen
    URL ${pktgen_url}
    URL_MD5 bd06338849a533d2cb8dc666ac9c82f3
    EXCLUDE_FROM_ALL ON
    PREFIX pktgen
    INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env 
        LIBRARY_PATH=${CMAKE_CURRENT_BINARY_DIR}/install/lib:${CMAKE_CURRENT_BINARY_DIR}/install/lib64
        C_INCLUDE_PATH=${CMAKE_CURRENT_BINARY_DIR}/install/include
        PKG_CONFIG_PATH=${CMAKE_CURRENT_BINARY_DIR}/install/lib/pkgconfig:${CMAKE_CURRENT_BINARY_DIR}/install/lib64/pkgconfig
        meson setup --prefix=<INSTALL_DIR> <BINARY_DIR> <SOURCE_DIR>
    BUILD_COMMAND ${CMAKE_COMMAND} -E env
        LIBRARY_PATH=${CMAKE_CURRENT_BINARY_DIR}/install/lib:${CMAKE_CURRENT_BINARY_DIR}/install/lib64
        C_INCLUDE_PATH=${CMAKE_CURRENT_BINARY_DIR}/install/include:${CMAKE_CURRENT_BINARY_DIR}/install/include/dpdk
        meson compile
    INSTALL_COMMAND meson install
)
