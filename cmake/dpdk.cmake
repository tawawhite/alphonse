if(OFFLINE_ENVIRONMENT)
    set(dpdk_url ${CMAKE_CURRENT_SOURCE_DIR}/third_party/dpdk-19.11.tar.xz)
else()
    set(dpdk_url http://fast.dpdk.org/rel/dpdk-19.11.tar.xz)
endif()

ExternalProject_Add(dpdk
    URL ${dpdk_url}
    EXCLUDE_FROM_ALL ON
    PREFIX dpdk
    INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env 
        PATH=${CMAKE_CURRENT_BINARY_DIR}/install/bin:$ENV{PATH}
        LIBRARY_PATH=${CMAKE_CURRENT_BINARY_DIR}/install/lib:${CMAKE_CURRENT_BINARY_DIR}/install/lib64
        C_INCLUDE_PATH=${CMAKE_CURRENT_BINARY_DIR}/install/include
        PKG_CONFIG_PATH=${CMAKE_CURRENT_BINARY_DIR}/install/lib/pkgconfig
        meson  -Dprefix=<INSTALL_DIR> --includedir=${CMAKE_INSTALL_INCLUDEDIR}/dpdk <BINARY_DIR> <SOURCE_DIR>
    BUILD_COMMAND ${CMAKE_COMMAND} -E env
        LIBRARY_PATH=${CMAKE_CURRENT_BINARY_DIR}/install/lib:${CMAKE_CURRENT_BINARY_DIR}/install/lib64
        C_INCLUDE_PATH=${CMAKE_CURRENT_BINARY_DIR}/install/include
        ninja
    # BUILD_COMMAND echo
    INSTALL_COMMAND ninja install
    # INSTALL_COMMAND echo
)
