if(OFFLINE_ENVIRONMENT)
    set(libpcap_url ${CMAKE_CURRENT_SOURCE_DIR}/third_party/libpcap-1.9.1.tar.gz)
else()
    set(libpcap_url https://github.com/the-tcpdump-group/libpcap/archive/libpcap-1.9.1.tar.gz)
endif()

ExternalProject_Add(libpcap
    URL ${libpcap_url}
    URL_MD5 9feb4d1ccc5ea8c8b3e1558aa0c2be6f
    EXCLUDE_FROM_ALL ON
    PREFIX libpcap
    INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install
    CMAKE_ARGS  -D CMAKE_BUILD_TYPE=Release
                -D CMAKE_INSTALL_PREFIX=<INSTALL_DIR>
                -D BUILD_SHARED_LIBS=ON
                -D DISABLE_DAG=ON
                -D DISABLE_SNF=ON
                -D DISABLE_TC=ON
                -D CMAKE_POSITION_INDEPENDENT_CODE=ON
    INSTALL_COMMAND make install
    COMMAND ${CMAKE_COMMAND} -E copy <INSTALL_DIR>/lib/pkgconfig/libpcap.pc <INSTALL_DIR>/lib/pkgconfig/pcap.pc
)

# apt-get install flex byacc