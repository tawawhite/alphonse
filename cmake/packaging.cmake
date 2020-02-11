install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/install/lib/libllhttp.so
    ${CMAKE_CURRENT_BINARY_DIR}/install/lib/libllhttp.so.2
    ${CMAKE_CURRENT_BINARY_DIR}/install/lib/libllhttp.so.2.0.1
    ${CMAKE_CURRENT_BINARY_DIR}/install/lib/libpcap.so
    ${CMAKE_CURRENT_BINARY_DIR}/install/lib/libpcap.so.1
    ${CMAKE_CURRENT_BINARY_DIR}/install/lib/libpcap.so.1.9.1
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
