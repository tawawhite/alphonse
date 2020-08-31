if(OFFLINE_ENVIRONMENT)
    set(llhttp_url ${CMAKE_CURRENT_SOURCE_DIR}/third_party/llhttp-2.1.1.tar.gz)
else()
    set(llhttp_url https://github.com/JackLiar/llhttp-cmake/releases/download/v2.1.1/llhttp-2.1.1.tar.gz)
endif()

ExternalProject_Add(llhttp
    URL ${llhttp_url}
    EXCLUDE_FROM_ALL ON
    PREFIX llhttp
    INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install
    CMAKE_ARGS  -D CMAKE_BUILD_TYPE=Release
                -D CMAKE_INSTALL_PREFIX=<INSTALL_DIR>
                -D BUILD_SHARED_LIBS=ON
                -D CMAKE_POSITION_INDEPENDENT_CODE=ON
)
