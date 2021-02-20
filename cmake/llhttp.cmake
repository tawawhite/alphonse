if(OFFLINE_ENVIRONMENT)
    set(llhttp_url ${CMAKE_CURRENT_SOURCE_DIR}/third_party/llhttp-4.0.0.tar.gz)
else()
    set(llhttp_url https://github.com/JackLiar/llhttp-cmake/releases/download/v4.0.0/llhttp-4.0.0.tar.gz)
endif()

ExternalProject_Add(llhttp
    URL ${llhttp_url}
    URL_MD5 5112291f095e698aa4f90f13edcf734d
    EXCLUDE_FROM_ALL ON
    PREFIX llhttp
    INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install
    CMAKE_ARGS  -D CMAKE_BUILD_TYPE=Release
                -D CMAKE_INSTALL_PREFIX=<INSTALL_DIR>
                -D BUILD_SHARED_LIBS=ON
                -D CMAKE_POSITION_INDEPENDENT_CODE=ON
)
