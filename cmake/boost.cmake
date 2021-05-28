if(OFFLINE_ENVIRONMENT)
    set(boost_url ${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost_1_76_0.tar.bz2)
else()
    set(boost_url https://boostorg.jfrog.io/artifactory/main/release/1.76.0/source/boost_1_76_0.tar.bz2)
endif()

ExternalProject_Add(boost
    URL ${boost_url}
    URL_MD5 33334dd7f862e8ac9fe1cc7c6584fb6d
    EXCLUDE_FROM_ALL ON
    PREFIX boost
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
)