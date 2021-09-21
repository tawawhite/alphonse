if(OFFLINE_ENVIRONMENT)
    set(boost_url ${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost_1_77_0.tar.bz2)
else()
    set(boost_url https://boostorg.jfrog.io/artifactory/main/release/1.77.0/source/boost_1_77_0.tar.bz2)
endif()

ExternalProject_Add(boost
    URL ${boost_url}
    URL_MD5 09dc857466718f27237144c6f2432d86
    EXCLUDE_FROM_ALL ON
    PREFIX boost
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
)