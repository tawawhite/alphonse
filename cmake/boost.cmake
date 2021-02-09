if(OFFLINE_ENVIRONMENT)
    set(boost_url ${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost_1_73_0.tar.bz2)
else()
    set(boost_url https://dl.bintray.com/boostorg/release/1.73.0/source/boost_1_73_0.tar.bz2)
endif()

ExternalProject_Add(boost
    URL ${boost_url}
    URL_MD5 9273c8c4576423562bbe84574b07b2bd
    EXCLUDE_FROM_ALL ON
    PREFIX boost
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
)