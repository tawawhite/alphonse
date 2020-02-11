macro(set_build_type)
    if(NOT CMAKE_CONFIGURATION_TYPES)
        set(allowableBuileTypes DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
        set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "${allowableBuileTypes}")
        if(NOT CMAKE_BUILD_TYPE)
            set(CMAKE_BUILD_TYPE RELWITHDEBINFO CACHE STRING "" FORCE)
        else()
            string(TOUPPER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE)
            if(NOT CMAKE_BUILD_TYPE IN_LIST allowableBuileTypes)
                message(FATEL_ERROR "Invalid build type: ${CMAKE_BUILD_TYPE}")
            endif()
        endif()
    endif()
endmacro(set_build_type)

macro(set_default_configuration)
    set_build_type()
    set(OFFLINE_ENVIRONMENT ON CACHE BOOL "")
    include(GNUInstallDirs)
    if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
        set(CMAKE_INSTALL_PREFIX "${CMAKE_CURRENT_SOURCE_DIR}/dist" CACHE PATH "parsers/plugins install location" FORCE)
    endif()
    include(GNUInstallDirs)
endmacro(set_default_configuration)

macro(print_configuration)
    message(STATUS "")
    message(STATUS "")
    message(STATUS "Project configure summary:")
    message(STATUS "")
    message(STATUS "  CMake build type .................: ${CMAKE_BUILD_TYPE}")
    message(STATUS "  Install prefix ...................: ${CMAKE_INSTALL_PREFIX}")
    message(STATUS "  OFFLINE_ENVIRONMENT ..............: ${OFFLINE_ENVIRONMENT}")
    message(STATUS "")
endmacro(print_configuration)

set_default_configuration()
print_configuration()
