# CMakeFiles for 3rd vendor library

include(ExternalProject)
#### GoogleTest
ExternalProject_Add(GoogleTest PREFIX GoogleTest
        URL ${CMAKE_CURRENT_SOURCE_DIR}/googletest-release-1.8.0.tar.gz
        URL_MD5 16877098823401d1bf2ed7891d7dce36
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE})

ExternalProject_Get_Property(GoogleTest INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(gtest STATIC IMPORTED GLOBAL)
set_property(TARGET gtest PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libgtest.a)
set_property(TARGET gtest PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set_property(TARGET gtest PROPERTY INTERFACE_LINK_LIBRARIES pthread)

ExternalProject_Add(hiredis-vip PREFIX hiredis-vip
        URL ${CMAKE_CURRENT_SOURCE_DIR}/hiredis-vip-0.3.0.tar.gz
        URL_MD5 e4d4a2928188b11f696d35ca1c52e9a4
        CONFIGURE_COMMAND ""
        BUILD_COMMAND make
        INSTALL_COMMAND ""
        BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(hiredis-vip SOURCE_DIR)
set(HIREDIS_INCLUDE_DIRECTORIES ${SOURCE_DIR})
file(MAKE_DIRECTORY ${HIREDIS_INCLUDE_DIRECTORIES})

add_library(hiredis-vip-static STATIC IMPORTED GLOBAL)
set_property(TARGET hiredis-vip-static PROPERTY IMPORTED_LOCATION ${SOURCE_DIR}/libhiredis_vip.a)
set_property(TARGET hiredis-vip-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${SOURCE_DIR})

ExternalProject_Add(igraph PREFIX igraph
        URL ${CMAKE_CURRENT_SOURCE_DIR}/igraph-0.7.1.tar.gz
        URL_MD5 4f6e7c16b45fce8ed423516a9786e4e8
        CONFIGURE_COMMAND ./configure --prefix=<INSTALL_DIR> --disable-shared --with-pic
        BUILD_COMMAND make
        INSTALL_COMMAND make install
        BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(igraph INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(igraph-static STATIC IMPORTED GLOBAL)
add_dependencies(igraph-static igraph)
set_property(TARGET igraph-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libigraph.a)
set_property(TARGET igraph-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

ExternalProject_Add(ipmatcher PREFIX ipmatcher
        URL ${CMAKE_CURRENT_SOURCE_DIR}/IPMatcher-20200503.zip
		CONFIGURE_COMMAND ""
        BUILD_COMMAND make
		INSTALL_COMMAND make DESTDIR=<INSTALL_DIR> install
        BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(ipmatcher INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(ipmatcher-static STATIC IMPORTED GLOBAL)
add_dependencies(ipmatcher-static ipmatcher)
set_property(TARGET ipmatcher-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/ipmatcher.a)
set_property(TARGET ipmatcher-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
