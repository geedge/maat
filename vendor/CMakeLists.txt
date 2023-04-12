# CMakeFiles for 3rd vendor library
cmake_minimum_required(VERSION 3.5)
include(ExternalProject)

set(VENDOR_ROOT ${CMAKE_BINARY_DIR}/vendor)
set(VENDOR_BUILD ${CMAKE_BINARY_DIR}/vendor/vbuild)

set(CMAKE_C_FLAGS "-std=c99 -fPIC -Wall") 
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -Wall")

# GoogleTest
ExternalProject_Add(GoogleTest PREFIX GoogleTest
                    URL ${CMAKE_CURRENT_SOURCE_DIR}/googletest-release-1.8.0.tar.gz
                    URL_MD5 16877098823401d1bf2ed7891d7dce36
                    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${VENDOR_BUILD} -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE})

ExternalProject_Get_Property(GoogleTest INSTALL_DIR)
file(MAKE_DIRECTORY ${VENDOR_BUILD}/include)

add_library(gtest_static STATIC IMPORTED GLOBAL)
set_property(TARGET gtest_static PROPERTY IMPORTED_LOCATION ${VENDOR_BUILD}/lib/libgtest.a)
set_property(TARGET gtest_static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${VENDOR_BUILD}/include)
set_property(TARGET gtest_static PROPERTY INTERFACE_LINK_LIBRARIES pthread)

# colm-0.13.0.5
ExternalProject_Add(colm PREFIX colm 
                    URL ${CMAKE_CURRENT_SOURCE_DIR}/colm-0.13.0.5.tar.gz
	                CONFIGURE_COMMAND ./autogen.sh && ./configure --prefix=${VENDOR_BUILD}
	                BUILD_COMMAND make	
	                INSTALL_COMMAND make install
	                BUILD_IN_SOURCE 1)

# ragel-7.0.0.10
ExternalProject_Add(ragel PREFIX ragel
                    URL ${CMAKE_CURRENT_SOURCE_DIR}/ragel-7.0.0.10.tar.gz
	                CONFIGURE_COMMAND ./autogen.sh && ./configure --prefix=${VENDOR_BUILD} --with-colm=${VENDOR_BUILD}
	                DEPENDS colm
	                BUILD_COMMAND make	
	                INSTALL_COMMAND make install
	                BUILD_IN_SOURCE 1)

# HyperScan 5.4.0
ExternalProject_Add(hyperscan PREFIX hyperscan
                    URL ${CMAKE_CURRENT_SOURCE_DIR}/hyperscan-5.4.0.tar.gz
	                DEPENDS ragel
	                CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${VENDOR_BUILD} -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC")

ExternalProject_Get_Property(hyperscan INSTALL_DIR)
file(MAKE_DIRECTORY ${VENDOR_BUILD}/include)

add_library(hyperscan_static STATIC IMPORTED GLOBAL)
add_dependencies(hyperscan_static hyperscan)
set_property(TARGET hyperscan_static PROPERTY IMPORTED_LOCATION ${VENDOR_BUILD}/lib64/libhs.a)
set_property(TARGET hyperscan_static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${VENDOR_BUILD}/include)

add_library(hyperscan_runtime_static STATIC IMPORTED GLOBAL)
add_dependencies(hyperscan_runtime_static hyperscan)
set_property(TARGET hyperscan_runtime_static PROPERTY IMPORTED_LOCATION ${VENDOR_BUILD}/lib64/libhs_runtime.a)
set_property(TARGET hyperscan_runtime_static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${VENDOR_BUILD}/include)

# hiredis-1.1.0
ExternalProject_Add(hiredis PREFIX hiredis
                    URL ${CMAKE_CURRENT_SOURCE_DIR}/hiredis-1.1.0.tar.gz
		            CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${VENDOR_BUILD} -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_C_FLAGS="-fPIC")

ExternalProject_Get_Property(hiredis INSTALL_DIR)
file(MAKE_DIRECTORY ${VENDOR_BUILD}/include)

add_library(hiredis-static STATIC IMPORTED GLOBAL)
add_dependencies(hiredis-static hiredis)

set_property(TARGET hiredis-static  PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${VENDOR_BUILD}/include)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
set_property(TARGET hiredis-static  PROPERTY IMPORTED_LOCATION ${VENDOR_BUILD}/lib64/libhiredisd.a)
else()
set_property(TARGET hiredis-static  PROPERTY IMPORTED_LOCATION ${VENDOR_BUILD}/lib64/libhiredis.a)
endif()

#igraph-0.7.1
ExternalProject_Add(igraph PREFIX igraph
                    URL ${CMAKE_CURRENT_SOURCE_DIR}/igraph-0.7.1.tar.gz
                    URL_MD5 4f6e7c16b45fce8ed423516a9786e4e8
                    CONFIGURE_COMMAND ./configure --prefix=${VENDOR_BUILD} --disable-shared --with-pic
                    BUILD_COMMAND make
                    INSTALL_COMMAND make install
                    BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(igraph INSTALL_DIR)
file(MAKE_DIRECTORY ${VENDOR_BUILD}/include)

add_library(igraph-static STATIC IMPORTED GLOBAL)
add_dependencies(igraph-static igraph)
set_property(TARGET igraph-static PROPERTY IMPORTED_LOCATION ${VENDOR_BUILD}/lib/libigraph.a)
set_property(TARGET igraph-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${VENDOR_BUILD}/include)