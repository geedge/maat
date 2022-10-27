# CMakeFiles for 3rd vendor library

include(ExternalProject)

set(VENDOR_ROOT ${CMAKE_BINARY_DIR}/vendor)
set(VENDOR_BUILD ${CMAKE_BINARY_DIR}/vendor/vbuild)

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

execute_process(COMMAND ${CMAKE_COMMAND} -E tar xvf ${CMAKE_CURRENT_SOURCE_DIR}/boost_1_80_0.tar.gz
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/deps/)

# HyperScan 5.4.0
ExternalProject_Add(hyperscan PREFIX hyperscan
        URL ${CMAKE_CURRENT_SOURCE_DIR}/hyperscan-5.4.0.tar.gz
	    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${VENDOR_BUILD} -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DBOOST_ROOT=${PROJECT_SOURCE_DIR}/deps/boost_1_80_0 -DCMAKE_C_FLAGS="-fPIC")

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