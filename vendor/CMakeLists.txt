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

# hiredis-1.0.2
ExternalProject_Add(hiredis PREFIX hiredis	
        URL ${CMAKE_CURRENT_SOURCE_DIR}/hiredis-1.0.2.tar.gz
        CONFIGURE_COMMAND ""
        BUILD_COMMAND make
        INSTALL_COMMAND ""
        BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(hiredis SOURCE_DIR)
set(HIREDIS_INCLUDE_DIRECTORIES ${SOURCE_DIR})
file(MAKE_DIRECTORY ${HIREDIS_INCLUDE_DIRECTORIES})

add_library(hiredis-static STATIC IMPORTED GLOBAL)
set_property(TARGET hiredis-static PROPERTY IMPORTED_LOCATION ${SOURCE_DIR}/libhiredis.a)
set_property(TARGET hiredis-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${SOURCE_DIR})

#igraph-0.7.1
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

#ipmatcher-1.1
ExternalProject_Add(ipmatcher PREFIX ipmatcher
        URL ${CMAKE_CURRENT_SOURCE_DIR}/ipmatcher-v1.1.zip
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

#FieldStat2
ExternalProject_Add(FieldStat2 PREFIX FieldStat2
        URL ${CMAKE_CURRENT_SOURCE_DIR}/FieldStat2-master.zip
		CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE})

ExternalProject_Get_Property(FieldStat2 INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(fieldstat2-static STATIC IMPORTED GLOBAL)
add_dependencies(fieldstat2-static FieldStat2)
set_property(TARGET fieldstat2-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libMESA_field_stat2.a)
set_property(TARGET fieldstat2-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

# mesa_handle_logger
ExternalProject_Add(MESA_handle_logger PREFIX MESA_handle_logger
        URL ${CMAKE_CURRENT_SOURCE_DIR}/MESA_handle_logger-dev-2.0.zip
		CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_C_FLAGS="-fPIC")

ExternalProject_Get_Property(MESA_handle_logger INSTALL_DIR)
message(" MESA_handle_logger CMAKE_BINARY_DIR: ${CMAKE_BINARY_DIR}")
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(mesalogger-static STATIC IMPORTED GLOBAL)
add_dependencies(mesalogger-static MESA_handle_logger)
set_property(TARGET mesalogger-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/src/MESA_handle_logger-build/libMESA_handle_logger.a)
set_property(TARGET mesalogger-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

# mesa_htable
ExternalProject_Add(MESA_htable PREFIX MESA_htable
        URL ${CMAKE_CURRENT_SOURCE_DIR}/MESA_htable-master.zip
		CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_C_FLAGS="-fPIC")

ExternalProject_Get_Property(MESA_htable INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(mesahtable-static STATIC IMPORTED GLOBAL)
add_dependencies(mesahtable-static MESA_htable)
set_property(TARGET mesahtable-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/src/MESA_htable-build/libMESA_htable.a)
set_property(TARGET mesahtable-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)