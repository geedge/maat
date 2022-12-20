cmake_minimum_required (VERSION 3.5)
set(lib_name maatframe)
project (maatframe)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(Version)

SET(CMAKE_INSTALL_PREFIX /opt/MESA/)

LINK_DIRECTORIES(/opt/MESA/lib /usr/lib64)

set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -Wall)
set(MAAT_DEPEND_DYN_LIB pcre rulescan pthread m pcre crypto z zlog)
include_directories(${PROJECT_SOURCE_DIR}/inc/)
include_directories(/opt/MESA/include/)

#for ASAN
set(ASAN_OPTION "OFF" CACHE STRING " set asan type chosen by the user, using OFF as default")
set_property(CACHE ASAN_OPTION  PROPERTY STRINGS OFF ADDRESS THREAD)
message(STATUS "ASAN_OPTION='${ASAN_OPTION}'")

if(ASAN_OPTION MATCHES "ADDRESS")
    set(CMAKE_C_FLAGS "${CMAKADDRESS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
elseif(ASAN_OPTION MATCHES "THREAD")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
endif()
# end of for ASAN

enable_testing()

add_subdirectory (vendor)
add_subdirectory (src) 
add_subdirectory (test)
add_subdirectory (tools)

include(Package)
