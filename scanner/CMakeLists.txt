add_definitions(-D_GNU_SOURCE) 
add_definitions(-fPIC)

include_directories(${PROJECT_SOURCE_DIR}/deps)
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/src/inc_internal)

add_library(adapter-static adapter_hs.cpp bool_matcher.cpp fqdn_engine.cpp)
target_link_libraries(adapter-static hyperscan_static hyperscan_runtime_static ipmatcher-static)