add_definitions(-D_GNU_SOURCE) 
add_definitions(-fPIC)

include_directories(${PROJECT_SOURCE_DIR}/deps)
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/src/inc_internal)

add_subdirectory(ip_matcher/IntervalIndex)

add_library(adapter-static adapter_hs/adapter_hs.cpp bool_matcher/bool_matcher.cpp 
            fqdn_engine/fqdn_engine.cpp ip_matcher/ip_matcher.cpp ip_matcher/ipv4_match.cpp 
            ip_matcher/ipv6_match.cpp flag_matcher/flag_matcher.cpp interval_matcher/cgranges.c
            interval_matcher/interval_matcher.cpp)
target_link_libraries(adapter-static hyperscan_static hyperscan_runtime_static interval_index_static)