add_definitions(-D_GNU_SOURCE) 
add_definitions(-fPIC)

add_library(interval_index_static ACEI.cpp CEI.cpp DirectIndex.cpp FastIntervalIndex.cpp 
	    Int128IntervalIndex.cpp IntervalIndex.cpp IntervalTree.cpp IPMaskIndex.cpp 
	    NaiveIntervalIndex.cpp NaiveIntervalIndex2.cpp PortIndex.cpp SuccinctHash.cpp
	    sigmastar_tools.cpp)
