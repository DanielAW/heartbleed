project(heartbleed)
cmake_minimum_required(VERSION 2.8)
aux_source_directory(. SRC_LIST)

SET(CMAKE_CXX_FLAGS "-std=c++11")


################ FIND BOTAN ######################
SET(PC_BOTAN_INCLUDEDIR "/opt/hearbleed/include/botan-1.11")

FIND_PATH(BOTAN_INCLUDE_DIR botan/botan.h
   HINTS
   ${PC_BOTAN_INCLUDEDIR}
)

SET(PC_BOTAN_LIBDIR "/opt/hearbleed/lib")

FIND_LIBRARY(BOTAN_LIBRARY NAMES botan-1.11
   HINTS
   ${PC_BOTAN_LIBDIR}
)
################ / FIND BOTAN ######################

include_directories(${BOTAN_INCLUDE_DIR})
add_executable(heartbleed ${SRC_LIST})
target_link_libraries(heartbleed ${BOTAN_LIBRARY})
