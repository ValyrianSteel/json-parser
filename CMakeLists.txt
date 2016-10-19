cmake_minimum_required (VERSION 2.6)
project (leptjson_test C)

if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ansi -std=c11 -pedantic -Wall")
endif()

add_library(leptjson leptjson.c)
add_executable(leptjson_test unit_test.c)
target_link_libraries(leptjson_test leptjson)
