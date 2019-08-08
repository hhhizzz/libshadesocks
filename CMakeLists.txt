cmake_minimum_required(VERSION 2.6)

project(shadesocks CXX)

add_definitions(-std=c++17)
set(CMAKE_CXX_FLAGS "-g -O2")

add_subdirectory("lib/googletest")
add_subdirectory("lib/gflags")

link_libraries(gtest gflags)

enable_testing()

add_executable(ss_test src/ss_test.cc src/ss.cc)
add_test(NAME ss_test COMMAND ss_test)

