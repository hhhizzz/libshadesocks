cmake_minimum_required(VERSION 2.6)

project(shadesocks CXX)

add_definitions(-std=c++17)
set(CMAKE_CXX_FLAGS "-g -O2")

add_subdirectory("lib/googletest")

find_package(gtest)
find_package(glog 0.4.0 REQUIRED)

link_libraries(gtest glog::glog)

enable_testing()

add_executable(ss_test src/ss_test.cc src/ss.cc)
add_test(NAME ss_test COMMAND ss_test)

