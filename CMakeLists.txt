cmake_minimum_required(VERSION 3.0)

project(shadesocks CXX)
set (CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-g -O2")

add_subdirectory("lib/googletest")
add_subdirectory("lib/glog")
# find_package(glog 0.4.0 REQUIRED)

link_libraries(gtest glog::glog)

enable_testing()

add_executable(ss_test src/ss_test.cc src/ss.cc)
add_test(NAME ss_test COMMAND ss_test)

