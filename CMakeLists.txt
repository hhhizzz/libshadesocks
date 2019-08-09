cmake_minimum_required(VERSION 3.0)

project(shadesocks CXX)
set (CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-g -O2")

find_package(GTest)
if (${GTEST_FOUND})
  message("Found GTest")
  find_package(GTest REQUIRED)
else()
  message("-- So add the GTest from lib/")
  add_subdirectory("lib/googletest")
endif()

find_package(glog 0.4.0)
if (${glog_FOUND})
  message("Found glog")
  find_package(glog 0.4.0 REQUIRED)
else()
  message("-- So add the glog from lib/")
  add_subdirectory("lib/glog")
endif()

link_libraries(${GTEST_BOTH_LIBRARIES} gtest glog::glog)

enable_testing()

add_executable(ss_test src/ss_test.cc src/ss.cc)
add_test(NAME ss_test COMMAND ss_test)

