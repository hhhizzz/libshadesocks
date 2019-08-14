cmake_minimum_required(VERSION 3.0)

project(shadesocks CXX)
set (CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-DNDEBUG -g2 -O2")

set(LINK_LIBRARIES)

find_package(GTest)
if (${GTEST_FOUND})
  message("Found GTest")
  find_package(GTest REQUIRED)
  list(APPEND LINK_LIBRARIES ${GTEST_BOTH_LIBRARIES})
else()
  message("-- So add the GTest from lib/")
  add_subdirectory("lib/googletest")
  list(APPEND LINK_LIBRARIES gtest)
endif()

find_package(glog 0.4.0)
if (${glog_FOUND})
  message("Found glog")
  find_package(glog 0.4.0 REQUIRED)
else()
  message("-- So add the glog from lib/")
  add_subdirectory("lib/glog")
endif()
list(APPEND LINK_LIBRARIES glog::glog)

add_subdirectory("lib/cryptopp_cmake")
list(APPEND LINK_LIBRARIES cryptopp-static)

link_libraries(${LINK_LIBRARIES})
enable_testing()

add_executable(ss_test src/ss_test.cc src/ss.cc ${CRYPTOPP_LIST})
add_test(NAME ss_test COMMAND ss_test)

