cmake_minimum_required(VERSION 3.0)

project(shadesocks CXX)
set (CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-DNDEBUG -g2 -O2")

set(LINK_LIBRARIES)

FIND_PATH(LIBUV_INCLUDE_DIR NAMES uv.h)
FIND_LIBRARY(LIBUV_LIBRARIES NAMES uv libuv)
if (LIBUV_LIBRARIES)
  message("Found LibUV")
  list(APPEND LINK_LIBRARIES ${LIBUV_LIBRARIES})
else()
  message("could not found libuv")
  include_directories("lib/libuv/include")
  add_subdirectory("lib/libuv")
endif()


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

add_executable(ss_test src/ss_test.cc src/ss.cc)
add_executable(ss_encrypt_test src/ss_encrypt_test.cc src/ss_encrypt.cc)
add_executable(ss_server_test src/ss_server_test.cc src/ss_server.cc)

add_test(NAME ss_test COMMAND ss_test)
add_test(NAME ss_encrypt_test COMMAND ss_encrypt_test)
add_test(NAME ss_server_test COMMAND ss_server_test)

