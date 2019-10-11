cmake_minimum_required(VERSION 3.0)

project(shadesocks CXX)
set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall -DNDEBUG -g2 -O2")

set(LINK_LIBRARIES)

FIND_PATH(LIBUV_INCLUDE_DIR NAMES uv.h)
FIND_LIBRARY(LIBUV_LIBRARIES NAMES uv libuv)
if (LIBUV_LIBRARIES)
    message("Found LibUV")
    list(APPEND LINK_LIBRARIES ${LIBUV_LIBRARIES})
else ()
    message("could not found LibUV -- So add LibUV from lib/")
    add_subdirectory("lib/libuv")
    include_directories("lib/libuv/include")
    list(APPEND LINK_LIBRARIES uv_a)
endif ()


find_package(GTest)
if (${GTEST_FOUND})
    message("Found GTest")
    find_package(GTest REQUIRED)
    list(APPEND LINK_LIBRARIES ${GTEST_BOTH_LIBRARIES})
else ()
    message("-- So add the GTest from lib/")
    add_subdirectory("lib/googletest")
    list(APPEND LINK_LIBRARIES gtest)
endif ()

find_package(glog 0.4.0)
if (${glog_FOUND})
    message("Found glog")
    find_package(glog 0.4.0 REQUIRED)
else ()
    message("-- So add the glog from lib/")
    add_subdirectory("lib/glog")
endif ()
list(APPEND LINK_LIBRARIES glog::glog)

add_subdirectory("lib/cryptopp_cmake")
list(APPEND LINK_LIBRARIES cryptopp-static)

link_libraries(${LINK_LIBRARIES})
enable_testing()

add_executable(ss_test test/ss_handle_test.cc)
add_executable(ss_encrypt_test test/ss_encrypt_test.cc)
add_executable(ss_server_test test/ss_server_test.cc)
add_executable(ss_connection_test test/ss_connection_test.cc)

add_test(NAME ss_test COMMAND ss_test)
add_test(NAME ss_encrypt_test COMMAND ss_encrypt_test)
add_test(NAME ss_server_test COMMAND ss_server_test)
add_test(NAME ss_connection_test COMMAND ss_connection_test)

