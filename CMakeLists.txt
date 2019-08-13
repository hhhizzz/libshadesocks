cmake_minimum_required(VERSION 3.0)

project(shadesocks CXX)
set (CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-DNDEBUG -g2 -O2")

add_subdirectory("lib/cryptopp")

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
if (DEFINED GTEST_BOTH_LIBRARIES)
  link_libraries(${GTEST_BOTH_LIBRARIES} glog::glog cryptopp-static)
else()
  link_libraries(gtest glog::glog cryptopp-static)
endif()
enable_testing()

# include_directories(lib/cryptopp)
# set(CRYPTOPP_LIST lib/cryptopp/cryptlib.cpp lib/cryptopp/cpu.cpp lib/cryptopp/integer.cpp lib/cryptopp/osrng.cpp)

add_executable(ss_test src/ss_test.cc src/ss.cc ${CRYPTOPP_LIST})
add_test(NAME ss_test COMMAND ss_test)

