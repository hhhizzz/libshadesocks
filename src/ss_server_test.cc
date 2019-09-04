#include <gtest/gtest.h>
#include "ss_server.h"
#include <cstring>
#include "ss_encrypt.h"


TEST(ServerTest, startServer) {
  shadesocks::Server server;
  server.start();
}

int main(int argc, char **argv) {
  FLAGS_colorlogtostderr = 1;
  FLAGS_stderrthreshold = 0;
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}