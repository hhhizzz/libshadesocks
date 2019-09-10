#include <gtest/gtest.h>
#include "ss_server.h"
#include "ss_encrypt.h"

TEST(ServerTest, startServer) {
  shadesocks::Server server;
}
TEST(LoopTest, defaultLoop) {
  auto def = shadesocks::Loop::getDefault();

  ASSERT_TRUE(static_cast<bool>(def));
  ASSERT_FALSE(def->alive());
  ASSERT_NO_THROW(def->stop());

  auto def2 = shadesocks::Loop::getDefault();
  ASSERT_EQ(def, def2);
}

int main(int argc, char** argv) {
  FLAGS_colorlogtostderr = 1;
  FLAGS_stderrthreshold = 0;
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}