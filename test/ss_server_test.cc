#include <gtest/gtest.h>
#include "../src/ss_server.h"
#include "../src/ss_encrypt.h"
#include "../src/ss.h"

void handle_signal(int signal) {
  LOG(INFO) << "stop the server";
  auto loop = shadesocks::Loop::getDefault();
  loop->stop();
  exit(0);
}

TEST(TCPHandler, startServer) {
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  auto loop = shadesocks::Loop::getDefault();

  auto tcp = loop->create_tcp_handle();
  try {
    tcp->bind("0.0.0.0", 1081);
    tcp->listen();
    loop->run();
  } catch (shadesocks::UvException& uvException) {
    LOG(ERROR) << uvException.what();
  }
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