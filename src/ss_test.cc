#include <gtest/gtest.h>
#include <glog/logging.h>
#include "ss.h"

TEST(FooTest, HandleNoneZeroInput) {
  LOG(ERROR)<<"start to test";
  EXPECT_EQ(2, Foo(4, 10));
  EXPECT_EQ(6, Foo(30, 18));
}

int main(int argc, char **argv) {
  google::InitGoogleLogging(argv[0]);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}