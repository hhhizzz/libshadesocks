#include <gtest/gtest.h>
#include "ss.h"

TEST(FooTest, HandleNoneZeroInput) {
  EXPECT_EQ(2, Foo(4, 10));
  EXPECT_EQ(6, Foo(30, 18));
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}