#include <gtest/gtest.h>
#include <glog/logging.h>
#include "ss.h"
namespace shadesocks {
TEST(ShadeHandleTest, ReadDataTest) {

  auto* stream = new uv_stream_t{};
  stream->loop = uv_default_loop();
  ShadeHandle shade_handle(stream);
  stream->data = &shade_handle;

  auto block = Util::StringToHex(
      "7396C95A33DFFA3042FF661FF0B85155268EF14E148EBFD1638AF66436717BC2ECF34B8044259EB5A5D5B2A0A47F9F5DFA6F242600C589034C2153C47C8E681BE67EA51796FFA7055D7636634222D7AD6417EF7250F1EAD171CFBEDBC2D474206DCA0A83A0446FFFBEB8262773073DF5D89C0A2A462C6F4A50EBB23FEC308AC64387CD7CE6066908512277E5E573C762171F631B375CAF0C59315F15E867");

  uv_buf_t buf;
  ShadeHandle::AllocBuffer(reinterpret_cast<uv_handle_t*>(stream), 158, &buf);
  for (int i = 0; i < 158; i++) {
    buf.base[i] = block.data()[i];
  }

  ShadeHandle::ReadData(stream, 158, &buf);

}
}

int main(int argc, char** argv) {
  FLAGS_colorlogtostderr = 1;
  FLAGS_stderrthreshold = 0;
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}