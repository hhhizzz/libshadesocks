#include <gtest/gtest.h>
#include <glog/logging.h>
#include "../src/ss.h"
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

  shade_handle.proxy_state = ProxyState::ClientReading;
  ShadeHandle::ReadClientDone(stream, 158, &buf);

  delete stream;
}

TEST(ShadeHandleTest, GetRequestTest) {
  auto* stream = new uv_stream_t{};
  stream->loop = uv_default_loop();
  ShadeHandle shade_handle(stream);

  LOG(INFO) << "start to check domain";
  auto block = Util::StringToHex(
      "031D636F6E6E6563746976697479636865636B2E677374617469632E636F6D005048454144202F67656E65726174655F32303420485454502F312E310D0A486F73743A20636F6E6E6563746976697479636865636B2E677374617469632E636F6D0D0A557365722D4167656E743A20537572676520546573742F312E300D0A4163636570743A202A2F2A0D0A0D0A");
  shade_handle.data = block;

  char hostname[NI_MAXHOST];
  shade_handle.GetRequest();
  auto addr = std::move(shade_handle.addr_out);
  inet_ntop(addr->sin_family, &addr->sin_addr, hostname, NI_MAXHOST);
  auto port = ntohs(addr->sin_port);

  LOG(INFO) << "ip is: " << hostname;
  LOG(INFO) << "hostname is: " << shade_handle.hostname_out;
  LOG(INFO) << "port is: " << port;
  ASSERT_EQ(port, 80);
  ASSERT_STRCASEEQ(shade_handle.hostname_out.data(), "connectivitycheck.gstatic.com");

  LOG(INFO) << "start to check IPv4";
  block = Util::StringToHex(
      "01CBD02B580050");
  shade_handle.data = block;

  shade_handle.GetRequest();
  addr = std::move(shade_handle.addr_out);
  inet_ntop(addr->sin_family, &addr->sin_addr, hostname, NI_MAXHOST);
  port = ntohs(addr->sin_port);

  LOG(INFO) << "ip is: " << hostname;
  LOG(INFO) << "hostname is: " << shade_handle.hostname_out;
  LOG(INFO) << "port is: " << port;
  ASSERT_EQ(port, 80);
  ASSERT_STRCASEEQ(hostname, "203.208.43.88");
  ASSERT_STRCASEEQ(shade_handle.hostname_out.data(), "203.208.43.88");

  delete stream;
}

}

int main(int argc, char** argv) {
  FLAGS_colorlogtostderr = 1;
  FLAGS_stderrthreshold = 0;
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}