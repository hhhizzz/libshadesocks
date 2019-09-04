#ifndef SS_SERVER_H__
#define SS_SERVER_H__
#include <uv.h>
#include <glog/logging.h>
#include <memory>
#include <vector>
#include <iostream>
#include "ss_encrypt.h"

namespace shadesocks {
class Server {
 private:
  uv_tcp_t tcp_server;
  sockaddr_in address;

 public:
  struct write_req_t {
    uv_write_t req;
    uv_buf_t buf;
  };
  static uv_loop_t* loop;
  const static int DEFAULT_PORT = 1080;
  const static int DEFAULT_BACKLOG = 128;

  void start();
  Server();
  ~Server();
};
class ServerCallback {
 public:
  void static on_new_connection(uv_stream_t* server, int status);
  void static read_buffer(uv_stream_t* client, ssize_t nread,
                          const uv_buf_t* buf);
  void static alloc_buffer(uv_handle_t* handle, size_t suggested_size,
                           uv_buf_t* buf);
  void static after_write(uv_write_t* req, int status);
  void static on_close(uv_handle_t* handle) { delete handle; }
};
}  // namespace shadesocks
#endif