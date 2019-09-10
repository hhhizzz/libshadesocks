#ifndef SS_SERVER_H__
#define SS_SERVER_H__
#include <uv.h>
#include <glog/logging.h>
#include <memory>
#include <vector>
#include <iostream>
#include "ss_encrypt.h"

namespace shadesocks {

class Loop final {
 private:
  using Deleter = void (*)(uv_loop_t*);
  explicit Loop(std::unique_ptr<uv_loop_t, Deleter> ptr) noexcept
      : loop{std::move(ptr)} {}

  std::unique_ptr<uv_loop_t, Deleter> loop;

 public:
  /**
   * Gets the initialized default loop.
   */
  static std::shared_ptr<Loop> getDefault();

  void close();

  bool run(uv_run_mode mode = UV_RUN_DEFAULT) noexcept;

  void stop() noexcept;

  bool alive() const noexcept;

  ~Loop() noexcept {
    if (this->loop) {
      close();
    }
  }
};

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