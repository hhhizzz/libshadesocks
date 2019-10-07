#ifndef SS_SERVER_H__
#define SS_SERVER_H__
#include <uv.h>
#include <glog/logging.h>
#include <memory>
#include <utility>
#include <vector>
#include <iostream>
#include "ss.h"
#include "ss_encrypt.h"

namespace shadesocks {

class Loop;

class TCPHandle {
  friend class Loop;

 private:
  uv_tcp_t resource;

  std::string hostname;
  int port;

  explicit TCPHandle() : resource() {}

 public:
  void bind(const std::string hostname = "0.0.0.0", const int port = 1080, unsigned int flags = 0) {
    sockaddr_in addr{};
    uv_ip4_addr(hostname.c_str(), port, &addr);

    this->hostname = hostname;
    this->port = port;

    int err = uv_tcp_bind(&resource, (const struct sockaddr*) &addr, std::forward<unsigned int>(flags));
    if (err != 0) {
      throw UvException(err);
    }
    LOG(INFO) << "bind hostname: " << hostname << ", port: " << port;
  }

  void listen(int backlog = 128) {
    uv_connection_cb on_connection = [](uv_stream_t* server, int status) {
      if (status < 0) {
        throw UvException(status);
      }
      auto shade_handle = new ShadeHandle(server);
      shade_handle->Accept(server);
    };

    int err = uv_listen(reinterpret_cast<uv_stream_t*>(&this->resource), backlog, on_connection);
    if (err) {
      throw UvException(err);
    }
    LOG(INFO) << "start to listen on: " + hostname + ", port: " << port;
  }

};

class Loop final : public std::enable_shared_from_this<Loop> {
 private:
  using Deleter = void (*)(uv_loop_t*);
  Loop(std::unique_ptr<uv_loop_t, Deleter> ptr) noexcept
      : loop{std::move(ptr)} {}

  std::unique_ptr<uv_loop_t, Deleter> loop;

 public:
  /**
   * Gets the initialized default loop.
   */
  static std::shared_ptr<Loop> getDefault() {
    static std::weak_ptr<Loop> ref;
    std::shared_ptr<Loop> loop;

    if (ref.expired()) {
      LOG(INFO) << "create default loop";
      auto default_loop = uv_default_loop();

      if (default_loop) {
        Deleter do_nothing = [](uv_loop_t*) {};
        auto ptr = std::unique_ptr<uv_loop_t, Deleter>(default_loop, do_nothing);
        loop = std::shared_ptr<Loop>(new Loop{std::move(ptr)});
      }
      ref = loop;

    } else {
      loop = ref.lock();
    }
    return loop;
  }

  uv_loop_t* get() {
    return this->loop.get();
  }

  void close() {
    auto err = uv_loop_close(loop.get());
    if (err) {
      throw UvException(err);
    }
  }

  void run(uv_run_mode mode = UV_RUN_DEFAULT) noexcept {
    int err = uv_run(loop.get(), mode);
    if (err != 0) {
      LOG(ERROR) << uv_strerror(err);
    }
  }

  void stop() noexcept {
    LOG(INFO) << "stop the loop";
    uv_stop(loop.get());
  }

  bool alive() const noexcept {
    return uv_loop_alive(loop.get()) != 0;
  }

  std::shared_ptr<TCPHandle> create_tcp_handle() {
    if (this->loop == nullptr) {
      throw UvException("cannot create handle without loop");
    }

    auto handle_ptr = std::shared_ptr<TCPHandle>(new TCPHandle{});
    uv_tcp_init(this->get(), &handle_ptr->resource);

    return handle_ptr;
  }

  ~Loop() noexcept {
    if (this->loop) {
      try {
        close();
      } catch (UvException& uv_exception) {
        LOG(ERROR) << uv_exception.what();
      }
    }
    LOG(INFO) << "loop closed";
  }
};

}  // namespace shadesocks
#endif