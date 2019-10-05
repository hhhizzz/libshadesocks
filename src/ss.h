#include <exception>
#include <string>
#include <uv.h>
#include <gtest/gtest.h>
#include "ss_encrypt.h"

#ifndef SS_H__
#define SS_H__

namespace shadesocks {
class UvException : public std::runtime_error {
 public:
  explicit UvException(int err) : std::runtime_error(uv_strerror(err)) {}
  explicit UvException(const std::string& what) : std::runtime_error(what) {}
};

class ShadeHandle final {
 private:
  std::unique_ptr<uv_tcp_t> p_handle_in;
  std::unique_ptr<uv_tcp_t> p_handle_out;

  std::unique_ptr<Cipher> cipher;

  uv_stream_t* p_server;

 public:
  ShadeHandle(uv_stream_t* server, std::string method = "aes-256-cfb") {
    this->p_handle_in = std::make_unique<uv_tcp_t>();
    this->p_handle_out = std::make_unique<uv_tcp_t>();
    uv_tcp_init(server->loop, this->p_handle_in.get());
    uv_tcp_init(server->loop, this->p_handle_out.get());

    this->p_server = server;
    this->cipher = Util::getEncryption(method);
  }

  ~ShadeHandle() {
    DLOG(INFO) << "ShadeHandle has been deleted";
  }

  void accept() {
    int err = uv_accept(p_server, this->handle_in<uv_stream_t>());
    if (err) {
      throw UvException(err);
    }
    this->p_handle_in->data = this;

    uv_alloc_cb alloc_cp = [](uv_handle_t* handle,
                              size_t suggested_size,
                              uv_buf_t* buf) {
      buf->base = (char*) malloc(suggested_size);
      buf->len = suggested_size;
    };

    uv_read_cb read_cp = [](uv_stream_t* stream,
                            ssize_t nread,
                            const uv_buf_t* buf) {
      DLOG(INFO) << "start to read buffer, nread is: " << nread;
      if (nread > 0) {
        SecByteBlock bytes((byte*) buf->base, nread);

        DLOG(INFO) << "Got data: " << shadesocks::Util::HexToString(bytes);
      } else if (nread < 0) {
        if (nread != UV_EOF) {
          LOG(ERROR) << "Read error: " << uv_err_name(nread);
        }
      } else {
        LOG(INFO) << "data is empty";
      }

      delete buf->base;
      uv_close((uv_handle_t*) stream, [](uv_handle_t* handle) {
        DLOG(INFO) << "uv close handle";
        delete (ShadeHandle*) handle->data;
      });
    };
    uv_read_start(this->handle_in<uv_stream_t>(), alloc_cp, read_cp);
  }

  template<typename U>
  U* handle_in() {
    return reinterpret_cast<U*>(this->p_handle_in.get());
  }
};

}
#endif