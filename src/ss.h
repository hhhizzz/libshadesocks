#include <exception>
#include <string>
#include <utility>
#include <uv.h>
#include <gtest/gtest_prod.h>
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
  FRIEND_TEST(ShadeHandleTest, ReadDataTest);

  std::unique_ptr<uv_tcp_t> p_handle_in;
  std::unique_ptr<uv_tcp_t> p_handle_out;

  std::unique_ptr<Cipher> cipher;
  std::string cipher_method;
  std::string password;

  uv_stream_t* p_server;

  static void ReadData(uv_stream_t* stream,
                       ssize_t nread,
                       const uv_buf_t* buf) {
    auto shade_handle = reinterpret_cast<ShadeHandle*>(stream->data);
    if (shade_handle == nullptr) {
      throw UvException("cannot read data from handle");
    }
    SecByteBlock data;
    DLOG(INFO) << "start to read buffer, nread is: " << nread;
    if (nread > 0) {
      SecByteBlock bytes((byte*) buf->base, nread);
      DLOG(INFO) << "Got data: " << shadesocks::Util::HexToString(bytes);

      if (shade_handle->cipher == nullptr) {
        auto cipher_info = cipher_map.at(shade_handle->cipher_method);
        auto iv = SecByteBlock((byte*) buf->base, cipher_info.iv_length);
        auto key = Util::PasswordToKey(shade_handle->password, cipher_info.key_length);
        shade_handle->cipher = Util::getEncryption(shade_handle->cipher_method, key, iv);
        DLOG(INFO) << "cipher created, method: " << shade_handle->cipher_method << ", key: " << Util::HexToString(key)
                   << ", iv: " << Util::HexToString(iv);

        SecByteBlock encrypt_data((byte*) buf->base + cipher_info.iv_length, nread - cipher_info.iv_length);
        data = shade_handle->cipher->decrypt(encrypt_data);
      } else {
        SecByteBlock encrypt_data((byte*) buf->base, nread);
        data = shade_handle->cipher->decrypt(encrypt_data);
      }
    } else if (nread < 0) {
      if (nread != UV_EOF) {
        LOG(ERROR) << "Read error: " << uv_err_name(nread);
      }
    } else {
      LOG(INFO) << "data is empty";
    }
    DLOG(INFO) << "encrypt data is: " << std::string((char*) data.data());

    delete[] buf->base;
//    uv_close(reinterpret_cast<uv_handle_t*>(stream), [](uv_handle_t* handle) {
//      DLOG(INFO) << "uv close handle";
//      delete (ShadeHandle*) handle->data;
//    });
  }

  static void AllocBuffer(uv_handle_t* handle,
                          size_t suggested_size,
                          uv_buf_t* buf) {
    buf->base = new char[suggested_size];
    buf->len = suggested_size;
  }

 public:
  explicit ShadeHandle(uv_stream_t* server, std::string method = "aes-256-cfb", std::string password = "123456")
      : p_server(server), cipher_method(std::move(method)), password(std::move(password)) {
    this->p_handle_in = std::make_unique<uv_tcp_t>();
    this->p_handle_out = std::make_unique<uv_tcp_t>();
    uv_tcp_init(server->loop, this->p_handle_in.get());
    uv_tcp_init(server->loop, this->p_handle_out.get());
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

    uv_read_start(this->handle_in<uv_stream_t>(), AllocBuffer, ReadData);
  }

  template<typename U>
  U* handle_in() {
    return reinterpret_cast<U*>(this->p_handle_in.get());
  }
};

}
#endif