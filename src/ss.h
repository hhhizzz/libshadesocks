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

enum AddrType {
  TypeIPv4 = 1,
  TypeIPv6 = 4,
  TypeDomain = 3,
};

class ShadeHandle final {
 private:
  FRIEND_TEST(ShadeHandleTest, ReadDataTest);
  FRIEND_TEST(ShadeHandleTest, GetRequestTest);

  std::unique_ptr<uv_tcp_t> p_handle_in;
  std::unique_ptr<uv_tcp_t> p_handle_out;

  std::unique_ptr<Cipher> cipher;
  std::string cipher_method;
  std::string password;

  uv_stream_t* p_server;

  SecByteBlock data;
  ssize_t offset;

  std::unique_ptr<sockaddr_in> GetRequest() {
    auto addr_type = data[0] & 0xf;
    this->offset = 1;
    std::unique_ptr<char> char_addr;
    std::unique_ptr<sockaddr_in> addr;

    switch (addr_type) {
      case AddrType::TypeIPv4: {
        char_addr = std::unique_ptr<char>(new char[4]);
        for (; offset < 4 + 1; offset++) {
          char_addr.get()[offset - 1] = data[offset];
        }
        addr = std::make_unique<sockaddr_in>();
        addr->sin_family = AF_INET;
        memcpy(&addr->sin_addr,
               char_addr.get(),
               sizeof(addr->sin_addr));
        break;
      }
      case AddrType::TypeIPv6: {
        throw UvException("doesn't support IPv6 now");
      }
      case AddrType::TypeDomain: {
        char length = data[1];
        this->offset += 1;
        char_addr = std::unique_ptr<char>(new char[length + 1]);
        for (; offset < length + 2; offset++) {
          char_addr.get()[offset - 2] = data[offset];
        }
        char_addr.get()[length] = '\0';

        addrinfo hints{};
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        struct addrinfo* addr_info;
        int err = getaddrinfo(char_addr.get(), nullptr, &hints, &addr_info);
        if (err != 0) {
          throw UvException(gai_strerror(err));
        }

        if (addr_info == nullptr) {
          std::string what = "cannot find address for: ";
          what.append(char_addr.get());
          throw UvException(what);
        }

        addr = std::make_unique<sockaddr_in>();
        memcpy(addr.get(), addr_info->ai_addr, sizeof(sockaddr_in));

        delete[] addr_info;
        break;
      }
      default:throw UvException("unknown request");
    }

    uint16_t dport = 0;
    dport = data[offset++] << 8;
    dport |= data[offset++];
    addr->sin_port = htons(dport);

    return addr;
  }

  static void ReadData(uv_stream_t* stream,
                       ssize_t nread,
                       const uv_buf_t* buf) {
    auto shade_handle = reinterpret_cast<ShadeHandle*>(stream->data);
    if (shade_handle == nullptr) {
      throw UvException("cannot read data from handle");
    }
    shade_handle->offset = 0;

    DLOG(INFO) << "start to read buffer, nread is: " << nread;
    if (nread > 0) {
      SecByteBlock bytes((byte*) buf->base, nread);
      DLOG(INFO) << "Got data: " << Util::HexToString(bytes);

      if (shade_handle->cipher == nullptr) {
        auto cipher_info = cipher_map.at(shade_handle->cipher_method);
        auto iv = SecByteBlock((byte*) buf->base, cipher_info.iv_length);
        auto key = Util::PasswordToKey(shade_handle->password, cipher_info.key_length);
        shade_handle->cipher = Util::getEncryption(shade_handle->cipher_method, key, iv);
        DLOG(INFO) << "cipher created, method: " << shade_handle->cipher_method << ", key: " << Util::HexToString(key)
                   << ", iv: " << Util::HexToString(iv);

        SecByteBlock encrypt_data((byte*) buf->base + cipher_info.iv_length, nread - cipher_info.iv_length);
        shade_handle->data = shade_handle->cipher->decrypt(encrypt_data);
      } else {
        SecByteBlock encrypt_data((byte*) buf->base, nread);
        shade_handle->data = shade_handle->cipher->decrypt(encrypt_data);
      }
    } else if (nread < 0) {
      if (nread != UV_EOF) {
        LOG(ERROR) << "Read error: " << uv_err_name(nread);
      }
    } else {
      DLOG(INFO) << "data is empty";
    }
    DLOG(INFO) << "encrypt data is: " << Util::HexToString(shade_handle->data);

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