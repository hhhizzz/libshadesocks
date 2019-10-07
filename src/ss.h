#include <exception>
#include <memory>
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

class ProxyException : public std::runtime_error {
 public:
  explicit ProxyException(const std::string& what) : std::runtime_error(what) {}
};

enum AddrType {
  TypeIPv4 = 1,
  TypeIPv6 = 4,
  TypeDomain = 3,
};

enum ProxyState {
  ServerWriting,
  ServerReading,
  ClientWriting,
  ClientReading,
};

class ShadeHandle final {
 private:
  FRIEND_TEST(ShadeHandleTest, ReadDataTest);
  FRIEND_TEST(ShadeHandleTest, GetRequestTest);
  FRIEND_TEST(ShadeHandleTest, ConnectTest);

  ProxyState proxy_state;

  uv_tcp_t p_handle_in;
  uv_tcp_t p_handle_out;

  std::unique_ptr<sockaddr_in> addr_out;
  std::string hostname_out;

  std::unique_ptr<Cipher> cipher;
  std::string cipher_method;
  std::string password;

  SecByteBlock data;
  ssize_t offset;

  void DoNext() {
    switch (this->proxy_state) {
      case ClientReading: {
        this->ReadClient();
        break;
      }
      case ServerWriting: {
        this->WriteServer();
        break;
      }
      case ServerReading: {
        this->ReadServer();
        break;
      }
      case ClientWriting: {
        this->WriteClient();
        break;
      }
    }
  }

  static void ConnectDone(uv_connect_t* req, int status) {
    if (status < 0) {
      throw UvException(status);
    }
    auto shade_handle = reinterpret_cast<ShadeHandle*>(req->data);
    DLOG(INFO) << "connected to " << shade_handle->hostname_out << ":" << ntohs(shade_handle->addr_out->sin_port);
    shade_handle->proxy_state = ProxyState::ServerWriting;

    delete req;

    shade_handle->DoNext();
  }

  void Connect() {
    DLOG(INFO) << "start to connect to " << this->hostname_out << ":" << ntohs(this->addr_out->sin_port);
    auto p_connect = new uv_connect_t{};
    p_connect->data = this;
    uv_tcp_connect(p_connect, &this->p_handle_out, reinterpret_cast<sockaddr*>(addr_out.get()), ConnectDone);
  }

  //send client data to server
  void WriteServer() {
    DLOG(INFO) << "start to write data to server";

    auto p_write = new uv_write_t{};
    p_write->data = this;

    uv_buf_t buf;
    buf.len = this->data.size() - this->offset;
    buf.base = (char*) &this->data[offset];

    uv_write(p_write,
             this->handle_out<uv_stream_t>(),
             &buf,
             1,
             WriteServerDone);
  }

  void ReadServer() {
    this->p_handle_out.data = this;
    uv_read_start(this->handle_out<uv_stream_t>(), AllocBuffer, ReadServerData);
  }

  //send server data to client
  void WriteClient() {
    auto p_write = new uv_write_t{};
    p_write->data = this;

    uv_buf_t buf;
    buf.len = this->data.size() - this->offset;
    buf.base = (char*) &this->data[this->offset];

    uv_write(p_write,
             this->handle_in<uv_stream_t>(),
             &buf,
             1,
             WriteClientDone);
  }

  void GetRequest() {
    auto addr_type = data[0] & 0xf;
    this->offset = 1;
    std::string char_addr;
    this->hostname_out.clear();

    switch (addr_type) {
      case AddrType::TypeIPv4: {
        char_addr.reserve(4);
        for (; offset < 4 + 1; offset++) {
          char_addr[offset - 1] = data[offset];
          this->hostname_out.append(std::to_string(int(data[offset])));
          if (offset != 4) {
            this->hostname_out.append(".");
          }
        }
        addr_out = std::make_unique<sockaddr_in>();
        addr_out->sin_family = AF_INET;
        memcpy(&addr_out->sin_addr,
               &char_addr[0],
               sizeof(addr_out->sin_addr));
        break;
      }
      case AddrType::TypeIPv6: {
        throw UvException("doesn't support IPv6 now");
      }
      case AddrType::TypeDomain: {
        char length = data[1];
        this->offset += 1;
        char_addr.reserve(length + 1);
        for (; offset < length + 2; offset++) {
          char_addr[offset - 2] = data[offset];
        }
        char_addr[length] = '\0';

        addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        struct addrinfo* addr_info;

        //TODO: use uv call back to get addrinfo
        int err = getaddrinfo(&char_addr[0], nullptr, nullptr, &addr_info);
        if (err != 0) {
          throw UvException(gai_strerror(err));
        }

        if (addr_info == nullptr) {
          std::string what = "cannot find address for: ";
          what.append(char_addr);
          throw UvException(what);
        }
        this->hostname_out = char_addr;

        addr_out = std::make_unique<sockaddr_in>();
        memcpy(addr_out.get(), addr_info->ai_addr, sizeof(sockaddr_in));

        freeaddrinfo(addr_info);
        break;
      }
      default:throw UvException("unknown request");
    }

    uint16_t dport = 0;
    dport = data[offset++] << 8;
    dport |= data[offset++];
    addr_out->sin_port = htons(dport);
  }

  void ReadClient() {
    this->p_handle_in.data = this;
    uv_read_start(this->handle_in<uv_stream_t>(), AllocBuffer, ReadClientData);
  }

  //call back method for read from client handle
  //decrypt data
  static void ReadClientData(uv_stream_t* stream,
                             ssize_t nread,
                             const uv_buf_t* buf) {
    //check if ShadeHandle created
    auto shade_handle = reinterpret_cast<ShadeHandle*>(stream->data);
    if (shade_handle == nullptr) {
      throw UvException("cannot read data from handle");
    }

    //check if current state is right
    if (nread >= 0 && shade_handle->proxy_state != ProxyState::ClientReading) {
      LOG(ERROR) << "current state is in: " << shade_handle->proxy_state;
      throw ProxyException("expect current state ClientReading");
    }

    shade_handle->offset = 0;

    DLOG(INFO) << "start to read buffer from client, nread is: " << nread;
    if (nread > 0) {
      SecByteBlock bytes((byte*) buf->base, nread);
      DLOG(INFO) << "Got data: " << Util::HexToString(bytes);

      //if it's first time getting data from client, create cipher and parse server address
      if (shade_handle->cipher == nullptr) {
        auto found = cipher_map.find(shade_handle->cipher_method);
        if (found == cipher_map.cend()) {
          throw ProxyException("unsupported encrypt method");
        }
        auto cipher_info = found->second;
        auto iv = SecByteBlock((byte*) buf->base, cipher_info.iv_length);
        auto key = Util::PasswordToKey(shade_handle->password, cipher_info.key_length);
        shade_handle->cipher = Util::getEncryption(shade_handle->cipher_method, key, iv);
        DLOG(INFO) << "cipher created, method: " << shade_handle->cipher_method << ", key: " << Util::HexToString(key)
                   << ", iv: " << Util::HexToString(iv);

        SecByteBlock encrypt_data((byte*) buf->base + cipher_info.iv_length, nread - cipher_info.iv_length);
        shade_handle->data = shade_handle->cipher->decrypt(encrypt_data);

        uv_read_stop(stream);

        shade_handle->GetRequest();
        shade_handle->Connect();
      } else {
        SecByteBlock encrypt_data((byte*) buf->base, nread);
        shade_handle->data = shade_handle->cipher->decrypt(encrypt_data);

        uv_read_stop(stream);

        shade_handle->proxy_state = ProxyState::ServerWriting;
        shade_handle->DoNext();
      }
      DLOG(INFO) << "encrypt data is: " << Util::HexToString(shade_handle->data);

    } else if (nread < 0) {
      if (nread != UV_EOF) {
        LOG(ERROR) << "Read error: " << uv_err_name(nread);
        throw UvException(nread);
      } else {
        DLOG(INFO) << "close connection for client sent an EOF";
        uv_close(shade_handle->handle_in<uv_handle_t>(), [](uv_handle_t* handle) {
          uv_close(reinterpret_cast<ShadeHandle*>(handle->data)->handle_out<uv_handle_t>(),
                   [](uv_handle_t* handle) {
                     delete (ShadeHandle*) handle->data;
                   });
        });
      }
    }

    delete[] buf->base;
  }

  static void WriteClientDone(uv_write_t* req, int status) {
    //check if ShadeHandle created
    DLOG(INFO) << "data has been wrote to client";
    auto shade_handle = reinterpret_cast<ShadeHandle*>(req->data);
    if (shade_handle == nullptr) {
      throw UvException("cannot read data from handle");
    }

    //check if current state is right
    if (shade_handle->proxy_state != ProxyState::ClientWriting) {
      LOG(ERROR) << "current state is in: " << shade_handle->proxy_state;
      throw ProxyException("expect current state ServerWriting");
    }
    if (status >= 0) {
      shade_handle->proxy_state = ProxyState::ClientReading;
      shade_handle->DoNext();
    } else {
      LOG(ERROR) << "error in write data to client";
      throw UvException(status);
    }
    shade_handle->proxy_state = ProxyState::ClientReading;
    delete req;
  }

  static void WriteServerDone(uv_write_t* req, int status) {
    //check if ShadeHandle created
    DLOG(INFO) << "data has been wrote to server";
    auto shade_handle = reinterpret_cast<ShadeHandle*>(req->data);
    if (shade_handle == nullptr) {
      throw UvException("cannot read data from handle");
    }

    //check if current state is right
    if (shade_handle->proxy_state != ProxyState::ServerWriting) {
      LOG(ERROR) << "current state is in: " << shade_handle->proxy_state;
      throw ProxyException("expect current state ServerWriting");
    }
    if (status >= 0) {
      shade_handle->proxy_state = ProxyState::ServerReading;
      shade_handle->DoNext();
    } else {
      LOG(ERROR) << "write to server error";
      throw UvException(status);
    }
    delete req;
  }

  //copy data to this->data
  static void ReadServerData(uv_stream_t* stream,
                             ssize_t nread,
                             const uv_buf_t* buf) {
    DLOG(INFO) << "read buffer from server, nread is: " << nread;

    auto shade_handle = reinterpret_cast<ShadeHandle*>(stream->data);
    if (shade_handle == nullptr) {
      throw UvException("cannot read data from handle");
    }
    //check if current state is right
    if (nread >= 0 && shade_handle->proxy_state != ProxyState::ServerReading) {
      LOG(ERROR) << "current state is in: " << shade_handle->proxy_state;
      throw ProxyException("expect current state ServerReading");
    }
    shade_handle->offset = 0;

    if (nread >= 0) {

      SecByteBlock bytes((byte*) buf->base, nread);
      DLOG(INFO) << "Got data: \n" << std::string(buf->base);

      //encrypt data
      auto cipher_info = cipher_map.at(shade_handle->cipher_method);
      auto iv = SecByteBlock((byte*) buf->base, cipher_info.iv_length);
      auto key = Util::PasswordToKey(shade_handle->password, cipher_info.key_length);
      SecByteBlock decrypt_data((byte*) buf->base + cipher_info.iv_length, nread - cipher_info.iv_length);
      shade_handle->data = shade_handle->cipher->encrypt(decrypt_data);
      shade_handle->offset = 0;

      uv_read_stop(stream);

      shade_handle->proxy_state = ProxyState::ClientWriting;
      shade_handle->DoNext();
    } else if (nread < 0) {
      if (nread != UV_EOF) {
        LOG(ERROR) << "Read error: " << uv_err_name(nread);
        throw UvException(nread);
      } else {
        DLOG(INFO) << "got an EOF";
      }
    }

    delete[] buf->base;
  }

  static void AllocBuffer(uv_handle_t* handle,
                          size_t suggested_size,
                          uv_buf_t* buf) {
    buf->base = new char[suggested_size];
    buf->len = suggested_size;
  }

 public:
  explicit ShadeHandle(uv_stream_t* server, std::string method = "aes-256-cfb", std::string password = "123456")
      : cipher_method(std::move(method)), password(std::move(password)) {
    uv_tcp_init(server->loop, &this->p_handle_in);
    uv_tcp_init(server->loop, &this->p_handle_out);
  }

  ~ShadeHandle() {
    DLOG(INFO) << "ShadeHandle has been deleted";
  }

  void Accept(uv_stream_t* server) {
    int err = uv_accept(server, this->handle_in<uv_stream_t>());
    if (err) {
      throw UvException(err);
    }
    this->proxy_state = ProxyState::ClientReading;
    this->DoNext();
  }

  template<typename U>
  U* handle_in() {
    return reinterpret_cast<U*>(&this->p_handle_in);
  }

  template<typename U>
  U* handle_out() {
    return reinterpret_cast<U*>(&this->p_handle_out);
  }
};

}
#endif