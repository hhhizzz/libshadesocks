#ifndef SHADESOCKS_SRC_SS_HANDLE_H_
#define SHADESOCKS_SRC_SS_HANDLE_H_
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
  RequestingAddress,
};

class ShadeHandle final {
 private:
  FRIEND_TEST(ShadeHandleTest, ReadDataTest);
  FRIEND_TEST(ShadeHandleTest, GetRequestTest);
  FRIEND_TEST(ShadeHandleTest, ConnectTest);

  ProxyState proxy_state;

  uv_stream_t* server_handle;

  uv_tcp_t p_handle_in;
  uv_tcp_t p_handle_out;

  bool connected;

  std::unique_ptr<sockaddr_in> addr_out;
  std::string hostname_out;
  uint16_t port_out;

  std::unique_ptr<Cipher> decrypt_cipher;
  std::unique_ptr<Cipher> encrypt_cipher;
  std::string cipher_method;
  std::string password;

  //save cipher text
  SecByteBlock data;
  ssize_t offset;

  //save plaintext
  char temp[10000];
  ssize_t length;

  void DoNext() {
    switch (this->proxy_state) {
      case ClientReading: {
        this->ReadClient();
        break;
      }
      case RequestingAddress: {
        //TODO: requesting address
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
    shade_handle->connected = true;

    auto length = shade_handle->length;
    if (length == 0) {
      DLOG(INFO) << "the current data is empty, so wait next data";
    } else {
      shade_handle->proxy_state = ProxyState::ServerWriting;
      shade_handle->DoNext();
    }

    delete req;
  }

  void Connect() {
    this->connected = true;
    DLOG(INFO) << "start to connect to " << this->hostname_out << ":" << ntohs(this->addr_out->sin_port);
    auto p_connect = new uv_connect_t{};
    p_connect->data = this;
    int err = uv_tcp_connect(p_connect, &this->p_handle_out, reinterpret_cast<sockaddr*>(addr_out.get()), ConnectDone);
    if (err) {
      throw UvException(err);
    }
  }

  void CopyToTemp() {
    this->length = data.size() - offset;
    memcpy(temp, data.data() + offset, length);
  }

  void GetRequest() {
    DLOG(INFO) << "before parse address, current offset is: " << this->offset;
    auto addr_type = data[0] & 0xf;
    this->offset += 1;
    std::string char_addr;
    this->hostname_out.clear();
    auto req = new uv_getaddrinfo_t{};
    req->data = this;

    switch (addr_type) {
      case AddrType::TypeIPv4: {
        char_addr.resize(4);
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

        this->port_out = 0;
        this->port_out = data[offset++] << 8;
        this->port_out |= data[offset++];
        addr_out->sin_port = htons(this->port_out);

        this->length = this->data.size() - this->offset;
        if (this->length) {
          uv_read_stop(this->handle_in<uv_stream_t>());
          this->CopyToTemp();
          this->Connect();
        }

        break;
      }
      case AddrType::TypeIPv6: {
        throw UvException("doesn't support IPv6 now");
      }
      case AddrType::TypeDomain: {
        char length = data[1];
        this->offset += 1;
        char_addr.resize(length);
        for (; offset < length + 2; offset++) {
          char_addr[offset - 2] = data[offset];
        }

        addrinfo hints{};
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        this->hostname_out = char_addr;

        addr_out = std::make_unique<sockaddr_in>();

        this->port_out = 0;
        this->port_out = data[offset++] << 8;
        this->port_out |= data[offset++];

        DLOG(INFO) << "start to look up the address";
        this->proxy_state = ProxyState::RequestingAddress;
        uv_getaddrinfo(this->server_handle->loop, req, GetRequestDone, char_addr.data(), nullptr, &hints);
        break;
      }
      default:throw UvException("unknown request");
    }

    DLOG(INFO) << "after parse address, current offset is: " << this->offset;
  }

  //send client data to server
  void WriteServer() {
    DLOG(INFO) << "start to write data to server, length: " << this->length;

    auto p_write = new uv_write_t{};
    p_write->data = this;

    uv_buf_t buf;
    buf.len = this->length;
    buf.base = this->temp;

    uv_write(p_write,
             this->handle_out<uv_stream_t>(),
             &buf,
             1,
             WriteServerDone);
  }

  void ReadServer() {
    this->p_handle_out.data = this;
    DLOG(INFO) << "start to read from server";
    uv_read_start(this->handle_out<uv_stream_t>(), AllocBuffer, ReadServerDone);
  }

  //send server data to client
  void WriteClient() {
    auto p_write = new uv_write_t{};
    p_write->data = this;

    uv_buf_t buf;
    buf.len = this->length;
    buf.base = this->temp;

    uv_write(p_write,
             this->handle_in<uv_stream_t>(),
             &buf,
             1,
             WriteClientDone);
  }

  void ReadClient() {
    DLOG(INFO) << "start read data from client";
    this->p_handle_in.data = this;
    uv_read_start(this->handle_in<uv_stream_t>(), AllocBuffer, ReadClientDone);
  }

  //call back method for read from client handle
  //decrypt data
  static void ReadClientDone(uv_stream_t* stream,
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

    DLOG(INFO) << "read buffer from client, nread is: " << nread;
    if (nread > 0) {
      SecByteBlock bytes((byte*) buf->base, nread);
      DLOG(INFO) << "Got data from client, length:  " << nread;

      //if it's first time getting data from client, create cipher and parse server address
      if (shade_handle->decrypt_cipher == nullptr) {

        clock_t t1 = clock();

        auto found = cipher_map.find(shade_handle->cipher_method);
        if (found == cipher_map.cend()) {
          throw ProxyException("unsupported encrypt method");
        }
        auto cipher_info = found->second;
        auto iv = SecByteBlock((byte*) buf->base, cipher_info.iv_length);
        auto key = Util::PasswordToKey(shade_handle->password, cipher_info.key_length);
        shade_handle->decrypt_cipher = Util::getEncryption(shade_handle->cipher_method, key, iv);
        DLOG(INFO) << "decrypt cipher created, method: " << shade_handle->cipher_method << ", key: "
                   << Util::HexToString(key)
                   << ", iv: " << Util::HexToString(iv);

        SecByteBlock encrypt_data((byte*) buf->base + cipher_info.iv_length, nread - cipher_info.iv_length);
        shade_handle->data = shade_handle->decrypt_cipher->decrypt(encrypt_data);

        clock_t t2 = clock();
        DLOG(INFO) << "decrypt data use " << (t2 - t1) * 1.0f / CLOCKS_PER_SEC * 1000 << "ms";

        shade_handle->GetRequest();
      } else {
        clock_t t1 = clock();

        SecByteBlock encrypt_data((byte*) buf->base, nread);
        shade_handle->data = shade_handle->decrypt_cipher->decrypt(encrypt_data);

        clock_t t2 = clock();
        DLOG(INFO) << "decrypt data use " << (t2 - t1) * 1.0f / CLOCKS_PER_SEC * 1000 << "ms";

        uv_read_stop(stream);

        shade_handle->CopyToTemp();
        if (shade_handle->connected) {
          shade_handle->proxy_state = ProxyState::ServerWriting;
          shade_handle->DoNext();
        } else {
          shade_handle->Connect();
        }

      }

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

  }

  static void GetRequestDone(uv_getaddrinfo_t* req,
                             int status,
                             struct addrinfo* addr_info) {
    if (status < 0) {
      throw UvException(status);
    }

    auto shade_handle = reinterpret_cast<ShadeHandle*>(req->data);
    if (shade_handle == nullptr) {
      throw UvException("cannot read data from handle");
    }

    //check if current state is right
    if (shade_handle->proxy_state != ProxyState::RequestingAddress) {
      LOG(ERROR) << "current state is in: " << shade_handle->proxy_state;
      throw ProxyException("expect current state ServerWriting");
    }

    memcpy(shade_handle->addr_out.get(), addr_info->ai_addr, sizeof(sockaddr_in));
    shade_handle->addr_out->sin_port = htons(shade_handle->port_out);

    freeaddrinfo(addr_info);
    DLOG(INFO) << "got ip address";

    shade_handle->length = shade_handle->data.size() - shade_handle->offset;
    if (shade_handle->length) {
      uv_read_stop(shade_handle->handle_in<uv_stream_t>());
      shade_handle->CopyToTemp();
      shade_handle->Connect();
    }
  }

  static void WriteClientDone(uv_write_t* req, int status) {
    //check if ShadeHandle created
    auto shade_handle = reinterpret_cast<ShadeHandle*>(req->data);
    if (shade_handle == nullptr) {
      throw UvException("cannot read data from handle");
    }

    DLOG(INFO) << "data has been wrote to client, length: " << shade_handle->length;

    //check if current state is right
    if (shade_handle->proxy_state != ProxyState::ClientWriting) {
      LOG(ERROR) << "current state is in: " << shade_handle->proxy_state;
      throw ProxyException("expect current state ServerWriting");
    }
    if (status < 0) {
      LOG(ERROR) << "error in write data to client";
      throw UvException(status);
    }

    shade_handle->proxy_state = ProxyState::ClientReading;
    shade_handle->DoNext();
    delete req;
  }

  //copy data to this->data
  static void ReadServerDone(uv_stream_t* stream,
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

    if (nread > 0) {

      SecByteBlock bytes((byte*) buf->base, nread);
      DLOG(INFO) << "Got data, length: " << nread;

      clock_t t1 = clock();

      if (shade_handle->encrypt_cipher == nullptr) {
        //encrypt data
        auto cipher_info = cipher_map.at(shade_handle->cipher_method);
        auto iv = Util::RandomBlock(cipher_info.iv_length);
        auto key = Util::PasswordToKey(shade_handle->password, cipher_info.key_length);
        shade_handle->encrypt_cipher = Util::getEncryption(shade_handle->cipher_method, key, iv);

        DLOG(INFO) << "encrypt cipher created, method: " << shade_handle->cipher_method << ", key: "
                   << Util::HexToString(key)
                   << ", iv: " << Util::HexToString(iv);

        SecByteBlock decrypt_data((byte*) buf->base, nread);

        shade_handle->data = shade_handle->encrypt_cipher->encrypt(decrypt_data);
        shade_handle->length = iv.size() + nread;

        memcpy(shade_handle->temp, iv.data(), iv.size());
        memcpy(shade_handle->temp + iv.size(), shade_handle->data.data(), shade_handle->data.size());
      } else {
        SecByteBlock decrypt_data((byte*) buf->base, nread);
        shade_handle->data = shade_handle->encrypt_cipher->encrypt(decrypt_data);
        shade_handle->length = nread;

        memcpy(shade_handle->temp, shade_handle->data.data(), shade_handle->data.size());
      }

      DLOG(INFO) << "send data to client, length: " << shade_handle->length;

      clock_t t2 = clock();

      DLOG(INFO) << "encrypt data use " << (t2 - t1) * 1.0f / CLOCKS_PER_SEC * 1000 << "ms";

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
  }

  static void WriteServerDone(uv_write_t* req, int status) {
    //check if ShadeHandle created
    auto shade_handle = reinterpret_cast<ShadeHandle*>(req->data);
    if (shade_handle == nullptr) {
      throw UvException("cannot read data from handle");
    }

    DLOG(INFO) << "data has been wrote to server, length: " << shade_handle->length;

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

  static void AllocBuffer(uv_handle_t* handle,
                          size_t suggested_size,
                          uv_buf_t* buf) {
    auto shade_handle = reinterpret_cast<ShadeHandle*>(handle->data);
    if (shade_handle == nullptr) {
      throw UvException("cannot read data from handle");
    }
    buf->base = shade_handle->temp;
    buf->len = sizeof(shade_handle->temp);
  }

 public:
  explicit ShadeHandle(uv_stream_t* server, std::string method = "aes-256-cfb", std::string password = "123456")
      : cipher_method(std::move(method)), password(std::move(password)) {
    uv_tcp_init(server->loop, &this->p_handle_in);
    uv_tcp_init(server->loop, &this->p_handle_out);
    this->server_handle = server;
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
#endif //SHADESOCKS_SRC_SS_HANDLE_H_
