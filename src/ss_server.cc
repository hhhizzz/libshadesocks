#include "ss_server.h"
namespace shadesocks {

uv_loop_t* Server::loop = uv_default_loop();

Server::Server() {
  uv_tcp_init(shadesocks::Server::loop, &this->tcp_server);
  uv_ip4_addr("0.0.0.0", DEFAULT_PORT, &this->address);

  uv_tcp_bind(&this->tcp_server, (sockaddr*) &this->address, 0);
}
Server::~Server() {}

void Server::start() {
  LOG(INFO) << "start the server at port: " << DEFAULT_PORT;
  int error = uv_listen((uv_stream_t*) &this->tcp_server, DEFAULT_BACKLOG,
                        ServerCallback::on_new_connection);
  if (error) {
    LOG(ERROR) << "Listen error: " << uv_strerror(error);
    // TODO: start fail
  }
  uv_run(loop, UV_RUN_DEFAULT);
}

void ServerCallback::on_new_connection(uv_stream_t* server, int status) {
  if (status < 0) {
    LOG(ERROR) << "New connection error: " << uv_strerror(status);
    // error!
    return;
  }

  uv_tcp_t* client = new uv_tcp_t();
  uv_tcp_init(Server::loop, client);
  if (uv_accept(server, (uv_stream_t*) client) == 0) {
    uv_read_start((uv_stream_t*) client, ServerCallback::alloc_buffer,
                  ServerCallback::read_buffer);
  } else {
    uv_close((uv_handle_t*) client, ServerCallback::on_close);
  }
}
void ServerCallback::read_buffer(uv_stream_t* client, ssize_t nread,
                                 const uv_buf_t* buf) {
  if (nread > 0) {
    Server::write_req_t* req = new Server::write_req_t();

    SecByteBlock bytes((byte*) buf->base, nread);

    LOG(INFO) << "Got data: " << shadesocks::Util::HexToString(bytes);

    req->buf = uv_buf_init(buf->base, nread);

    uv_write(&req->req, client, &req->buf, 1, ServerCallback::after_write);
    return;
  }
  if (nread < 0) {
    if (nread != UV_EOF) {
      LOG(ERROR) << "Read error: " << uv_err_name(nread);
    }
    uv_close((uv_handle_t*) client, ServerCallback::on_close);
  }

  delete buf->base;
}
void ServerCallback::alloc_buffer(uv_handle_t* handle, size_t suggested_size,
                                  uv_buf_t* buf) {
  buf->base = (char*) malloc(suggested_size);
  buf->len = suggested_size;
}
void ServerCallback::after_write(uv_write_t* req, int status) {
  if (status) {
    LOG(ERROR) << "Write error " << uv_strerror(status);
  }
  auto* wr = reinterpret_cast<Server::write_req_t*>(req);
  delete[] wr->buf.base;
  delete wr;
}

std::shared_ptr<Loop> Loop::getDefault() {
  static std::weak_ptr<Loop> ref;
  std::shared_ptr<Loop> loop;

  if (ref.expired()) {
    auto def = uv_default_loop();

    if (def) {
      auto ptr = std::unique_ptr<uv_loop_t, Deleter>(def, [](uv_loop_t*) {});
      loop = std::shared_ptr<Loop>{new Loop{std::move(ptr)}};
    }

    ref = loop;
  } else {
    loop = ref.lock();
  }

  return loop;
}

void Loop::close() {
  uv_loop_close(this->loop.get());
}
bool Loop::run(uv_run_mode mode) noexcept {
  return (uv_run(loop.get(), mode) == 0);
}
void Loop::stop() noexcept {
  uv_stop(loop.get());
}
bool Loop::alive() const noexcept {
  return uv_loop_alive(this->loop.get()) != 0;
}

}  // namespace shadesocks