#include <algorithm>
#include <atomic>
#include <boost/asio.hpp>
#include <boost/asio/post.hpp>
#include <cstring>
#include <deque>
#include <fast_proto/logger.hxx>
#include <fast_proto/net/common.hxx>    
#include <fast_proto/net/tcp_server.hxx>
#include <format>
#include <memory>
#include <vector>
#include <unordered_set>

namespace FastProto::net {

using boost::asio::ip::tcp;

static constexpr uint32_t kMaxFrameLen = 32u * 1024u * 1024u;

struct TcpServer::Impl {
  struct Session : public std::enable_shared_from_this<Session> {
    tcp::socket socket;
    TcpServer& owner;
    std::array<std::uint8_t, 4> len_buf{};
    std::vector<std::uint8_t> in_buf;

    std::deque<std::shared_ptr<std::vector<uint8_t>>> out_q;
    bool writing = false;

    explicit Session(boost::asio::io_context& ioc, TcpServer& owner_)
        : socket(ioc), owner(owner_) {}

    void start() { do_read_len(); }

    void do_read_len() {
      auto self = shared_from_this();
      boost::asio::async_read(
          socket, boost::asio::buffer(len_buf),
          [self](boost::system::error_code ec, std::size_t n) {
            if (ec || n != 4) {
              self->close();
              return;
            }
            uint32_t nlen = 0;
            std::memcpy(&nlen, self->len_buf.data(), 4);
            const uint32_t len = ntohl(nlen);
            if (len == 0 || len > kMaxFrameLen) {
              self->close();
              return;
            }
            self->in_buf.resize(len);
            self->do_read_body();
          });
    }

    void do_read_body() {
      auto self = shared_from_this();
      boost::asio::async_read(
          socket, boost::asio::buffer(in_buf),
          [self](boost::system::error_code ec, std::size_t n) {
            if (ec || n != self->in_buf.size()) {
              self->close();
              return;
            }

            FastProto::Packet req;
            if (!common::deserialize_packet(self->in_buf, req)) {
              Logger::print_error("FastProto",
                                  "[Server] Failed to deserialize packet");
              self->close();
              return;
            }

            req.source_fd =
                static_cast<std::intptr_t>(self->socket.native_handle());

            FastProto::Packet resp;
            if (const auto it = self->owner.handlers_.find(req.opcode);
                it != self->owner.handlers_.end()) {
              it->second(req, resp);
            }

            auto payload = common::serialize_packet(resp);
            const uint32_t nlen = htonl(static_cast<uint32_t>(payload.size()));

            auto out = std::make_shared<std::vector<uint8_t>>();
            out->reserve(4 + payload.size());
            out->insert(out->end(), reinterpret_cast<const uint8_t*>(&nlen),
                        reinterpret_cast<const uint8_t*>(&nlen) + 4);
            out->insert(out->end(), payload.begin(), payload.end());

            self->enqueue_write(out);

            self->do_read_len();
          });
    }

    void enqueue_write(const std::shared_ptr<std::vector<uint8_t>>& buf) {
      out_q.push_back(buf);
      if (!writing) {
        writing = true;
        do_write();
      }
    }

    void do_write() {
      if (out_q.empty()) {
        writing = false;
        return;
      }
      auto self = shared_from_this();
      auto& buf = *out_q.front();
      boost::asio::async_write(
          socket, boost::asio::buffer(buf),
          [self](boost::system::error_code ec, std::size_t) {
            if (ec) {
              self->close();
              return;
            }
            self->out_q.pop_front();
            self->do_write();
          });
    }

    void close() {
      auto fd = static_cast<std::intptr_t>(socket.native_handle());

      boost::system::error_code ignored;
      socket.shutdown(tcp::socket::shutdown_both, ignored);
      socket.close(ignored);

      owner.notify_disconnect(fd);
    }
  };

  using WorkGuard = boost::asio::executor_work_guard<boost::asio::io_context::executor_type>;
  explicit Impl(TcpServer* outer, uint16_t port)
      : ioc(1), acceptor(ioc), self(outer), work(boost::asio::make_work_guard(ioc)) {
    boost::system::error_code ec;
    tcp::endpoint ep(tcp::v4(), port);
    acceptor.open(ep.protocol(), ec);
    acceptor.set_option(tcp::acceptor::reuse_address(true), ec);
    acceptor.bind(ep, ec);
    acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
  }

  void start_accept() {
    auto session = std::make_shared<Session>(ioc, *self);
    acceptor.async_accept(
        session->socket, [this, session](boost::system::error_code ec) {
          if (!ec && self->running_.load(std::memory_order_acquire)) {
            sessions.push_back(session);
            Logger::print_debug("FastProto", "[Server] Client connected");

            auto fd =
                static_cast<std::intptr_t>(session->socket.native_handle());
            self->notify_connect(fd);

            session->start();
          }

          if (self->running_.load(std::memory_order_acquire)) {
            start_accept();
          }
        });
  }

  void broadcast_shared(const std::shared_ptr<std::vector<uint8_t>>& buf) {
    sessions.erase(std::remove_if(sessions.begin(), sessions.end(),
                                  [](const std::weak_ptr<Session>& w) {
                                    return w.expired();
                                  }),
                   sessions.end());

    for (auto& w : sessions) {
      if (auto s = w.lock()) {
        s->enqueue_write(buf);
      }
    }
  }

  void multicast_shared(const std::shared_ptr<std::vector<uint8_t>>& buf,
                        const std::shared_ptr<std::unordered_set<std::intptr_t>>& targets) {
    sessions.erase(std::remove_if(sessions.begin(), sessions.end(),
                                  [](const std::weak_ptr<Session>& w){ return w.expired(); }),
                   sessions.end());

    for (auto& w : sessions) {
      if (auto s = w.lock()) {
        auto fd = static_cast<std::intptr_t>(s->socket.native_handle());
        if (targets->count(fd)) {
          s->enqueue_write(buf);
        }
      }
    }
  }

  void stop_all() {
    boost::system::error_code ec;
    acceptor.cancel(ec);
    acceptor.close(ec);
    for (auto& w : sessions) {
      if (auto s = w.lock())
        s->close();
    }
    sessions.clear();
    work.reset();
    ioc.stop();
  }

  boost::asio::io_context ioc;
  tcp::acceptor acceptor;
  std::vector<std::weak_ptr<Session>> sessions;
  TcpServer* self;
  WorkGuard work;
};

TcpServer::TcpServer(const uint16_t port)
    : impl_(std::make_unique<Impl>(this, port)), port_(port) {}

TcpServer::~TcpServer() {
  stop();
}

void TcpServer::register_handler(uint32_t opcode, common::PacketHandlerFn fn) {
  handlers_[opcode] = std::move(fn);
}

void TcpServer::set_connect_handler(ConnectClientFn fn) {
  on_connect_ = std::move(fn);
}

void TcpServer::set_disconnect_handler(DisconnectClientFn fn) {
  on_disconnect_ = std::move(fn);
}

void TcpServer::broadcast(const FastProto::Packet& packet) {
  const auto payload = common::serialize_packet(packet);
  const uint32_t nlen = htonl(static_cast<uint32_t>(payload.size()));

  auto buf = std::make_shared<std::vector<uint8_t>>();
  buf->reserve(4 + payload.size());
  buf->insert(buf->end(), reinterpret_cast<const uint8_t*>(&nlen),
              reinterpret_cast<const uint8_t*>(&nlen) + 4);
  buf->insert(buf->end(), payload.begin(), payload.end());

  boost::asio::post(
      impl_->ioc, [impl = impl_.get(), buf]() { impl->broadcast_shared(buf); });
}

void TcpServer::multicast(const FastProto::Packet& packet,
                          const std::vector<std::intptr_t>& fds) {
  const auto payload = common::serialize_packet(packet);
  const uint32_t nlen = htonl(static_cast<uint32_t>(payload.size()));

  auto buf = std::make_shared<std::vector<uint8_t>>();
  buf->reserve(4 + payload.size());
  buf->insert(buf->end(), reinterpret_cast<const uint8_t*>(&nlen),
              reinterpret_cast<const uint8_t*>(&nlen) + 4);
  buf->insert(buf->end(), payload.begin(), payload.end());

  auto targets = std::make_shared<std::unordered_set<std::intptr_t>>(fds.begin(), fds.end());
  boost::asio::post(impl_->ioc, [impl = impl_.get(), buf, targets]() {
    impl->multicast_shared(buf, targets);
  });
}

void TcpServer::run() {
  if (running_.exchange(true, std::memory_order_acq_rel))
    return;

  Logger::print_debug(
      "FastProto", std::format("[Server] Listening on port {}", port_).c_str());

  impl_->start_accept();
  impl_->ioc.restart();
  impl_->ioc.run();

  running_.store(false, std::memory_order_release);
  Logger::print_debug("FastProto", "[Server] Stopped");
}

void TcpServer::stop() {
  if (!running_.exchange(false, std::memory_order_acq_rel))
    return;

  boost::asio::post(impl_->ioc, [impl = impl_.get()]() { impl->stop_all(); });
  impl_->ioc.poll();
}

void TcpServer::notify_connect(std::intptr_t fd) {
  if (on_connect_)
    on_connect_(fd);
}

void TcpServer::notify_disconnect(std::intptr_t fd) {
  if (on_disconnect_)
    on_disconnect_(fd);
}

}