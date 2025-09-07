#include <array>
#include <atomic>
#include <boost/asio.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <cstring>
#include <deque>
#include <fast_proto/logger.hxx>
#include <fast_proto/net/common.hxx>
#include <fast_proto/net/tcp_client.hxx>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace FastProto::net {

using boost::asio::ip::tcp;
namespace io = boost::asio;

static constexpr std::uint32_t kMaxFrameLen = 32u * 1024u * 1024u;

struct TcpClient::Impl {
  explicit Impl(TcpClient* outer)
      : self(outer), socket(ioc), retry_timer(ioc) {}

  void start_read() { do_read_len(); }

  void do_read_len() {
    auto* impl = this;
    io::async_read(
        socket, io::buffer(len_buf.data(), len_buf.size()),
        [impl](const boost::system::error_code& ec, std::size_t n) {
          if (ec || n != 4) {
            Logger::print_error(
                "FastProto",
                std::format("[Client] read len error: {}", ec.message())
                    .c_str());
            impl->on_transport_error();
            return;
          }
          std::uint32_t nlen = 0;
          std::memcpy(&nlen, impl->len_buf.data(), 4);
          const std::uint32_t len = ntohl(nlen);
          if (len == 0 || len > kMaxFrameLen) {
            Logger::print_error("FastProto", "[Client] invalid frame length");
            impl->on_transport_error();
            return;
          }
          impl->in_buf.resize(len);
          impl->do_read_body();
        });
  }

  void do_read_body() {
    auto* impl = this;
    io::async_read(
        socket, io::buffer(in_buf.data(), in_buf.size()),
        [impl](const boost::system::error_code& ec, std::size_t n) {
          if (ec || n != impl->in_buf.size()) {
            Logger::print_error(
                "FastProto",
                std::format("[Client] read body error: {}", ec.message())
                    .c_str());
            impl->on_transport_error();
            return;
          }
          FastProto::Packet req;
          if (!common::deserialize_packet(impl->in_buf, req)) {
            Logger::print_error("FastProto", "[Client] decode error");
            impl->on_transport_error();
            return;
          }

          FastProto::Packet resp;
          auto handler = impl->self->handler_;
          if (handler) {
            try {
              handler(req, resp);
            } catch (...) {
              Logger::print_error("FastProto",
                                  "[Client] handler threw exception");
            }
          }

          if (handler) {
            auto payload = common::serialize_packet(resp);
            if (!payload.empty()) {
              auto buf = std::make_shared<std::vector<std::uint8_t>>();
              buf->resize(4 + payload.size());
              const std::uint32_t nlen =
                  htonl(static_cast<std::uint32_t>(payload.size()));
              std::memcpy(buf->data(), &nlen, 4);
              std::memcpy(buf->data() + 4, payload.data(), payload.size());
              io::post(impl->ioc.get_executor(), [impl, buf]() {
                if (impl->socket.is_open())
                  impl->enqueue_write(buf);
              });
            }
          }

          impl->do_read_len();
        });
  }

  void enqueue_write(const std::shared_ptr<std::vector<std::uint8_t>>& buf) {
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
    auto self_buf = out_q.front();
    auto* impl = this;
    io::async_write(
        socket, io::buffer(self_buf->data(), self_buf->size()),
        [impl](const boost::system::error_code& ec, std::size_t /* ignore */) {
          if (ec) {
            Logger::print_error(
                "FastProto",
                std::format("[Client] write error: {}", ec.message()).c_str());
            impl->out_q.clear();
            impl->writing = false;
            impl->on_transport_error();
            return;
          }
          if (!impl->out_q.empty()) {
            impl->out_q.pop_front();
          } else {
            Logger::print_debug(
                "FastProto",
                "[Client] write completion with empty queue (race on clear)");
          }
          
          impl->do_write();
        });
  }

  void on_transport_error() {
    close_socket_only();
    schedule_reconnect();
  }

  void close_socket_only() {
    boost::system::error_code ignored;
    socket.shutdown(tcp::socket::shutdown_both, ignored);
    socket.close(ignored);
    connected.store(false, std::memory_order_release);
  }

  void do_connect(std::shared_ptr<std::promise<bool>> first_attempt = nullptr) {
    auto resolver = std::make_shared<tcp::resolver>(ioc);
    resolver->async_resolve(
        self->host_, std::to_string(self->port_),
        [this, resolver, first_attempt](const boost::system::error_code& ec,
                                        tcp::resolver::results_type results) {
          if (ec) {
            Logger::print_error(
                "FastProto",
                std::format("[Client] resolve error: {}", ec.message())
                    .c_str());
            if (first_attempt)
              first_attempt->set_value(false);
            schedule_reconnect();
            return;
          }
          boost::asio::async_connect(
              socket, results,
              [this, first_attempt](const boost::system::error_code& ec2,
                                    const tcp::endpoint&) {
                if (ec2) {
                  Logger::print_error(
                      "FastProto",
                      std::format("[Client] connect error: {}", ec2.message())
                          .c_str());
                  if (first_attempt)
                    first_attempt->set_value(false);
                  schedule_reconnect();
                  return;
                }
                try {
                  socket.set_option(boost::asio::socket_base::keep_alive(true));
                } catch (...) {}
                connected.store(true, std::memory_order_release);
                backoff_cur = backoff_min;
                Logger::print_debug("FastProto", "[Client] Connected");
                start_read();
                if (first_attempt)
                  first_attempt->set_value(true);
              });
        });
  }

  void schedule_reconnect() {
    if (!auto_reconnect)
      return;
    if (!self->running_.load(std::memory_order_acquire))
      return;

    backoff_cur =
        std::min<std::chrono::milliseconds>(backoff_cur * 2, backoff_max);
    retry_timer.expires_after(backoff_cur);
    retry_timer.async_wait([this](const boost::system::error_code& ec) {
      if (ec)
        return;
      if (!auto_reconnect)
        return;
      if (!self->running_.load(std::memory_order_acquire))
        return;
      if (socket.is_open())
        return;
      do_connect();
    });
  }

  TcpClient* self;

  std::atomic<bool> connected{false};

  io::io_context ioc;
  tcp::socket socket;
  std::unique_ptr<std::thread> io_thread;

  io::steady_timer retry_timer;
  std::chrono::milliseconds backoff_min{std::chrono::milliseconds(500)};
  std::chrono::milliseconds backoff_cur{backoff_min};
  std::chrono::milliseconds backoff_max{std::chrono::milliseconds(15000)};
  bool auto_reconnect{true};

  std::array<std::uint8_t, 4> len_buf{};
  std::vector<std::uint8_t> in_buf;

  std::deque<std::shared_ptr<std::vector<std::uint8_t>>> out_q;
  bool writing = false;

  std::optional<io::executor_work_guard<io::io_context::executor_type>>
      work_guard;
};

TcpClient::TcpClient(const std::string& host, std::uint16_t port)
    : impl_(std::make_unique<Impl>(this)), host_(host), port_(port) {}

TcpClient::~TcpClient() {
  disconnect();
}

bool TcpClient::connect() {
  if (running_.exchange(true, std::memory_order_acq_rel))
    return true;

  Impl* impl = impl_.get();

  impl->ioc.restart();
  impl->work_guard.emplace(io::make_work_guard(impl->ioc));
  impl->io_thread =
      std::make_unique<std::thread>([impl]() { impl->ioc.run(); });

  auto ready = std::make_shared<std::promise<bool>>();
  auto fut = ready->get_future();

  io::post(impl->ioc.get_executor(), [impl, ready]() mutable {
    impl->backoff_cur = impl->backoff_min;
    impl->auto_reconnect = true;
    impl->do_connect(ready);
  });

  bool ok = false;
  try {
    ok = fut.get();
  } catch (...) {
    ok = false;
  }
  return ok;
}

void TcpClient::disconnect() {
  Impl* impl = impl_.get();
  if (!running_.exchange(false, std::memory_order_acq_rel))
    return;

  impl->auto_reconnect = false;
  (void)impl->retry_timer.cancel();

  std::promise<void> closed;
  auto fut = closed.get_future();
  io::post(impl->ioc.get_executor(), [impl, p = std::move(closed)]() mutable {
    impl->out_q.clear();
    impl->writing = false;
    impl->close_socket_only();
    p.set_value();
  });
  (void)fut.wait_for(std::chrono::milliseconds(200));

  impl->ioc.stop();
  if (impl->io_thread && impl->io_thread->joinable()) {
    impl->io_thread->join();
    impl->io_thread.reset();
  }
  impl->work_guard.reset();
  Logger::print_debug("FastProto", "[Client] Disconnected");
}

bool TcpClient::send(const FastProto::Packet& pkt) {
  Impl* impl = impl_.get();
  if (!impl->connected.load(std::memory_order_acquire) ||
      !impl->socket.is_open())
    return false;

  auto payload = common::serialize_packet(pkt);
  if (payload.empty())
    return true;

  auto buf = std::make_shared<std::vector<std::uint8_t>>();
  buf->resize(4 + payload.size());
  const std::uint32_t nlen = htonl(static_cast<std::uint32_t>(payload.size()));
  std::memcpy(buf->data(), &nlen, 4);
  std::memcpy(buf->data() + 4, payload.data(), payload.size());

  io::post(impl->ioc.get_executor(), [impl, buf]() {
    if (impl->socket.is_open())
      impl->enqueue_write(buf);
  });
  return true;
}

void TcpClient::set_message_handler(common::PacketHandlerFn fn) {
  handler_ = std::move(fn);
}

void TcpClient::set_auto_reconnect(bool on) {
  impl_->auto_reconnect = on;
}

void TcpClient::set_reconnect_backoff(std::chrono::milliseconds min_ms,
                                      std::chrono::milliseconds max_ms) {
  impl_->backoff_min = min_ms;
  impl_->backoff_max = max_ms;
  if (impl_->backoff_cur < min_ms)
    impl_->backoff_cur = min_ms;
  if (impl_->backoff_cur > max_ms)
    impl_->backoff_cur = max_ms;
}

}
