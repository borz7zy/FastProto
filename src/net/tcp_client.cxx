#include <array>
#include <atomic>
#include <boost/asio.hpp>
#include <boost/asio/post.hpp>
#include <deque>
#include <fast_proto/logger.hxx>
#include <fast_proto/net/common.hxx>
#include <fast_proto/net/tcp_client.hxx>
#include <format>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace FastProto::net {

using boost::asio::ip::tcp;

static constexpr uint32_t kMaxFrameLen = 32u * 1024u * 1024u;

struct TcpClient::Impl {
  explicit Impl(TcpClient* outer) : self(outer), socket(ioc) {}

  void start_read() { do_read_len(); }

  void do_read_len() {
    auto* impl = this;
    boost::asio::async_read(
        socket, boost::asio::buffer(len_buf),
        [impl](const boost::system::error_code& ec, std::size_t n) {
          if (ec || n != 4) {
            impl->close();
            return;
          }
          uint32_t nlen = 0;
          std::memcpy(&nlen, impl->len_buf.data(), 4);
          const uint32_t len = ntohl(nlen);
          if (len == 0 || len > kMaxFrameLen) {
            impl->close();
            return;
          }
          impl->in_buf.resize(len);
          impl->do_read_body();
        });
  }

  void do_read_body() {
    auto* impl = this;
    boost::asio::async_read(
        socket, boost::asio::buffer(in_buf),
        [impl](const boost::system::error_code& ec, std::size_t n) {
          if (ec || n != impl->in_buf.size()) {
            impl->close();
            return;
          }

          FastProto::Packet pkt;
          if (!common::deserialize_packet(impl->in_buf, pkt)) {
            Logger::print_error("FastProto",
                                "[Client] Failed to deserialize packet");
            impl->close();
            return;
          }

          if (impl->self->handler_) {
            FastProto::Packet dummy;
            impl->self->handler_(pkt, dummy);
          }

          impl->do_read_len();
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
    auto* impl = this;
    auto& buf = *out_q.front();
    boost::asio::async_write(
        socket, boost::asio::buffer(buf),
        [impl](const boost::system::error_code& ec, std::size_t) {
          if (ec) {
            impl->close();
            return;
          }
          impl->out_q.pop_front();
          impl->do_write();
        });
  }

  void close() {
    boost::system::error_code ignored;
    socket.shutdown(tcp::socket::shutdown_both, ignored);
    socket.close(ignored);
    running.store(false, std::memory_order_release);
  }

  TcpClient* self;
  std::atomic<bool> running{false};

  boost::asio::io_context ioc;
  tcp::socket socket;
  std::unique_ptr<std::thread> io_thread;

  std::array<std::uint8_t, 4> len_buf{};
  std::vector<std::uint8_t> in_buf;

  std::deque<std::shared_ptr<std::vector<uint8_t>>> out_q;
  bool writing = false;
};

TcpClient::TcpClient(const std::string& host, uint16_t port)
    : impl_(std::make_unique<Impl>(this)), host_(host), port_(port) {}

TcpClient::~TcpClient() {
  disconnect();
}

bool TcpClient::connect() {
  if (running_.exchange(true, std::memory_order_acq_rel))
    return true;

  Impl* impl = impl_.get();

  impl->ioc.restart();
  impl->io_thread =
      std::make_unique<std::thread>([impl]() { impl->ioc.run(); });

  auto ready = std::make_shared<std::promise<bool>>();
  auto fut = ready->get_future();

  boost::asio::post(impl->ioc.get_executor(), [impl, prm = std::move(ready),
                                               this]() mutable {
    try {
      auto resolver = std::make_shared<tcp::resolver>(impl->ioc);
      resolver->async_resolve(
          host_, std::to_string(port_),
          [impl, prm, resolver](const boost::system::error_code& ec,
                                tcp::resolver::results_type results) {
            if (ec) {
              Logger::print_error(
                  "FastProto",
                  std::format("[Client] resolve error: {}", ec.message())
                      .c_str());
              prm->set_value(false);
              return;
            }
            boost::asio::async_connect(
                impl->socket, results,
                [impl, prm](const boost::system::error_code& ec2,
                            const tcp::endpoint&) {
                  if (ec2) {
                    Logger::print_error(
                        "FastProto",
                        std::format("[Client] connect error: {}", ec2.message())
                            .c_str());
                    prm->set_value(false);
                    return;
                  }
                  Logger::print_debug("FastProto", "[Client] Connected");
                  impl->running.store(true, std::memory_order_release);
                  impl->start_read();
                  prm->set_value(true);
                });
          });
    } catch (const std::exception& e) {
      Logger::print_error(
          "FastProto", std::format("[Client] exception: {}", e.what()).c_str());
      prm->set_value(false);
    }
  });

  const bool ok = fut.get();
  if (!ok) {
    running_.store(false, std::memory_order_release);
    if (impl->io_thread && impl->io_thread->joinable()) {
      impl->ioc.stop();
      impl->io_thread->join();
      impl->io_thread.reset();
    }
  }
  return ok;
}

void TcpClient::disconnect() {
  Impl* impl = impl_.get();
  if (!running_.exchange(false, std::memory_order_acq_rel))
    return;

  boost::asio::post(impl->ioc.get_executor(), [impl]() { impl->close(); });
  impl->ioc.stop();

  if (impl->io_thread && impl->io_thread->joinable()) {
    impl->io_thread->join();
    impl->io_thread.reset();
  }
  Logger::print_debug("FastProto", "[Client] Disconnected");
}

bool TcpClient::send(const FastProto::Packet& pkt) const {
  Impl* impl = impl_.get();
  if (!impl->running.load(std::memory_order_acquire))
    return false;

  const auto payload = common::serialize_packet(pkt);
  const uint32_t nlen_host = static_cast<uint32_t>(payload.size());
  const uint32_t nlen_net = htonl(nlen_host);

  auto buf = std::make_shared<std::vector<uint8_t>>();
  buf->reserve(4 + payload.size());
  buf->insert(buf->end(), reinterpret_cast<const uint8_t*>(&nlen_net),
              reinterpret_cast<const uint8_t*>(&nlen_net) + 4);
  buf->insert(buf->end(), payload.begin(), payload.end());

  boost::asio::post(impl->ioc.get_executor(), [impl, buf]() {
    if (impl->socket.is_open())
      impl->enqueue_write(buf);
  });
  return true;
}

void TcpClient::set_message_handler(common::PacketHandlerFn fn) {
  handler_ = std::move(fn);
}

}
