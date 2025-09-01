#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fast_proto/logger.hxx>
#include <fast_proto/net/common.hxx>
#include <fast_proto/net/socket_handle.hxx>
#include <fast_proto/net/tcp_server.hxx>
#include <fast_proto/platform.hxx>
#include <format>
#include <sstream>
#include <stop_token>
#include <system_error>
#include <thread>

namespace FastProto::net {

TcpServer::TcpServer(uint16_t port) : port_(port), server_fd_(), pool_{} {
#ifdef _WIN32
  WSADATA wsa_data;
  const int wsa_err = WSAStartup(MAKEWORD(2, 2), &wsa_data);
  if (wsa_err != 0) {
    Logger::print_error("FastProto", std::format("WSAStartup failed: {}", wsa_err).c_str());
    running_.store(false, std::memory_order_release);

    return;
  }
#endif
}

TcpServer::~TcpServer() {
  stop();
}

void TcpServer::register_handler(uint32_t opcode, common::PacketHandlerFn fn) {
  handlers_[opcode] = std::move(fn);
}

void TcpServer::broadcast(const FastProto::Packet& packet) {
  auto out_buf = common::serialize_packet(packet);
  uint32_t out_nlen = htonl(static_cast<uint32_t>(out_buf.size()));

  std::vector<SocketHandle> clients_copy;
  {
    std::lock_guard<std::mutex> lk(clients_mtx_);
    clients_copy.resize(client_fds_.size());
    //clients_copy = client_fds_;
    memcpy(clients_copy.data(), client_fds_.data(),
           sizeof(SocketHandle) * client_fds_.size());
  }

  for (auto& client : clients_copy) {
    int fd = client.get();
    if (fd < 0)
      continue;

    if (common::send_all(fd, reinterpret_cast<const uint8_t*>(&out_nlen), sizeof(out_nlen)) <= 0)
      continue;
    
    if (common::send_all(fd, out_buf.data(), out_buf.size()) <= 0)
      continue;

  }
}

void TcpServer::run() {
  running_.store(true, std::memory_order_release);

#ifdef _WIN32
  SocketHandle srv(::socket(AF_INET, SOCK_STREAM, 0));
  if (!srv.valid()) {
    const int err = WSAGetLastError();
    //std::cerr << "[Server] socket error: " << err << "\n";
    Logger::print_error("FastProto", std::format("[Server] socket error: {}", err).c_str());
    running_.store(false, std::memory_order_release);
    return;
  }
#else
  SocketHandle srv(::socket(AF_INET, SOCK_STREAM, 0));
  if (!srv.valid()) {
    //std::perror("[Server] socket");
    std::error_code ec(errno, std::system_category());
    Logger::print_error("FastProto", std::format("[Server] socket error: ", ec.message()).c_str());
    running_.store(false, std::memory_order_release);
    return;
  }
#endif

  constexpr int opt = 1;
#ifdef _WIN32
  ::setsockopt(srv.get(), SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
  ::setsockopt(srv.get(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port_);

  if (::bind(srv.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    std::perror("[Server] bind");
    srv.reset();
    running_.store(false, std::memory_order_release);
    return;
  }

  if (::listen(srv.get(), 128) < 0) {
    std::perror("[Server] listen");
    srv.reset();
    running_.store(false, std::memory_order_release);
    return;
  }

  server_fd_ = std::move(srv);
  Logger::print_debug("FastProto", std::format("[Server] Listening on port {}", port_).c_str());

  while (running_.load(std::memory_order_acquire)) {
    sockaddr_in cli_addr{};
#ifdef _WIN32
    int cli_len = sizeof(cli_addr);
#else
    socklen_t cli_len = sizeof(cli_addr);
#endif

    SocketHandle client(::accept(
        server_fd_.get(), reinterpret_cast<sockaddr*>(&cli_addr), &cli_len));
    if (!client.valid()) {
#ifdef _WIN32
      int e = WSAGetLastError();
#else
      int e = errno;
#endif
      if (!running_.load(std::memory_order_acquire))
        break;

#ifdef _WIN32
      if (e == WSAEINTR || e == WSAEWOULDBLOCK) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        continue;
      }
#else
      if (e == EINTR)
        continue;
      if (e == EBADF)
        break;
      if (e == EAGAIN || e == EWOULDBLOCK) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        continue;
      }
      if (e == EMFILE || e == ENFILE) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        continue;
      }
#endif
      Logger::print_error("FastProto",
                          std::format("[Server] accept error: {} ({})",
                                      std::generic_category().message(e), e)
                              .c_str());

      std::this_thread::sleep_for(std::chrono::milliseconds(1));
      continue;
    }

    const unsigned long long int client_id =
        next_client_id_.fetch_add(1ULL, std::memory_order_relaxed);

    {
      std::lock_guard<std::mutex> lk(clients_mtx_);
      int raw_fd = client.get();
      client_fds_.push_back(std::move(client));

      pool_.submit([this, raw_fd, client_id]() {
        TcpServer::handle_client(raw_fd, client_id);
      });
    }

    Logger::print_debug("FastProto", std::format("[Server] Client connected: id={}", client_id).c_str());
  }

  server_fd_.reset();
}

void TcpServer::stop() {
  running_.store(false, std::memory_order_release);

  server_fd_.reset();

  std::vector<SocketHandle> clients;
  {
    std::lock_guard lk(clients_mtx_);
    clients.swap(client_fds_);
  }

#ifdef _WIN32
  WSACleanup();
#endif

  Logger::print_debug("FastProto", "[Server] Stopped");
}

void TcpServer::handle_client(int client_fd, int client_id) {
  constexpr uint32_t kMaxFrameLen = 32u * 1024u * 1024u;

  while (running_) {
    uint32_t nlen = 0;
    ssize_t r = common::recv_all(client_fd, reinterpret_cast<uint8_t*>(&nlen),
                                 sizeof(nlen));
    if (r <= 0)
      break;

    const uint32_t len = ntohl(nlen);
    if (len == 0 || len > kMaxFrameLen)
      break;

    std::vector<uint8_t> buf(len);
    r = common::recv_all(client_fd, buf.data(), len);
    if (r <= 0)
      break;

    FastProto::Packet req;
    if (!common::deserialize_packet(buf, req)) {
      std::ostringstream os;
      os << "[Server] Failed to deserialize packet"
         << " len=" << buf.size() << " magic=" << std::hex
         << static_cast<int>(buf[0]) << " " << static_cast<int>(buf[1])
         << " " << static_cast<int>(buf[2]) << " "
         << static_cast<int>(buf[3]) << std::dec;
      Logger::print_error("FastProto", os.str().c_str());
      break;
    }

    req.source_fd = client_fd;

    FastProto::Packet resp;
    auto it = handlers_.find(req.opcode);
    if (it != handlers_.end()) {
      it->second(req, resp);
    }

    auto out_buf = common::serialize_packet(resp);
    const auto out_len = static_cast<uint32_t>(out_buf.size());
    uint32_t out_nlen = htonl(out_len);

    if (common::send_all(client_fd, reinterpret_cast<const uint8_t*>(&out_nlen),
                         sizeof(out_nlen)) <= 0)
      break;
    if (common::send_all(client_fd, out_buf.data(), out_buf.size()) <= 0)
      break;
  }

  {
    std::lock_guard<std::mutex> lk(clients_mtx_);
    auto it = std::find_if(
        client_fds_.begin(), client_fds_.end(),
        [client_fd](const SocketHandle& h) { return h.get() == client_fd; });
    if (it != client_fds_.end()) {
      client_fds_.erase(it);
    }
  }

  Logger::print_debug("FastProto", std::format("[Server] Client disconnected: id={}", client_id).c_str());
}

}
