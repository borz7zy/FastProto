#include <fast_proto/net/websocket_server.hxx>
#include <fast_proto/net/common.hxx>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

namespace FastProto::net {

WebSocketServer::WebSocketServer(uint16_t port) : port_(port) {}

WebSocketServer::~WebSocketServer() {
  stop();
}

void WebSocketServer::register_handler(uint32_t opcode, common::PacketHandlerFn fn) {
  handlers_[opcode] = std::move(fn);
}

void WebSocketServer::run() {
  running_.store(true, std::memory_order_release);

  server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd_ < 0) {
    std::perror("[Server] socket");
    running_.store(false, std::memory_order_release);
    return;
  }

  int opt = 1;
  ::setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in addr{};
  addr.sin_family       = AF_INET;
  addr.sin_addr.s_addr  = (INADDR_ANY);
  addr.sin_port         = htons(port_);

  if (::bind(server_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    std::perror("[Server] bind");
    ::close(server_fd_);
    server_fd_ = -1;
    running_.store(false, std::memory_order_release);
    return;
  }

  if (::listen(server_fd_, 128) < 0) {
    std::perror("[Server] listen");
    ::close(server_fd_);
    server_fd_ = -1;
    running_.store(false, std::memory_order_release);
    return;
  }

  std::cout << "[Server] Listening on port " << port_ << std::endl;

  while (running_.load(std::memory_order_acquire)) {
    sockaddr_in cli_addr{};
    socklen_t cli_len = sizeof(cli_addr);

    auto client_fd = ::accept(server_fd_, reinterpret_cast<sockaddr*>(&cli_addr), &cli_len);
    if (client_fd < 0) {
      int e = errno;

      if (!running_.load(std::memory_order_acquire)) break;

      if(e == EINTR)
        continue;

      if(e == EBADF)
        break;

      if(e == EAGAIN || e == EWOULDBLOCK){
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        continue;
      }

      if (e == EMFILE || e == ENFILE) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        continue;
      }

      std::cerr << "[Server] accept error: " << std::strerror(e) << std::endl;
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
      continue;
    }

    const int client_id = next_client_id_.fetch_add(1, std::memory_order_relaxed);
    {
      std::lock_guard<std::mutex> lk(clients_mtx_);
      client_fds_.push_back(client_fd);
      client_threads_.emplace_back(&WebSocketServer::handle_client, this, client_fd, client_id);
    }

    std::cout << "[Server] Client connected: fd=" << client_fd << std::endl;
  }
  if (server_fd_ >= 0) {
    ::close(server_fd_);
    server_fd_ = -1;
  }
}

void WebSocketServer::stop() {
  running_.store(false, std::memory_order_release);

  int fd = server_fd_;
  if (fd >= 0) {
    ::shutdown(fd, SHUT_RDWR);
    ::close(fd);
    server_fd_ = -1;
  }

  std::vector<int> fds;
  {
    std::lock_guard lk(clients_mtx_);
    fds.swap(client_fds_);
  }
  for (int fd : fds) {
    ::shutdown(fd, SHUT_RDWR);
    ::close(fd);
  }
  for (auto& t : client_threads_) if (t.joinable()) t.join();
  client_threads_.clear();

  std::cout << "[Server] Stopped" << std::endl;
}

void WebSocketServer::handle_client(int client_fd, int client_id) {
  constexpr uint32_t kMaxFrameLen = 32u * 1024u * 1024u;

  while (running_) {
    uint32_t nlen = 0;
    ssize_t r = common::recv_all(client_fd, reinterpret_cast<uint8_t*>(&nlen), sizeof(nlen));
    if (r <= 0) break;

    const uint32_t len = ntohl(nlen);
    if (len == 0 || len > kMaxFrameLen) break;

    std::vector<uint8_t> buf(len);
    r = common::recv_all(client_fd, buf.data(), len);
    if (r <= 0) break;

    FastProto::Packet req;
    if (!common::deserialize_packet(buf, req)) {
      std::cerr << "[Server] Failed to deserialize packet"
                << " len=" << buf.size()
                << " magic="
                << std::hex
                << static_cast<int>(buf[0]) << " "
                << static_cast<int>(buf[1]) << " "
                << static_cast<int>(buf[2]) << " "
                << static_cast<int>(buf[3])
                << std::dec << std::endl;
      break;
    }

    FastProto::Packet resp;
    auto it = handlers_.find(req.opcode);
    if (it != handlers_.end()) {
      it->second(req, resp);
    }

    auto out_buf = common::serialize_packet(resp);
    uint32_t out_len = static_cast<uint32_t>(out_buf.size());
    uint32_t out_nlen = htonl(out_len);

    if (common::send_all(client_fd, reinterpret_cast<const uint8_t*>(&out_nlen), sizeof(out_nlen)) <= 0) break;
    if (common::send_all(client_fd, out_buf.data(), out_buf.size()) <= 0) break;
  }

  close(client_fd);
  std::cout << "[Server] Client disconnected: id=" << client_id << std::endl;
}


}
