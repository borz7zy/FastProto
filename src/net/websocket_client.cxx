#include <fast_proto/net/websocket_client.hxx>
#include <fast_proto/net/common.hxx>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

namespace FastProto::net {

WebSocketClient::WebSocketClient(const std::string& host, uint16_t port)
    : host_(host), port_(port) {}

WebSocketClient::~WebSocketClient() {
  running_ = false;
  if (sockfd_ >= 0) {
    ::shutdown(sockfd_, SHUT_RDWR);
    ::close(sockfd_);
    sockfd_ = -1;
  }
  if (listen_thread_.joinable()) {
    listen_thread_.join();
  }
}

bool WebSocketClient::connect() {
  sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd_ < 0) {
    perror("socket");
    return false;
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port_);

  if (inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) <= 0) {
    perror("inet_pton");
    close(sockfd_);
    return false;
  }

  if (::connect(sockfd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    perror("connect");
    close(sockfd_);
    return false;
  }

  running_ = true;
  listen_thread_ = std::thread(&WebSocketClient::listen_loop, this);

  std::cout << "[Client] Connected to " << host_ << ":" << port_ << std::endl;
  return true;
}

void WebSocketClient::disconnect() {
  running_ = false;
  if (sockfd_ >= 0) {
    ::shutdown(sockfd_, SHUT_RDWR);
    ::close(sockfd_);
    sockfd_ = -1;
  }
  if (listen_thread_.joinable()) {
    listen_thread_.join();
  }

  std::cout << "[Client] Disconnected" << std::endl;
}

bool WebSocketClient::send(const FastProto::Packet& pkt) const {
  if (sockfd_ < 0) return false;

  const auto buf = common::serialize_packet(pkt);
  const uint32_t len = static_cast<uint32_t>(buf.size());
  const uint32_t nlen = htonl(len);

  if (common::send_all(sockfd_, reinterpret_cast<const uint8_t*>(&nlen), sizeof(nlen)) <= 0)
    return false;
  if (common::send_all(sockfd_, buf.data(), buf.size()) <= 0)
    return false;

  return true;
}


void WebSocketClient::set_message_handler(common::PacketHandlerFn fn) {
    handler_ = std::move(fn);
}

void WebSocketClient::listen_loop() {
  constexpr uint32_t kMaxFrameLen = 32u * 1024u * 1024u;

  while (running_) {
    uint32_t nlen = 0;
    ssize_t r = common::recv_all(sockfd_, reinterpret_cast<uint8_t*>(&nlen), sizeof(nlen));
    if (r <= 0) break;

    const uint32_t len = ntohl(nlen);
    if (len == 0 || len > kMaxFrameLen) break;

    std::vector<uint8_t> buf(len);
    r = common::recv_all(sockfd_, buf.data(), len);
    if (r <= 0) break;

    FastProto::Packet pkt;
    if (!common::deserialize_packet(buf, pkt)) {
      std::cerr << "[Client] Failed to deserialize packet" << std::endl;
      break;
    }

    if (handler_) {
      FastProto::Packet resp;
      handler_(pkt, resp);
    }
  }

  running_ = false;
}

}
