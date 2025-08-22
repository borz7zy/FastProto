#include <fast_proto/net/common.hxx>
#include <fast_proto/net/websocket_client.hxx>
#include <fast_proto/platform.hxx>
#include <iostream>
#include <utility>

namespace FastProto::net {

WebSocketClient::WebSocketClient(const std::string& host, uint16_t port)
    : host_(host), port_(port) {
#ifdef _WIN32
  WSADATA wsaData;
  int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (res != 0) {
    std::cerr << "WSAStartup failed: " << res << "\n";
  }
#endif
}

WebSocketClient::~WebSocketClient() {
  disconnect();
}

bool WebSocketClient::connect() {
  SocketHandle sock(::socket(AF_INET, SOCK_STREAM, 0));
  if (!sock.valid()) {
#ifdef _WIN32
    std::cerr << "[Client] socket error: " << WSAGetLastError() << "\n";
#else
    perror("[Client] socket");
#endif
    return false;
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port_);

#ifdef _WIN32
  if (InetPton(AF_INET, host_.c_str(), &addr.sin_addr) <= 0) {
    std::cerr << "[Client] inet_pton failed\n";
    return false;
  }
#else
  if (inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) <= 0) {
    perror("inet_pton");
    return false;
  }
#endif

  if (::connect(sock.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    perror("[Client] connect");
    return false;
  }

  sockfd_ = std::move(sock);
  running_ = true;
  listen_thread_ = std::thread(&WebSocketClient::listen_loop, this);

  std::cout << "[Client] Connected to " << host_ << ":" << port_ << "\n";
  return true;
}

void WebSocketClient::disconnect() {
  running_ = false;

  sockfd_.reset();

  if (listen_thread_.joinable()) {
    listen_thread_.join();
  }

#ifdef _WIN32
  WSACleanup();
#endif

  std::cout << "[Client] Disconnected\n";
}

bool WebSocketClient::send(const FastProto::Packet& pkt) const {
  if (!sockfd_.valid())
    return false;

  const auto buf = common::serialize_packet(pkt);
  const auto len = static_cast<uint32_t>(buf.size());
  const uint32_t nlen = htonl(len);

  if (common::send_all(sockfd_.get(), reinterpret_cast<const uint8_t*>(&nlen), sizeof(nlen)) <= 0)
    return false;

  if (common::send_all(sockfd_.get(), buf.data(), buf.size()) <= 0)
    return false;

  return true;
}


void WebSocketClient::set_message_handler(common::PacketHandlerFn fn) {
  handler_ = std::move(fn);
}

void WebSocketClient::listen_loop() {
  constexpr uint32_t kMaxFrameLen = 32u * 1024u * 1024u;

  while (running_ && sockfd_.valid()) {
    uint32_t nlen = 0;
    ssize_t r = common::recv_all(sockfd_.get(), reinterpret_cast<uint8_t*>(&nlen), sizeof(nlen));
    if (r <= 0)
      break;

    const uint32_t len = ntohl(nlen);
    if (len == 0 || len > kMaxFrameLen)
      break;

    std::vector<uint8_t> buf(len);
    r = common::recv_all(sockfd_.get(), buf.data(), len);
    if (r <= 0)
      break;

    FastProto::Packet pkt;
    if (!common::deserialize_packet(buf, pkt)) {
      std::cerr << "[Client] Failed to deserialize packet\n";
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
