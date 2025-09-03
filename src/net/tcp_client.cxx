#include <fast_proto/logger.hxx>
#include <fast_proto/net/common.hxx>
#include <fast_proto/net/tcp_client.hxx>
#include <fast_proto/platform.hxx>
#include <format>
#include <system_error>
#include <thread>
#include <utility>

namespace FastProto::net {

TcpClient::TcpClient(const std::string& host, uint16_t port)
    : host_(host), port_(port), pool_{} {
#ifdef _WIN32
  WSADATA wsaData;
  int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (res != 0) {
    Logger::print_error("FastProto", std::format("[Client] WSAStartup failed: {}", res).c_str());
  }
#endif
}

TcpClient::~TcpClient() {
  disconnect();
}

bool TcpClient::connect() {
  SocketHandle sock(::socket(AF_INET, SOCK_STREAM, 0));
  if (!sock.valid()) {
#ifdef _WIN32
    Logger::print_error(
        "FastProto",
        std::format("[Client] socket error: {}", WSAGetLastError()).c_str());
#else
    std::error_code ec(errno, std::system_category());
    Logger::print_error(
        "FastProto",
        std::format("[Client] socket error: {}", ec.message()).c_str());
#endif
    return false;
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port_);

#ifdef _WIN32
  if (InetPton(AF_INET, host_.c_str(), &addr.sin_addr) <= 0) {
    Logger::print_error("FastProto", "[Client] inet_pton failed");
    return false;
  }
#else
  if (inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) <= 0) {
    perror("inet_pton");
    return false;
  }
#endif

  if (::connect(sock.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    std::error_code ec(errno, std::system_category());
    Logger::print_error(
        "FastProto",
        std::format("[Client] connect error: {}", ec.message()).c_str());
    return false;
  }

  sockfd_ = std::move(sock);
  running_ = true;
  pool_.submit([this]() { listen_loop(); });

  Logger::print_debug(
      "FastProto",
      std::format("[Client] Connected to {}:{}", host_, port_).c_str());
  return true;
}

void TcpClient::disconnect() {
  running_ = false;

  sockfd_.reset();

#ifdef _WIN32
  WSACleanup();
#endif

  Logger::print_debug("FastProto", "[Client] Disconnected");
}

bool TcpClient::send(const FastProto::Packet& pkt) const {
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


void TcpClient::set_message_handler(common::PacketHandlerFn fn) {
  handler_ = std::move(fn);
}

void TcpClient::listen_loop() {
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
      Logger::print_error("FastProto", "[Client] Failed to deserialize packet");
      break;
    }

if (handler_) {
      // const FastProto::Packet pkt_copy = pkt;
      pool_.submit([this, pkt]() mutable {
        FastProto::Packet resp; // dummy
        handler_(pkt, resp);
      });
    }
  }

  running_ = false;
}

}
