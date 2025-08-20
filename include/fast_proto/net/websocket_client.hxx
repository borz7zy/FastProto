#pragma once

#include <atomic>
#include <fast_proto/fast_proto.hxx>
#include <fast_proto/net/common.hxx>
#include <fast_proto/platform.hxx>
#include <functional>
#include <string>
#include <thread>

namespace FastProto::net {

class WebSocketClient {
public:
  explicit WebSocketClient(const std::string& host, uint16_t port);
  ~WebSocketClient();

  bool connect();
  void disconnect();

  bool send(const FastProto::Packet& pkt) const;

  void set_message_handler(common::PacketHandlerFn fn);

private:
  void listen_loop();

  std::string host_;
  uint16_t port_;
#ifdef _WIN32
  SOCKET sockfd_{INVALID_SOCKET};
#else
  int sockfd_{-1};
#endif

  std::atomic<bool> running_{false};
  std::thread listen_thread_;

  common::PacketHandlerFn handler_;
};

}
