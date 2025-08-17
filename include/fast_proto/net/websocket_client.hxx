#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <functional>

#include <fast_proto/fast_proto.hxx>
#include <fast_proto/net/common.hxx>

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
  int sockfd_{-1};

  std::atomic<bool> running_{false};
  std::thread listen_thread_;

  common::PacketHandlerFn handler_;
};

}
