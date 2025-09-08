#pragma once

#include <atomic>
#include <chrono>
#include <fast_proto/fast_proto.hxx>
#include <fast_proto/net/common.hxx>
#include <functional>
#include <memory>
#include <string>

namespace FastProto::net {

class TcpClient {
 public:
  explicit TcpClient(const std::string& host, uint16_t port);
  ~TcpClient();

  bool connect();
  void disconnect();

  bool send(const FastProto::Packet& pkt);

  void set_message_handler(common::PacketHandlerFn fn);

  void set_auto_reconnect(bool on);
  void set_reconnect_backoff(std::chrono::milliseconds min_ms,
                             std::chrono::milliseconds max_ms);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;

  std::string host_;
  uint16_t port_;
  std::atomic<bool> running_{false};
  common::PacketHandlerFn handler_;
};

}
