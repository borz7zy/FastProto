#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>

#include <fast_proto/fast_proto.hxx>
#include <fast_proto/net/common.hxx>

namespace FastProto::net {

class TcpClient {
 public:
  explicit TcpClient(const std::string& host, uint16_t port);
  ~TcpClient();

  [[nodiscard]] bool connect();
  void disconnect();

  [[nodiscard]] bool send(const FastProto::Packet& pkt) const;

  void set_message_handler(common::PacketHandlerFn fn);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;

  std::string host_;
  uint16_t port_;
  std::atomic<bool> running_{false};
  common::PacketHandlerFn handler_;
};

}
