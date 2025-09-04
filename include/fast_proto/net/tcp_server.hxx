#pragma once

#include <atomic>
#include <cstdint>
#include <fast_proto/fast_proto.hxx>
#include <fast_proto/net/common.hxx>
#include <functional>
#include <memory>
#include <unordered_map>
#include <vector>

namespace FastProto::net {

class TcpServer {
 public:
  explicit TcpServer(std::uint16_t port);
  ~TcpServer();

  void register_handler(std::uint32_t opcode, common::PacketHandlerFn fn);
  void broadcast(const FastProto::Packet& packet);
  void multicast(const FastProto::Packet& packet,
                 const std::vector<std::intptr_t>& fds);


  void run();
  void stop();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;

  std::uint16_t port_;
  std::atomic<bool> running_{false};
  std::unordered_map<std::uint32_t, common::PacketHandlerFn> handlers_;
};

}