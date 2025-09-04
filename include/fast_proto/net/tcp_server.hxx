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
  using DisconnectClientFn = std::function<void(std::intptr_t)>;
  using ConnectClientFn = std::function<void(std::intptr_t)>;

  explicit TcpServer(std::uint16_t port);
  ~TcpServer();

  void set_disconnect_handler(DisconnectClientFn fn);
  void set_connect_handler(ConnectClientFn fn);

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

  void notify_connect(std::intptr_t fd);
  ConnectClientFn on_connect_;
  void notify_disconnect(std::intptr_t fd);
  DisconnectClientFn on_disconnect_;
};

}