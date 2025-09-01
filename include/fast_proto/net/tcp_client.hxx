#pragma once

#include <atomic>
#include <fast_proto/fast_proto.hxx>
#include <fast_proto/net/common.hxx>
#include <fast_proto/net/socket_handle.hxx>
#include <fast_proto/platform.hxx>
#include <fast_proto/utils/thread_pool.hxx>
#include <functional>
#include <string>
#include <thread>

namespace FastProto::net {

class TcpClient {
public:
  explicit TcpClient(const std::string& host, uint16_t port);
  ~TcpClient();

  bool connect();
  void disconnect();

  bool send(const FastProto::Packet& pkt) const;

  void set_message_handler(common::PacketHandlerFn fn);

private:
  void listen_loop();

  std::string host_;
  uint16_t port_;
  SocketHandle sockfd_;

  std::atomic<bool> running_{false};
  std::thread listen_thread_;

  common::PacketHandlerFn handler_;

  ThreadPool pool_;
};

}
