#pragma once

#include <atomic>
#include <cstdint>
#include <fast_proto/net/common.hxx>
#include <fast_proto/net/socket_handle.hxx>
#include <fast_proto/platform.hxx>
#include <fast_proto/uint_128.hxx>
#include <fast_proto/utils/thread_pool.hxx>
#include <functional>
#include <mutex>
#include <stop_token>
#include <thread>
#include <unordered_map>
#include <vector>

namespace FastProto::net {

class TcpServer {
public:
  explicit TcpServer(uint16_t port);
  ~TcpServer();

  void register_handler(uint32_t opcode, common::PacketHandlerFn fn);
  void broadcast(const FastProto::Packet& packet);

  void run();
  void stop();

private:
  void handle_client(int client_fd, int client_id);

  uint16_t port_;
  std::atomic<bool> running_{false};
  std::mutex clients_mtx_;
  std::unordered_map<uint32_t, common::PacketHandlerFn> handlers_;
  std::vector<SocketHandle> client_fds_;
  std::atomic<std::uint64_t> next_client_id_{0ULL};
  SocketHandle server_fd_;

  ThreadPool pool_;
};

}
