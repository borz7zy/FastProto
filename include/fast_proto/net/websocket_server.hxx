#pragma once

#include <atomic>
#include <fast_proto/net/common.hxx>
#include <fast_proto/platform.hxx>
#include <functional>
#include <mutex>
#include <robin_hood.h>
#include <thread>
#include <vector>

namespace FastProto::net {

class WebSocketServer {
public:
  explicit WebSocketServer(uint16_t port);
  ~WebSocketServer();

  void register_handler(uint32_t opcode, common::PacketHandlerFn fn);

  void run();
  void stop();

private:
  void handle_client(int client_fd, int client_id);

  uint16_t port_;
  std::atomic<bool> running_{false};
  std::mutex clients_mtx_;
  robin_hood::unordered_map<uint32_t, common::PacketHandlerFn> handlers_;
  std::vector<int> client_fds_;
  std::atomic<int> next_client_id_{0};
  std::vector<std::thread> client_threads_;
#ifdef _WIN32
  SOCKET server_fd_{INVALID_SOCKET};
#else
  int server_fd_{-1};
#endif
};

}
