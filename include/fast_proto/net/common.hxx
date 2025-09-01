#pragma once

#include <fast_proto/fast_proto.hxx>
#include <fast_proto/platform.hxx>
#include <functional>
#include <vector>

namespace FastProto::net::common {

using PacketHandlerFn = std::function<void(const FastProto::Packet& req, FastProto::Packet& resp)>;

std::vector<uint8_t> serialize_packet(const FastProto::Packet& pkt);
bool deserialize_packet(const std::vector<uint8_t>& data, FastProto::Packet& pkt);

#ifdef _WIN32
static bool set_nonblock(SOCKET s, bool on = true);
int poll_writable(SOCKET s, int timeout_ms);
#else
static bool set_nonblock(int fd);
int poll_writable(auto s, int timeout_ms);
#endif

ssize_t send_all(int sockfd, const uint8_t* data, size_t len);
ssize_t recv_all(int sockfd, uint8_t* data, size_t len);

}
