#pragma once

#include <functional>
#include <vector>
#include <fast_proto/fast_proto.hxx>

namespace FastProto::net::common {

using PacketHandlerFn = std::function<void(const FastProto::Packet& req, FastProto::Packet& resp)>;

std::vector<uint8_t> serialize_packet(const FastProto::Packet& pkt);
bool deserialize_packet(const std::vector<uint8_t>& data, FastProto::Packet& pkt);

ssize_t send_all(int sockfd, const uint8_t* data, size_t len);
ssize_t recv_all(int sockfd, uint8_t* data, size_t len);

}
