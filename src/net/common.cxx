#include <sys/types.h>
#include <fast_proto/net/common.hxx>
#include <fast_proto/platform.hxx>
#include <stdexcept>
#include <vector>

namespace FastProto::net::common {

namespace {
constexpr uint8_t kMagic[4] = {'F','P','N','1'};

inline void put_u8(std::vector<uint8_t>& out, uint8_t v) { out.push_back(v); }

inline void put_u32(std::vector<uint8_t>& out, uint32_t v) {
  out.push_back(static_cast<uint8_t>(v & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

inline uint32_t get_u32(const uint8_t*& p, const uint8_t* end) {
  if (end - p < 4) throw std::runtime_error("decode: truncated u32");
  const uint32_t v = static_cast<uint32_t>(p[0])        |
                    (static_cast<uint32_t>(p[1]) << 8)  |
                    (static_cast<uint32_t>(p[2]) << 16) |
                    (static_cast<uint32_t>(p[3]) << 24) ;
  p += 4;
  return v;
}
} // namespace

std::vector<uint8_t> serialize_packet(const FastProto::Packet& pkt) {
  std::vector<uint8_t> out;
  out.insert(out.end(), std::begin(kMagic), std::end(kMagic));
  put_u32(out, pkt.opcode);
  put_u32(out, pkt.flags);
  put_u32(out, static_cast<uint32_t>(pkt.args.size()));

  for (const auto& a : pkt.args) {
    put_u8(out, static_cast<uint8_t>(a.type_id));
    put_u32(out, static_cast<uint32_t>(a.value.size()));
    out.insert(out.end(), a.value.begin(), a.value.end());
  }
  return out;
}

bool deserialize_packet(const std::vector<uint8_t>& data, FastProto::Packet& pkt) {
  pkt = FastProto::Packet{};
  if (data.size() < 16) return false;

  const uint8_t* p = data.data();
  const uint8_t* end = data.data() + data.size();

  if (!(p[0]==kMagic[0] && p[1]==kMagic[1] && p[2]==kMagic[2] && p[3]==kMagic[3])) return false;
  p += 4;

  pkt.opcode = get_u32(p, end);
  pkt.flags = get_u32(p, end);
  const uint32_t argc = get_u32(p, end);
  pkt.args.reserve(argc);

  for (uint32_t i = 0; i < argc; ++i) {
    if (p >= end) return false;
    const auto type = static_cast<FastProto::Type>(*p++);
    const uint32_t len = get_u32(p, end);
    if (len > static_cast<uint32_t>(end - p)) return false;
    FastProto::Arg a;
    a.type_id = type;
    a.value.assign(p, p + len);
    p += len;
    pkt.args.push_back(std::move(a));
  }
  return p == end;
}

ssize_t send_all(int sockfd, const uint8_t* data, size_t len) {
  size_t off = 0;
  while (off < len) {
#ifdef _WIN32
    const ssize_t n = ::send(sockfd, reinterpret_cast<const char*>(data + off), static_cast<int>(len - off), 0);
#else
    const ssize_t n = ::send(sockfd, data + off, len - off, 0);
#endif
    if (n <= 0) return n;
    off += static_cast<size_t>(n);
  }
  return static_cast<ssize_t>(off);
}

ssize_t recv_all(int sockfd, uint8_t* data, size_t len) {
  size_t off = 0;
  while (off < len) {
#ifdef _WIN32
    const ssize_t n = ::recv(sockfd, reinterpret_cast<char*>(data + off), len - off, MSG_WAITALL);
#else
    const ssize_t n = ::recv(sockfd, data + off, len - off, MSG_WAITALL);
#endif
    if (n <= 0) return n;
    off += static_cast<size_t>(n);
  }
  return static_cast<ssize_t>(off);
}

}
