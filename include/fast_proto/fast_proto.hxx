#pragma once

#include <fast_proto/uint_128.hxx>
#include <functional>
#include <unordered_map>
#include <string>
#include <vector>

namespace FastProto {

enum class Type : uint8_t {
  Bool,
  Int16,
  Int32,
  Int64,
  UInt16,
  UInt32,
  UInt128,
  String,
  Float,
  Double,
  Bytes,
};

struct Arg {
  Type type_id{};
  std::vector<uint8_t> value;

  static Arg make_bool(const bool& b);
  static Arg make_int16(const int16_t& v);
  static Arg make_uint16(const uint16_t& v);
  static Arg make_int32(const int32_t& v);
  static Arg make_uint32(const uint32_t& v);
  static Arg make_int64(const int64_t& v);
  static Arg make_uint128(const UInt128& v);
  static Arg make_float(const float& v);
  static Arg make_double(const double& v);
  static Arg make_string(const std::string& s);
  static Arg make_bytes(const std::vector<std::uint8_t>& data);

  [[nodiscard]] bool as_bool() const;
  [[nodiscard]] int16_t as_int16() const;
  [[nodiscard]] uint16_t as_uint16() const;
  [[nodiscard]] int32_t as_int32() const;
  [[nodiscard]] uint32_t as_uint32() const;
  [[nodiscard]] int64_t as_int64() const;
  [[nodiscard]] UInt128 as_uint128() const;
  [[nodiscard]] float as_float() const;
  [[nodiscard]] double as_double() const;
  [[nodiscard]] std::string as_string() const;
  [[nodiscard]] std::vector<std::uint8_t> as_bytes() const;
};

struct Packet {
  int source_fd;
  uint32_t opcode = 0;
  uint32_t flags = 0;
  std::vector<Arg> args;
};

using HandlerFn = std::function<void(const Packet& req, Packet& resp)>;

class EndpointRegistry {
public:
  void register_handler(uint32_t opcode, HandlerFn fn) {
    handlers[opcode] = std::move(fn);
  }

  bool dispatch(const Packet& req, Packet& resp) const {
    auto it = handlers.find(req.opcode);
    if (it == handlers.end()) return false;
    it->second(req, resp);
    return true;
  }
private:
  std::unordered_map<uint32_t, HandlerFn> handlers;
};

}
