#pragma once

#include <vector>
#include <string>
#include <functional>
#include <robin_hood.h>

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
};

struct UInt128 {
  uint64_t hi = 0;
  uint64_t lo = 0;

  static UInt128 from_u64(uint64_t v) {
    return {0, v};
  }
};

struct Arg {
  Type type_id{};
  std::vector<uint8_t> value;

  static Arg make_bool(bool b);
  static Arg make_int16(int16_t v);
  static Arg make_uint16(uint16_t v);
  static Arg make_int32(int32_t v);
  static Arg make_uint32(uint32_t v);
  static Arg make_int64(int64_t v);
  static Arg make_uint128(UInt128 v);
  static Arg make_float(float v);
  static Arg make_double(double v);
  static Arg make_string(const std::string& s);

  bool as_bool() const;
  int16_t as_int16() const;
  uint16_t as_uint16() const;
  int32_t as_int32() const;
  uint32_t as_uint32() const;
  int64_t as_int64() const;
  UInt128 as_uint128() const;
  float as_float() const;
  double as_double() const;
  std::string as_string() const;
};

struct Packet {
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
  robin_hood::unordered_map<uint32_t, HandlerFn> handlers;
};

}
