#include <cstring>
#include <fast_proto/fast_proto.hxx>
#include <stdexcept>

namespace FastProto {

Arg Arg::make_bool(const bool& b) {
  Arg a;
  a.type_id = Type::Bool;
  a.value.push_back(static_cast<uint8_t>(b ? 1 : 0));
  return a;
}

Arg Arg::make_int16(const int16_t& v) {
  Arg a;
  a.type_id = Type::Int16;
  a.value.resize(sizeof(v));
  std::memcpy(a.value.data(), &v, sizeof(v));
  return a;
}

Arg Arg::make_uint16(const uint16_t& v) {
  Arg a;
  a.type_id = Type::UInt16;
  a.value.resize(sizeof(v));
  std::memcpy(a.value.data(), &v, sizeof(v));
  return a;
}

Arg Arg::make_int32(const int32_t& v) {
  Arg a;
  a.type_id = Type::Int32;
  a.value.resize(sizeof(v));
  std::memcpy(a.value.data(), &v, sizeof(v));
  return a;
}

Arg Arg::make_uint32(const uint32_t& v) {
  Arg a;
  a.type_id = Type::UInt32;
  a.value.resize(sizeof(v));
  std::memcpy(a.value.data(), &v, sizeof(v));
  return a;
}

Arg Arg::make_int64(const int64_t& v) {
  Arg a;
  a.type_id = Type::Int64;
  a.value.resize(sizeof(v));
  std::memcpy(a.value.data(), &v, sizeof(v));
  return a;
}

Arg Arg::make_uint128(const UInt128& v) {
  Arg a;
  a.type_id = Type::UInt128;
  a.value.resize(sizeof(v));
  std::memcpy(a.value.data(), &v, sizeof(v));
  return a;
}

Arg Arg::make_float(const float& v) {
  Arg a;
  a.type_id = Type::Float;
  a.value.resize(sizeof(v));
  std::memcpy(a.value.data(), &v, sizeof(v));
  return a;
}

Arg Arg::make_double(const double& v) {
  Arg a;
  a.type_id = Type::Double;
  a.value.resize(sizeof(v));
  std::memcpy(a.value.data(), &v, sizeof(v));
  return a;
}

Arg Arg::make_string(const std::string& s) {
  Arg a;
  a.type_id = Type::String;
  a.value.assign(s.begin(), s.end());
  return a;
}

bool Arg::as_bool() const {
  if (type_id != Type::Bool) throw std::runtime_error("Arg type mismatch: Bool");
  return value[0] != 0;
}

int16_t Arg::as_int16() const {
  if (type_id != Type::Int16) throw std::runtime_error("Arg type mismatch: Int16");
  int16_t v;
  std::memcpy(&v, value.data(), sizeof(v));
  return v;
}

uint16_t Arg::as_uint16() const {
  if (type_id != Type::UInt16) throw std::runtime_error("Arg type mismatch: UInt16");
  uint16_t v;
  std::memcpy(&v, value.data(), sizeof(v));
  return v;
}

int32_t Arg::as_int32() const {
  if (type_id != Type::Int32) throw std::runtime_error("Arg type mismatch: Int32");
  int32_t v;
  std::memcpy(&v, value.data(), sizeof(v));
  return v;
}

uint32_t Arg::as_uint32() const {
  if (type_id != Type::UInt32) throw std::runtime_error("Arg type mismatch: UInt32");
  uint32_t v;
  std::memcpy(&v, value.data(), sizeof(v));
  return v;
}

int64_t Arg::as_int64() const {
  if (type_id != Type::Int64) throw std::runtime_error("Arg type mismatch: Int64");
  int64_t v;
  std::memcpy(&v, value.data(), sizeof(v));
  return v;
}

UInt128 Arg::as_uint128() const {
  if (type_id != Type::UInt128) throw std::runtime_error("Arg type mismatch: UInt128");
  UInt128 v;
  std::memcpy(&v, value.data(), sizeof(v));
  return v;
}

float Arg::as_float() const {
  if (type_id != Type::Float) throw std::runtime_error("Arg type mismatch: Float");
  float v;
  std::memcpy(&v, value.data(), sizeof(v));
  return v;
}

double Arg::as_double() const {
  if (type_id != Type::Double) throw std::runtime_error("Arg type mismatch: Double");
  double v;
  std::memcpy(&v, value.data(), sizeof(v));
  return v;
}

std::string Arg::as_string() const {
  if (type_id != Type::String) throw std::runtime_error("Arg type mismatch: String");
  return { value.begin(), value.end() };
}

}
