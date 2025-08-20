#pragma once

#include <cassert>
#include <cstdint>
#include <ostream>
#include <random>
#include <string>

struct UInt128 {
  uint64_t hi = 0;
  uint64_t lo = 0;

  // --- ctors ---
  constexpr UInt128() = default;
  constexpr explicit UInt128(uint64_t low) : hi(0), lo(low) {}
  constexpr UInt128(uint64_t high, uint64_t low) : hi(high), lo(low) {}

  // --- helpers ---
  static constexpr UInt128 zero() { return {0, 0}; }
  static constexpr UInt128 one()  { return {0, 1}; }
  [[nodiscard]] constexpr bool isZero() const { return hi == 0 && lo == 0; }
  static UInt128 random_u128() {
    static thread_local std::mt19937_64 gen([]{
      std::random_device rd;
      uint64_t seed = (static_cast<uint64_t>(rd()) << 32) ^ rd();
      return std::mt19937_64(seed);
    }());
    std::uniform_int_distribution<uint64_t> dist;
    return { dist(gen), dist(gen) }; // {hi, lo}
  }
  static std::string u128_to_be(const UInt128& x) {
    std::string out(16, '\0');
    for (unsigned int i = 0; i < 8; ++i) {
      out[i]     = static_cast<char>((x.hi >> (8 * (7 - i))) & 0xFF);
      out[8 + i] = static_cast<char>((x.lo >> (8 * (7 - i))) & 0xFF);
    }
    return out;
  }

  // --- comparisons ---
  friend constexpr bool operator==(const UInt128& a, const UInt128& b) {
    return a.hi == b.hi && a.lo == b.lo;
  }
  friend constexpr bool operator!=(const UInt128& a, const UInt128& b) { return !(a == b); }
  friend constexpr bool operator<(const UInt128& a, const UInt128& b) {
    return (a.hi < b.hi) || (a.hi == b.hi && a.lo < b.lo);
  }
  friend constexpr bool operator>(const UInt128& a, const UInt128& b) { return b < a; }
  friend constexpr bool operator<=(const UInt128& a, const UInt128& b) { return !(b < a); }
  friend constexpr bool operator>=(const UInt128& a, const UInt128& b) { return !(a < b); }

  // --- bitwise ---
  friend constexpr UInt128 operator&(const UInt128& a, const UInt128& b) {
    return {a.hi & b.hi, a.lo & b.lo};
  }
  friend constexpr UInt128 operator|(const UInt128& a, const UInt128& b) {
    return {a.hi | b.hi, a.lo | b.lo};
  }
  friend constexpr UInt128 operator^(const UInt128& a, const UInt128& b) {
    return {a.hi ^ b.hi, a.lo ^ b.lo};
  }
  friend constexpr UInt128 operator~(const UInt128& a) { return {~a.hi, ~a.lo}; }

  UInt128& operator&=(const UInt128& r) { hi &= r.hi; lo &= r.lo; return *this; }
  UInt128& operator|=(const UInt128& r) { hi |= r.hi; lo |= r.lo; return *this; }
  UInt128& operator^=(const UInt128& r) { hi ^= r.hi; lo ^= r.lo; return *this; }

  // --- shifts ---
  friend constexpr UInt128 operator<<(const UInt128& a, const unsigned int s) {
    if (s >= 128) return UInt128::zero();
    if (s == 0)   return a;
    if (s >= 64)  return {a.lo << (s - 64), 0};
    // 0 < s < 64
    return {(a.hi << s) | (a.lo >> (64 - s)), a.lo << s};
  }
  friend constexpr UInt128 operator>>(const UInt128& a, const unsigned int s) {
    if (s >= 128) return UInt128::zero();
    if (s == 0)   return a;
    if (s >= 64)  return {0, a.hi >> (s - 64)};
    // 0 < s < 64
    return {a.hi >> s, (a.lo >> s) | (a.hi << (64 - s))};
  }
  UInt128& operator<<=(unsigned s) { return *this = (*this) << s; }
  UInt128& operator>>=(unsigned s) { return *this = (*this) >> s; }

  // --- addition / subtraction ---
  friend constexpr UInt128 operator+(const UInt128& a, const UInt128& b) {
    UInt128 r;
    r.lo = a.lo + b.lo;
    r.hi = a.hi + b.hi + (r.lo < a.lo ? 1 : 0);
    return r;
  }
  friend constexpr UInt128 operator-(const UInt128& a, const UInt128& b) {
    UInt128 r;
    r.lo = a.lo - b.lo;
    r.hi = a.hi - b.hi - (a.lo < b.lo ? 1 : 0);
    return r;
  }
  UInt128& operator+=(const UInt128& r) { return *this = *this + r; }
  UInt128& operator-=(const UInt128& r) { return *this = *this - r; }

  static inline void mul64(const uint64_t u, const uint64_t v, uint64_t& hi_out, uint64_t& lo_out) {
    const uint64_t u1 = u >> 32;
    const uint64_t u0 = u & 0xffffffffu;
    const uint64_t v1 = v >> 32;
    const uint64_t v0 = v & 0xffffffffu;

    const uint64_t w0 = u0 * v0;
    uint64_t       t  = u1 * v0 + (w0 >> 32);
    const uint64_t w1 = t & 0xffffffffu;
    const uint64_t w2 = t >> 32;

    t = u0 * v1 + w1;
    const uint64_t lo = (t << 32) | (w0 & 0xffffffffu);
    const uint64_t hi = u1 * v1 + w2 + (t >> 32);

    hi_out = hi;
    lo_out = lo;
  }

  friend inline UInt128 operator*(const UInt128& a, const UInt128& b) {
    uint64_t p0_hi, p0_lo; mul64(a.lo, b.lo, p0_hi, p0_lo); // al*bl
    uint64_t p1_hi, p1_lo; mul64(a.lo, b.hi, p1_hi, p1_lo); // al*bh
    uint64_t p2_hi, p2_lo; mul64(a.hi, b.lo, p2_hi, p2_lo); // ah*bl

    UInt128 r;
    r.lo = p0_lo;

    uint64_t p0Hi = p0_hi;
    uint64_t old = p0Hi;
    p0Hi += p1_lo;
    (void)old;
    old = p0Hi;
    p0Hi += p2_lo;
    (void)old;

    r.hi = p0Hi;
    return r;
  }
  UInt128& operator*=(const UInt128& r) { return *this = *this * r; }

  static inline std::pair<UInt128, UInt128> divmod(UInt128 n, const UInt128 d) {
    assert(!d.isZero() && "division by zero");
    if (n < d) return { UInt128::zero(), n };
    if (d.hi == 0 && d.lo == 1) return { n, UInt128::zero() };

    UInt128 q = UInt128::zero();
    UInt128 r = UInt128::zero();

    for (int i = 127; i >= 0; --i) {
      // r = (r << 1) | bit(n, i)
      r <<= 1;
      const uint64_t bit = n.getBit(i);
      r.lo |= bit;

      if (r >= d) {
        r -= d;
        q.setBit(i);
      }
    }
    return { q, r };
  }

  friend inline UInt128 operator/(const UInt128& a, const UInt128& b) {
    return divmod(a, b).first;
  }
  friend inline UInt128 operator%(const UInt128& a, const UInt128& b) {
    return divmod(a, b).second;
  }
  UInt128& operator/=(const UInt128& r) { return *this = *this / r; }
  UInt128& operator%=(const UInt128& r) { return *this = *this % r; }

  [[nodiscard]] constexpr uint64_t getBit(const int idx) const {
    return (idx < 64) ? ((lo >> idx) & 1u)
                      : ((hi >> (idx - 64)) & 1u);
  }
  inline void setBit(const int idx) {
    if (idx < 64) lo |= (static_cast<uint64_t>(1) << idx);
    else          hi |= (static_cast<uint64_t>(1) << (idx - 64));
  }

  [[nodiscard]] std::string to_hex() const {
    static auto kHex = "0123456789abcdef";
    std::string s(32, '0');
    UInt128 t = *this;
    for (int i = 31; i >= 0; --i) {
      s[static_cast<unsigned int>(i)] = kHex[static_cast<uint8_t>(t.lo & 0xF)];
      t >>= 4;
    }

    const auto pos = s.find_first_not_of('0');
    return pos == std::string::npos ? "0" : s.substr(pos);
  }
};

inline std::ostream& operator<<(std::ostream& os, const UInt128& v) {
  return os << v.to_hex();
}