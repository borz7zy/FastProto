#include <gtest/gtest.h>
#include <chrono>
#include <cstring>
#include <fast_proto/crypto/crypto.hxx>
#include <fast_proto/fast_proto.hxx>
#include <fast_proto/net/common.hxx>
#include <fast_proto/net/websocket_client.hxx>
#include <fast_proto/net/websocket_server.hxx>
#include <fast_proto/uint_128.hxx>
#include <future>
#include <thread>
#include <random>

using namespace FastProto;

static inline UInt128 make128(uint64_t hi, uint64_t lo) { return { hi, lo }; }
static inline std::pair<uint64_t,uint64_t> split128_hex(const std::string& hex_no0x) {
  std::string s = hex_no0x;
  if (s.size() > 32) s = s.substr(s.size()-32);
  while (s.size() < 32) s = "0" + s;
  auto hi_str = s.substr(0, 16);
  auto lo_str = s.substr(16);
  uint64_t hi = std::stoull(hi_str, nullptr, 16);
  uint64_t lo = std::stoull(lo_str, nullptr, 16);
  return {hi, lo};
}

// ========== Arg Tests ==========

TEST(ArgTest, BoolRoundTrip) {
  auto a = Arg::make_bool(true);
  EXPECT_EQ(a.as_bool(), true);

  auto b = Arg::make_bool(false);
  EXPECT_EQ(b.as_bool(), false);
}

TEST(ArgTest, Int32RoundTrip) {
  int32_t v = -12345;
  auto a = Arg::make_int32(v);
  EXPECT_EQ(a.as_int32(), v);
}

TEST(ArgTest, Int64RoundTrip) {
  int64_t v = 9876543210LL;
  auto a = Arg::make_int64(v);
  EXPECT_EQ(a.as_int64(), v);
}

TEST(ArgTest, UInt128RoundTrip) {
  UInt128 u{0x1122334455667788ULL, 0x99AABBCCDDEEFF00ULL};
  auto a = Arg::make_uint128(u);
  auto out = a.as_uint128();
  EXPECT_EQ(out.hi, u.hi);
  EXPECT_EQ(out.lo, u.lo);
}

TEST(ArgTest, StringRoundTrip) {
  std::string s = "hello world";
  auto a = Arg::make_string(s);
  EXPECT_EQ(a.as_string(), s);
}

TEST(ArgTest, UInt32RoundTrip) {
  uint32_t v = 0xDEADBEEF;
  auto a = Arg::make_uint32(v);
  EXPECT_EQ(a.as_uint32(), v);
}

TEST(ArgTest, Int16RoundTrip) {
  int16_t v = -1234;
  auto a = Arg::make_int16(v);
  EXPECT_EQ(a.as_int16(), v);
}

TEST(ArgTest, UInt16RoundTrip) {
  uint16_t v = 5678;
  auto a = Arg::make_uint16(v);
  EXPECT_EQ(a.as_uint16(), v);
}

TEST(ArgTest, FloatRoundTrip) {
  float f = 3.1415926f;
  auto a = Arg::make_float(f);
  EXPECT_FLOAT_EQ(a.as_float(), f);
}

TEST(ArgTest, DoubleRoundTrip) {
  double d = 2.718281828;
  auto a = Arg::make_double(d);
  EXPECT_DOUBLE_EQ(a.as_double(), d);
}

TEST(ArgTest, EmptyStringRoundTrip) {
  auto a = Arg::make_string("");
  EXPECT_EQ(a.as_string(), "");
}

// ========== Packet Tests ==========

TEST(PacketTest, ConstructPacket) {
  Packet pkt;
  pkt.opcode = 1001;
  pkt.flags = 0x42;
  pkt.args.push_back(Arg::make_int32(123));

  EXPECT_EQ(pkt.opcode, 1001);
  EXPECT_EQ(pkt.flags, 0x42);
  EXPECT_EQ(pkt.args.size(), 1);
  EXPECT_EQ(pkt.args[0].as_int32(), 123);
}

TEST(PacketTest, RoundTripAllArgTypes) {
  Packet p;
  p.opcode = 0x12345678;
  p.flags = 0xCAFEBABE;

  p.args.push_back(Arg::make_bool(true));
  p.args.push_back(Arg::make_int32(-42));
  p.args.push_back(Arg::make_uint32(42));
  p.args.push_back(Arg::make_float(1.5f));
  p.args.push_back(Arg::make_double(2.5));
  p.args.push_back(Arg::make_string("тест"));

  auto bytes = net::common::serialize_packet(p);

  Packet q;
  ASSERT_TRUE(net::common::deserialize_packet(bytes, q));
  EXPECT_EQ(q.opcode, p.opcode);
  EXPECT_EQ(q.flags, p.flags);
  ASSERT_EQ(q.args.size(), p.args.size());
  EXPECT_EQ(q.args[0].as_bool(), true);
  EXPECT_EQ(q.args[1].as_int32(), -42);
  EXPECT_EQ(q.args[2].as_uint32(), 42u);
  EXPECT_FLOAT_EQ(q.args[3].as_float(), 1.5f);
  EXPECT_DOUBLE_EQ(q.args[4].as_double(), 2.5);
  EXPECT_EQ(q.args[5].as_string(), "тест");
}

// ========== EndpointRegistry Tests ==========

TEST(RegistryTest, DispatchHandler) {
  EndpointRegistry reg;

  reg.register_handler(1001, [](const Packet& req, Packet& resp) {
    int32_t v = req.args[0].as_int32();
    resp.opcode = 2001;
    resp.args.push_back(Arg::make_int32(v * 2));
  });

  Packet req;
  req.opcode = 1001;
  req.args.push_back(Arg::make_int32(21));

  Packet resp;
  bool handled = reg.dispatch(req, resp);

  EXPECT_TRUE(handled);
  EXPECT_EQ(resp.opcode, 2001);
  EXPECT_EQ(resp.args.size(), 1);
  EXPECT_EQ(resp.args[0].as_int32(), 42);
}

TEST(RegistryTest, UnknownOpcode) {
  EndpointRegistry reg;

  Packet req;
  req.opcode = 9999;

  Packet resp;
  bool handled = reg.dispatch(req, resp);

  EXPECT_FALSE(handled);
  EXPECT_TRUE(resp.args.empty());
}

// ========== Crypto Tests ==========

using namespace FastProto::crypto;

TEST(CryptoTest, LargePayload) {
  SymKey key{};
  ASSERT_TRUE(random_bytes(key.bytes, sizeof(key.bytes)));

  std::vector<uint8_t> payload(1024 * 1024); // 1MB
  ASSERT_TRUE(random_bytes(payload.data(), payload.size()));

  Frame frame;
  ASSERT_TRUE(encrypt_aead_gcm(key, Alg::AES_256_GCM, payload.data(), payload.size(), frame));

  std::vector<uint8_t> decrypted;
  ASSERT_TRUE(decrypt_aead_gcm(key, frame.bytes.data(), frame.bytes.size(), decrypted));
  EXPECT_EQ(decrypted.size(), payload.size());
  EXPECT_EQ(memcmp(decrypted.data(), payload.data(), payload.size()), 0);
}

TEST(CryptoTest, EncryptDecryptRoundTrip) {
  SymKey key{};
  for (int i = 0; i < 32; i++) key.bytes[i] = static_cast<uint8_t>(i);

  const char* msg = "secret payload 123";
  Frame frame;
  ASSERT_TRUE(encrypt_aead_gcm(key, Alg::AES_256_GCM,
                               reinterpret_cast<const uint8_t*>(msg), strlen(msg),
                               frame));

  std::vector<uint8_t> out;
  ASSERT_TRUE(decrypt_aead_gcm(key, frame.bytes.data(), frame.bytes.size(), out));

  std::string recovered(reinterpret_cast<char*>(out.data()), out.size());
  EXPECT_EQ(recovered, msg);
}

TEST(CryptoTest, TamperDetection) {
  SymKey key{};
  for (int i = 0; i < 32; i++) key.bytes[i] = static_cast<uint8_t>(i);

  const char* msg = "integrity check";
  Frame frame;
  ASSERT_TRUE(encrypt_aead_gcm(key, Alg::AES_256_GCM,
                               reinterpret_cast<const uint8_t*>(msg), strlen(msg),
                               frame));

  ASSERT_FALSE(frame.bytes.empty());
  frame.bytes.back() ^= 0xFF;

  std::vector<uint8_t> out;
  EXPECT_FALSE(decrypt_aead_gcm(key, frame.bytes.data(), frame.bytes.size(), out));
}

TEST(CryptoTest, WrongKeyFails) {
  SymKey key1{}, key2{};
  for (int i = 0; i < 32; i++) key1.bytes[i] = static_cast<uint8_t>(i);
  for (int i = 0; i < 32; i++) key2.bytes[i] = static_cast<uint8_t>(i+1); // другой ключ

  const char* msg = "top secret";
  Frame frame;
  ASSERT_TRUE(encrypt_aead_gcm(key1, Alg::AES_256_GCM,
                               reinterpret_cast<const uint8_t*>(msg), strlen(msg),
                               frame));

  std::vector<uint8_t> out;
  EXPECT_FALSE(decrypt_aead_gcm(key2, frame.bytes.data(), frame.bytes.size(), out));
}

TEST(CryptoTest, EmptyPlaintext) {
  SymKey key{};
  for (int i = 0; i < 32; i++) key.bytes[i] = static_cast<uint8_t>(i);

  Frame frame;
  ASSERT_TRUE(encrypt_aead_gcm(key, Alg::AES_256_GCM, nullptr, 0, frame));

  std::vector<uint8_t> out;
  ASSERT_TRUE(decrypt_aead_gcm(key, frame.bytes.data(), frame.bytes.size(), out));
  EXPECT_TRUE(out.empty());
}

TEST(CryptoTest, Aes256Gcm) {
  using namespace FastProto::crypto;
  SymKey k{}; ASSERT_TRUE(random_bytes(k.bytes, sizeof(k.bytes)));
  const char* msg = "hello";
  Frame f;
  ASSERT_TRUE(encrypt_aead_gcm(k, Alg::AES_256_GCM, reinterpret_cast<const uint8_t*>(msg), 5, f));
  std::vector<uint8_t> pt;
  ASSERT_TRUE(decrypt_aead_gcm(k, f.bytes.data(), f.bytes.size(), pt));
  EXPECT_EQ(std::string(pt.begin(), pt.end()), "hello");

  // tamper: flip last byte
  f.bytes.back() ^= 0x01;
  std::vector<uint8_t> bad;
  EXPECT_FALSE(decrypt_aead_gcm(k, f.bytes.data(), f.bytes.size(), bad));
}

TEST(PacketTest, RoundTrip) {
  Packet p;
  p.opcode = 0xAABBCCDD;
  p.flags = 0x11223344;
  p.args.push_back(Arg::make_int32(-7));
  p.args.push_back(Arg::make_string("привет"));
  auto bytes = net::common::serialize_packet(p);

  Packet q;
  ASSERT_TRUE(net::common::deserialize_packet(bytes, q));
  EXPECT_EQ(q.opcode, p.opcode);
  EXPECT_EQ(q.flags, p.flags);
  EXPECT_EQ(p.args.size(), p.args.size());
}

// ===== Network Tests =====

TEST(NetworkTest, ServerClientEcho) {
  constexpr uint16_t port = 9002;

  net::WebSocketServer ws_server(port);
  net::WebSocketClient ws_client("127.0.0.1", port);

  ws_server.register_handler(0x1234, [](const Packet& req, Packet& resp) {
    resp.opcode = req.opcode;
    resp.args = req.args;
  });

  std::thread server_thread([&]() { ws_server.run(); });

  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  ASSERT_TRUE(ws_client.connect());

  Packet req;
  req.opcode = 0x1234;
  req.args.push_back(Arg::make_string("hello"));

  ASSERT_TRUE(ws_client.send(req));

  std::promise<Packet> resp_promise;
  auto resp_future = resp_promise.get_future();

  ws_client.set_message_handler([&](const Packet& pkt, Packet& /*ignored*/) {
    resp_promise.set_value(pkt);
  });

  auto status = resp_future.wait_for(std::chrono::seconds(1));
  ASSERT_EQ(status, std::future_status::ready);

  Packet resp = resp_future.get();
  EXPECT_EQ(resp.opcode, req.opcode);
  ASSERT_EQ(resp.args.size(), 1);
  EXPECT_EQ(resp.args[0].as_string(), "hello");

  ws_client.disconnect();
  ws_server.stop();

  server_thread.join();
}

// ===== UInt128 =====
TEST(UInt128_Basics, CtorsAndComparisons) {
  UInt128 z;
  EXPECT_EQ(z.hi, 0u);
  EXPECT_EQ(z.lo, 0u);
  UInt128 a(123u);
  EXPECT_EQ(a.hi, 0u);
  EXPECT_EQ(a.lo, 123u);
  UInt128 b(5u, 6u);
  EXPECT_TRUE(b > a);
  EXPECT_TRUE(a < b);
  EXPECT_TRUE(a != b);
  EXPECT_TRUE(b == make128(5u, 6u));
  EXPECT_TRUE(make128(1,0) > make128(0,~0ull));
  EXPECT_TRUE(make128(7,0) >= make128(7,0));
  EXPECT_TRUE(make128(7,0) <= make128(7,0));
}

TEST(UInt128_Bitwise, AndOrXorNot) {
  auto a = make128(0x00FF00FF00FF00FFull, 0xAA55AA55AA55AA55ull);
  auto b = make128(0x0F0F0F0F0F0F0F0Full, 0xFFFF0000FFFF0000ull);
  EXPECT_EQ((a & b), make128(0x000F000F000F000Full, 0xAA550000AA550000ull));
  EXPECT_EQ((a | b), make128(0x0FFF0FFF0FFF0FFFull, 0xFFFFAA55FFFFAA55ull));
  EXPECT_EQ((a ^ b), make128(0x0FF00FF00FF00FF0ull, 0x55AAAA5555AAAA55ull));
  EXPECT_EQ((~UInt128{0,0}), make128(~0ull, ~0ull));
}

TEST(UInt128_Shifts, LeftRight) {
  auto one = make128(0,1);
  EXPECT_EQ(one << 0, one);
  EXPECT_EQ(one << 1, make128(0, 2));
  EXPECT_EQ(one << 63, make128(0, 1ull<<63));
  EXPECT_EQ(one << 64, make128(1, 0));
  EXPECT_EQ(one << 65, make128(2, 0));
  EXPECT_EQ(one << 127, make128(1ull<<63, 0));
  EXPECT_EQ(one << 128, UInt128::zero());

  auto top = make128(1ull<<63, 0);
  EXPECT_EQ(top >> 0, top);
  EXPECT_EQ(top >> 1,  make128(1ull<<62, 0));      // 1<<126
  EXPECT_EQ(top >> 63, make128(1, 0));             // 1<<64
  EXPECT_EQ(top >> 64, make128(0, 1ull<<63));      // 1<<63
  EXPECT_EQ((make128(~0ull, ~0ull) >> 128), UInt128::zero());
}

TEST(UInt128_AddSub, CarriesAndBorrows) {
  auto a = make128(0, ~0ull);
  auto b = make128(0, 1);
  auto s = a + b;
  EXPECT_EQ(s, make128(1, 0));

  auto zero = UInt128::zero();
  auto m1 = zero - b;
  EXPECT_EQ(m1, make128(~0ull, ~0ull));

  auto x = make128(0x0123456789abcdefull, 0xfedcba9876543210ull);
  auto y = make128(0, 0x00000000075BCD15ull);
  EXPECT_EQ((x - y) + y, x);
  EXPECT_EQ((x + y) - y, x);

  EXPECT_EQ(x + y, make128(0x0123456789abcdefull, 0xfedcba987dafff25ull));
  EXPECT_EQ(x - y, make128(0x0123456789abcdefull, 0xfedcba986ef864fbull));
}

TEST(UInt128_Mul, BasicAndVectors) {
  EXPECT_EQ((UInt128::zero() * UInt128::zero()), UInt128::zero());
  EXPECT_EQ((make128(0,1) * make128(0,1)), make128(0,1));

  auto max = make128(~0ull, ~0ull);
  EXPECT_EQ(max * make128(0,2), make128(0xffffffffffffffffull, 0xfffffffffffffffeull));

  auto a = make128(0x0123456789abcdefull, 0xfedcba9876543210ull);
  auto b = make128(0, 0x00000000075BCD15ull);
  EXPECT_EQ(a * b, make128(0xd70a3d70a348b557ull, 0x28f5c28f5caeeb50ull));
}

TEST(UInt128_DivMod, EdgesAndVectors) {
  auto a = make128(0x0123456789abcdefull, 0xfedcba9876543210ull);
  auto one = make128(0,1);
  EXPECT_EQ(a / one, a);
  EXPECT_EQ(a % one, UInt128::zero());
  EXPECT_EQ(UInt128::zero() / one, UInt128::zero());

  auto small = make128(0, 42);
  auto big   = make128(0, 1000);
  EXPECT_EQ(small / big, UInt128::zero());
  EXPECT_EQ(small % big, small);

  auto n1 = make128(~0ull, ~0ull);
  auto d1 = make128(0, ~0ull);
  EXPECT_EQ(n1 / d1, make128(1,1));
  EXPECT_EQ(n1 % d1, UInt128::zero());

  auto d = make128(0, 0x00000000075BCD15ull);
  EXPECT_EQ(a / d, make128(0x27951968ull, 0xB25AC09A9A988E27ull));
  EXPECT_EQ(a % d, make128(0, 0x51E4DDDull));

  auto n2 = make128(0xdeadbeefcafebabeull, 0x1122334455667788ull);
  auto d2 = make128(0x1234567890abcdefull, 0x0123456789abcdefull);
  EXPECT_EQ(n2 / d2, make128(0, 0xC));
  EXPECT_EQ(n2 % d2, make128(0x0439b14902f1138aull, 0x037af269e158d054ull));

  auto n3 = make128(1ull<<63, 0);
  auto q3 = make128(0x2aaaaaaaaaaaaaaauLL, 0xaaaaaaaaaaaaaaaauLL);
  auto r3 = make128(0, 2);
  EXPECT_EQ(n3 / make128(0,3), q3);
  EXPECT_EQ(n3 % make128(0,3), r3);
}

TEST(UInt128_Bits, GetSet) {
  UInt128 x;
  x.setBit(0);
  x.setBit(63);
  x.setBit(64);
  x.setBit(127);
  EXPECT_EQ(x, make128((1ull<<63) | 1ull, (1ull<<63) | 1ull));

  EXPECT_EQ(x.getBit(0), 1u);
  EXPECT_EQ(x.getBit(1), 0u);
  EXPECT_EQ(x.getBit(63), 1u);
  EXPECT_EQ(x.getBit(64), 1u);
  EXPECT_EQ(x.getBit(127), 1u);
  EXPECT_EQ(x.getBit(126), 0u);
}

TEST(UInt128_IO, ToHex) {
  EXPECT_EQ(UInt128::zero().to_hex(), "0");
  EXPECT_EQ(make128(0,1).to_hex(), "1");
  EXPECT_EQ(make128(0,0x10).to_hex(), "10");
  EXPECT_EQ(make128(0x1,0).to_hex(), "10000000000000000");

  auto v = make128(~0ull, ~0ull) * make128(0,2);
  EXPECT_EQ(v.to_hex(), "fffffffffffffffffffffffffffffffe");
}

#if defined(__SIZEOF_INT128__)
static inline UInt128 from_u128(__uint128_t v) {
  auto lo = static_cast<uint64_t>(v);
  auto hi = static_cast<uint64_t>(v >> 64);
  return make128(hi, lo);
}
static inline __uint128_t to_u128(const UInt128& x) {
  return (static_cast<__uint128_t>(x.hi) << 64) | x.lo;
}

TEST(UInt128_Randomized, AgainstBuiltinWhenAvailable) {
  std::mt19937_64 rng(123456789ULL);
  for (int i = 0; i < 2000; ++i) {
    uint64_t a_hi = rng(), a_lo = rng();
    uint64_t b_hi = rng(), b_lo = rng();
    __uint128_t au = ( (__uint128_t)a_hi << 64 ) | a_lo;
    __uint128_t bu = ( (__uint128_t)b_hi << 64 ) | b_lo;
    UInt128 A(a_hi, a_lo), B(b_hi, b_lo);

    EXPECT_EQ(A == B, au == bu);
    EXPECT_EQ(A <  B, au <  bu);
    EXPECT_EQ(A >  B, au >  bu);
    EXPECT_EQ(A <= B, au <= bu);
    EXPECT_EQ(A >= B, au >= bu);

    EXPECT_EQ(A + B, from_u128(au + bu));
    EXPECT_EQ(A - B, from_u128(au - bu));

    EXPECT_EQ(A * B, from_u128(au * bu));

    if (b_hi != 0 || b_lo != 0) {
      EXPECT_EQ(A / B, from_u128(au / bu));
      EXPECT_EQ(A % B, from_u128(au % bu));
    }

    auto s = static_cast<unsigned>(rng() % 131);
    UInt128 expect_l = (s >= 128) ? UInt128::zero() : from_u128(au << s);
    UInt128 expect_r = (s >= 128) ? UInt128::zero() : from_u128(au >> s);
    EXPECT_EQ(A << s, expect_l);
    EXPECT_EQ(A >> s, expect_r);

    EXPECT_EQ((A & B), from_u128(au & bu));
    EXPECT_EQ((A | B), from_u128(au | bu));
    EXPECT_EQ((A ^ B), from_u128(au ^ bu));
    EXPECT_EQ(~A,      from_u128(~au));
  }
}
#endif

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
