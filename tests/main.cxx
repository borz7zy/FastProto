#include <chrono>
#include <cstring>
#include <fast_proto/crypto/crypto.hxx>
#include <fast_proto/crypto/diffie_hellman.hxx>
#include <fast_proto/fast_proto.hxx>
#include <fast_proto/net/common.hxx>
#include <fast_proto/net/tcp_client.hxx>
#include <fast_proto/net/tcp_server.hxx>
#include <fast_proto/uint_128.hxx>
#include <future>
#include <gtest/gtest.h>
#include <random>
#include <thread>

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

namespace {

class Defer {
 public:
  explicit Defer(std::function<void()> f) : f_(std::move(f)) {}
  ~Defer() {
    if (f_)
      f_();
  }
  Defer(const Defer&) = delete;
  Defer& operator=(const Defer&) = delete;

 private:
  std::function<void()> f_;
};

} // namespace

TEST(NetworkTest, ServerClientEcho) {
  constexpr uint16_t port = 9002;

  net::TcpServer ws_server(port);
  net::TcpClient ws_client("127.0.0.1", port);

  ws_server.register_handler(0x1234, [](const Packet& req, Packet& resp) {
    resp.opcode = req.opcode;
    resp.args = req.args;
  });

  std::thread server_thread([&]() { ws_server.run(); });

  Defer cleanup([&] {
    ws_client.disconnect();
    ws_server.stop();
    if (server_thread.joinable())
      server_thread.join();
  });

  std::promise<Packet> resp_promise;
  auto resp_future = resp_promise.get_future();

  ws_client.set_message_handler([&](const Packet& pkt, Packet& /* ignored */) {
    try {
      resp_promise.set_value(pkt);
    } catch (const std::future_error&) {}
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  bool connected = false;
  for (size_t i = 0; i < 50 && !connected; ++i) {
    connected = ws_client.connect();
    if (!connected)
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  ASSERT_TRUE(connected) << "Client failed to connect to server";

  Packet req;
  req.opcode = 0x1234;
  req.args.push_back(Arg::make_string("hello"));
  ASSERT_TRUE(ws_client.send(req)) << "Client failed to send request";

  auto status = resp_future.wait_for(std::chrono::seconds(2));
  ASSERT_EQ(status, std::future_status::ready)
      << "Timed out waiting for echo response";

  Packet resp = resp_future.get();
  EXPECT_EQ(resp.opcode, req.opcode);
  ASSERT_EQ(resp.args.size(), 1u);
  EXPECT_EQ(resp.args[0].as_string(), "hello");
}

TEST(NetworkTest, ServerClientMulticast_Targeted) {
  using namespace std::literals::chrono_literals;

  constexpr uint16_t port       = 9003;
  constexpr uint32_t OP_HELLO   = 0xBEEF;
  constexpr uint32_t OP_TRIGGER = 0xCAFE;
  constexpr uint32_t OP_NOTIFY  = 0xC0DE;

  net::TcpServer ws_server(port);
  net::TcpClient ws_client("127.0.0.1", port);
  net::TcpClient ws_client2("127.0.0.1", port);

  std::mutex mu;
  std::unordered_map<std::string, std::intptr_t> name2fd;

  ws_server.register_handler(OP_HELLO, [&](const Packet& req, Packet& /* ignored */) {
    if (!req.args.empty()) {
      const auto name = req.args[0].as_string();
      std::lock_guard<std::mutex> lk(mu);
      name2fd[name] = static_cast<std::intptr_t>(req.source_fd);
    }
  });

  ws_server.register_handler(OP_TRIGGER, [&](const Packet& req, Packet& /* ignored */) {
    // args: [ target_name, payload ]
    ASSERT_GE(req.args.size(), 2u);
    const auto target = req.args[0].as_string();
    const auto payload = req.args[1].as_string();

    std::intptr_t target_fd = -1;
    {
      std::lock_guard<std::mutex> lk(mu);
      auto it = name2fd.find(target);
      if (it != name2fd.end()) target_fd = it->second;
    }
    if (target_fd != -1) {
      Packet notify;
      notify.opcode = OP_NOTIFY;
      notify.args.push_back(Arg::make_string(payload));
      ws_server.multicast(notify, { target_fd });
    }
  });

  std::thread server_thread([&]() { ws_server.run(); });

  Defer cleanup([&] {
    ws_client.disconnect();
    ws_client2.disconnect();
    ws_server.stop();
    if (server_thread.joinable())
      server_thread.join();
  });

  std::promise<Packet> got_c2_notify_promise;
  auto got_c2_notify = got_c2_notify_promise.get_future();

  std::promise<Packet> got_c1_unexpected_notify_promise;
  auto got_c1_unexpected_notify = got_c1_unexpected_notify_promise.get_future();

  ws_client.set_message_handler([&](const Packet& pkt, Packet&) {
    if (pkt.opcode == OP_NOTIFY) {
      try { got_c1_unexpected_notify_promise.set_value(pkt); } catch (...) {}
    }
  });

  ws_client2.set_message_handler([&](const Packet& pkt, Packet&) {
    if (pkt.opcode == OP_NOTIFY) {
      try { got_c2_notify_promise.set_value(pkt); } catch (...) {}
    }
  });

  std::this_thread::sleep_for(50ms);

  bool connected = false;
  for (size_t i = 0; i < 50 && !connected; ++i) {
    connected = ws_client.connect();
    if (!connected) std::this_thread::sleep_for(20ms);
  }
  ASSERT_TRUE(connected) << "Client failed to connect to server";

  bool connected2 = false;
  for (size_t i = 0; i < 50 && !connected2; ++i) {
    connected2 = ws_client2.connect();
    if (!connected2) std::this_thread::sleep_for(20ms);
  }
  ASSERT_TRUE(connected2) << "Client2 failed to connect to server";

  {
    Packet hello1; hello1.opcode = OP_HELLO;
    hello1.args.push_back(Arg::make_string("c1"));
    ASSERT_TRUE(ws_client.send(hello1));

    Packet hello2; hello2.opcode = OP_HELLO;
    hello2.args.push_back(Arg::make_string("c2"));
    ASSERT_TRUE(ws_client2.send(hello2));
  }

  {
    Packet trigger; trigger.opcode = OP_TRIGGER;
    trigger.args.push_back(Arg::make_string("c2"));
    trigger.args.push_back(Arg::make_string("hello-mc"));
    ASSERT_TRUE(ws_client.send(trigger));
  }

  auto status2 = got_c2_notify.wait_for(2s);
  ASSERT_EQ(status2, std::future_status::ready) << "Timed out waiting for multicast at client2";
  Packet resp2 = got_c2_notify.get();
  EXPECT_EQ(resp2.opcode, OP_NOTIFY);
  ASSERT_EQ(resp2.args.size(), 1u);
  EXPECT_EQ(resp2.args[0].as_string(), "hello-mc");

  auto status1 = got_c1_unexpected_notify.wait_for(200ms);
  EXPECT_EQ(status1, std::future_status::timeout) << "Client1 must not receive multicast";
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

  auto ssmall = make128(0, 42);
  auto big   = make128(0, 1000);
  EXPECT_EQ(ssmall / big, UInt128::zero());
  EXPECT_EQ(ssmall % big, ssmall);

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

TEST(DiffieHellman_RawAPI, PublicKeyHasExpectedSize) {
  DiffieHellman a;
  auto pub = a.getRawPublicKey();
  EXPECT_EQ(pub.size(), static_cast<size_t>(32));
}

TEST(DiffieHellman_RawAPI, SharedSecretMatchesAndIs32Bytes) {
  DiffieHellman a, b;

  auto a_pub = a.getRawPublicKey();
  auto b_pub = b.getRawPublicKey();

  auto s1 = a.computeSharedSecretFromRaw(b_pub.data(), b_pub.size());
  auto s2 = b.computeSharedSecretFromRaw(a_pub.data(), a_pub.size());

  EXPECT_EQ(s1.size(), static_cast<size_t>(32));
  EXPECT_EQ(s1, s2);
}

TEST(DiffieHellman_RawAPI, DifferentPeersLikelyDifferentSecrets) {
  DiffieHellman a, b, c;

  auto b_pub = b.getRawPublicKey();
  auto c_pub = c.getRawPublicKey();

  auto ab = a.computeSharedSecretFromRaw(b_pub.data(), b_pub.size());
  auto ac = a.computeSharedSecretFromRaw(c_pub.data(), c_pub.size());

  ASSERT_EQ(ab.size(), static_cast<size_t>(32));
  ASSERT_EQ(ac.size(), static_cast<size_t>(32));
  EXPECT_NE(ab, ac);
}

TEST(DiffieHellman_RawAPI, InvalidLengthThrows) {
  DiffieHellman a;

  std::vector<std::uint8_t> zero;                      // 0
  std::vector<std::uint8_t> short31(31, 0x01);         // 31
  std::vector<std::uint8_t> long33(33, 0x02);          // 33
  std::vector<std::uint8_t> long64(64, 0x03);          // 64

  EXPECT_THROW(a.computeSharedSecretFromRaw(zero.data(), zero.size()), std::runtime_error);
  EXPECT_THROW(a.computeSharedSecretFromRaw(short31.data(), short31.size()), std::runtime_error);
  EXPECT_THROW(a.computeSharedSecretFromRaw(long33.data(), long33.size()), std::runtime_error);
  EXPECT_THROW(a.computeSharedSecretFromRaw(long64.data(), long64.size()), std::runtime_error);
}

TEST(DiffieHellman_RawAPI, MoveSemanticsWork) {
  DiffieHellman alice;
  DiffieHellman bob;

  auto bob_pub = bob.getRawPublicKey();

  // move-ctor
  DiffieHellman bob2(std::move(bob));

  auto s1 = alice.computeSharedSecretFromRaw(bob_pub.data(), bob_pub.size());
  auto s2 = bob2.computeSharedSecretFromRaw(alice.getRawPublicKey().data(), 32);

  EXPECT_EQ(s1, s2);
}

TEST(DiffieHellman_Compat, RawAndSPKIProduceSameSecret) {
  DiffieHellman a, b;

  auto b_pub_raw = b.getRawPublicKey();
  auto b_pub_spki = b.getPublicKey(); // DER SPKI

  auto s_raw  = a.computeSharedSecretFromRaw(b_pub_raw.data(), b_pub_raw.size());
  auto s_spki = a.computeSharedSecret(b_pub_spki);

  EXPECT_EQ(s_raw, s_spki);
}

TEST(DiffieHellman_SPKI, InvalidDERThrows) {
  DiffieHellman a;

  std::vector<std::uint8_t> empty;
  EXPECT_THROW(a.computeSharedSecret(empty), std::runtime_error);

  DiffieHellman b;
  auto der = b.getPublicKey();
  if (der.size() > 5) {
    der.resize(der.size() - 5);
    EXPECT_THROW(a.computeSharedSecret(der), std::runtime_error);
  }
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
