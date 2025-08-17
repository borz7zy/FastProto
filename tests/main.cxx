#include <gtest/gtest.h>
#include <chrono>
#include <cstring>
#include <fast_proto/crypto/crypto.hxx>
#include <fast_proto/fast_proto.hxx>
#include <fast_proto/net/common.hxx>
#include <fast_proto/net/websocket_client.hxx>
#include <fast_proto/net/websocket_server.hxx>
#include <future>
#include <thread>

using namespace FastProto;

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


int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
