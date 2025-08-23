#include <cctype>
#include <cstring>
#include <fast_proto/crypto/crypto.hxx>
#include <fast_proto/fast_proto.hxx>
#include <fast_proto/net/tcp_server.hxx>
#include <iostream>

using namespace FastProto;
using namespace FastProto::net;
using namespace FastProto::crypto;

namespace {
constexpr uint8_t kDemoKey[32] = {
  0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
  0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,
  0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
  0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F
};

enum Op : uint32_t {
  ECHO = 0x01,
  SUM_I64,
  ENC_UPPER,
  GET_RAND_UI128
};

SymKey demo_key() {
  SymKey k{};
  std::memcpy(k.bytes, kDemoKey, sizeof(kDemoKey));
  return k;
}

}

int main(int argc, char** argv) {
  uint16_t port = 9000;
  if (argc >= 2) port = static_cast<uint16_t>(std::stoi(argv[1]));

  TcpServer server(port);

  server.register_handler(Op::ECHO, [](const Packet& req, Packet& resp) {
    resp.opcode = req.opcode;
    resp.flags  = 0;
    resp.args   = req.args;
  });

  server.register_handler(Op::SUM_I64, [](const Packet& req, Packet& resp) {
    long long sum = 0;
    for (const auto& a : req.args) {
      if (a.type_id == Type::Int64) {
        sum += a.as_int64();
      } else {
        sum += static_cast<long long>(a.as_int32());
      }
    }
    resp.opcode = req.opcode;
    resp.args.clear();
    resp.args.push_back(Arg::make_int64(sum));
  });

  server.register_handler(Op::ENC_UPPER, [](const Packet& req, Packet& resp) {
    resp.opcode = req.opcode;
    resp.args.clear();

    if (req.args.empty() || req.args[0].type_id != Type::String) {
      std::cerr << "[Server] enc_upper: bad args\n";
      return;
    }

    const auto& frame_bytes = req.args[0].value;
    std::vector<uint8_t> pt;
    Alg alg{};
    uint8_t ver{};
    if (!decrypt_aead_gcm(demo_key(), frame_bytes.data(), frame_bytes.size(), pt, &alg, &ver)) {
      std::cerr << "[Server] decrypt failed\n";
      return;
    }

    for (auto& ch : pt) ch = static_cast<uint8_t>(std::toupper(ch));

    Frame out_frame;
    if (!encrypt_aead_gcm(demo_key(), Alg::AES_256_GCM, pt.data(), pt.size(), out_frame)) {
      std::cerr << "[Server] encrypt failed\n";
      return;
    }

    resp.args.push_back(Arg::make_string(std::string(out_frame.bytes.begin(), out_frame.bytes.end())));
  });

  server.register_handler(Op::GET_RAND_UI128, [](const Packet& req, Packet& resp) {
    (void)req;
    resp.opcode = req.opcode;
    resp.flags = 0;
    resp.args.clear();

    const UInt128 r = UInt128::random_u128();
    resp.args.push_back(Arg::make_uint128(r));
  });

  std::cout << "[Server] starting on port " << port << " ...\n";
  server.run();

  return 0;
}
