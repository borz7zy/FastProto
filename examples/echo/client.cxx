#include <cstring>
#include <fast_proto/crypto/crypto.hxx>
#include <fast_proto/fast_proto.hxx>
#include <fast_proto/net/tcp_client.hxx>
#include <iostream>
#include <thread>

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

enum Op : uint8_t {
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

void print_packet(const Packet& p) {
  std::cout << "[Client] got packet opcode=" << p.opcode
            << " args=" << p.args.size() << "\n";
  for (size_t i = 0; i < p.args.size(); ++i) {
    const auto& a = p.args[i];
    std::cout << "  arg[" << i << "]: ";
    switch (a.type_id) {
      case Type::Bool:    { std::cout << "Bool="       << (a.as_bool() ? "true":"false"); break; }
      case Type::Int32:   { std::cout << "Int32="      << a.as_int32(); break; }
      case Type::Int64:   { std::cout << "Int64="      << a.as_int64(); break; }
      case Type::UInt128: { std::cout << "UInt128="    << a.as_uint128(); break; }
      case Type::String:  { std::cout << "String len=" << a.value.size(); break; }
      case Type::Int16:   { std::cout << "Int16="      << a.as_int16(); break; }
      case Type::UInt16:  { std::cout << "UInt16="     << a.as_uint16(); break; }
      case Type::UInt32:  { std::cout << "UInt32="     << a.as_uint32(); break; }
      case Type::Float:   { std::cout << "Float="      << a.as_float(); break; }
      case Type::Double:  { std::cout << "Double="     << a.as_double(); break; }
      default:            { std::cout << "Other type\n"; break; }
    }
    std::cout << "\n";
  }
}
}

int main(const int argc, char** argv) {
  std::string host = "127.0.0.1";
  uint16_t port = 9000;
  if (argc >= 2) host = argv[1];
  if (argc >= 3) port = static_cast<uint16_t>(std::stoi(argv[2]));

  TcpClient client(host, port);

  client.set_message_handler([](const Packet& req, Packet&){
    print_packet(req);

    if (req.opcode == Op::GET_RAND_UI128 && !req.args.empty() && req.args[0].type_id == Type::UInt128) {
      const auto a = req.args[0].as_uint128();
      std::cout << "UInt128 is " << a << "\n";
    }

    if (req.opcode == Op::ENC_UPPER && !req.args.empty() && req.args[0].type_id == Type::String) {
      const auto& frame_bytes = req.args[0].value;
      if (std::vector<uint8_t> pt; decrypt_aead_gcm(demo_key(), frame_bytes.data(), frame_bytes.size(), pt)) {
        const std::string s(pt.begin(), pt.end());
        std::cout << "  [decrypted text] \"" << s << "\"\n";
      } else {
        std::cerr << "  [decrypt failed]\n";
      }
    }
  });

  if (!client.connect()) {
    std::cerr << "[Client] connect failed\n";
    return 1;
  }

  // 1) ECHO
  Packet echo{};
  echo.opcode = Op::ECHO;
  echo.args.push_back(Arg::make_string("hello"));
  echo.args.push_back(Arg::make_int64(42));
  (void)client.send(echo);

  // 2) SUM_I64
  Packet sum{};
  sum.opcode = Op::SUM_I64;
  sum.args.push_back(Arg::make_int64(10));
  sum.args.push_back(Arg::make_int32(32));
  (void)client.send(sum);

  // 3) ENC_UPPER: "secret ping" -> AEAD frame
  Frame frame{};
  if (const auto msg = "secret ping"; !encrypt_aead_gcm(demo_key(), Alg::AES_256_GCM,
                        reinterpret_cast<const uint8_t*>(msg),
                        std::strlen(msg), frame)) {
    std::cerr << "[Client] encrypt failed\n";
  } else {
    Packet enc{};
    enc.opcode = Op::ENC_UPPER;
    enc.args.push_back(Arg::make_string(std::string(frame.bytes.begin(), frame.bytes.end())));
    (void)client.send(enc);
  }

  Packet randu128{};
  randu128.opcode = Op::GET_RAND_UI128;
  (void)client.send(randu128);

  std::this_thread::sleep_for(std::chrono::seconds(2));
  client.disconnect();

  return 0;
}
