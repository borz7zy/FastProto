#pragma once

#include <vector>

namespace FastProto::crypto {

enum class Alg : uint8_t { AES_256_GCM = 1 };

struct SymKey { uint8_t bytes[32]{  }; };

struct Frame { std::vector<uint8_t> bytes; };

inline constexpr uint8_t kVersion  = 1;
inline constexpr uint8_t kNonceLen = 12;
inline constexpr size_t  kTagLen   = 16;

bool encrypt_aead_gcm(const SymKey& key,
                      Alg alg,
                      const uint8_t* plaintext, size_t pt_len,
                      Frame& out_frame);

bool decrypt_aead_gcm(const SymKey& key,
                      const uint8_t* frame_bytes, size_t frame_len,
                      std::vector<uint8_t>& out_plaintext,
                      Alg* out_alg = nullptr, uint8_t* out_version = nullptr);

bool random_bytes(uint8_t* buf, size_t len);

inline constexpr uint32_t kMaxCiphertextLen = 16 * 1024 * 1024;

}