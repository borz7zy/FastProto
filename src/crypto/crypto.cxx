#include <openssl/aead.h>
#include <openssl/rand.h>
#include <cstring>
#include <fast_proto/crypto/crypto.hxx>
#include <limits>

namespace FastProto::crypto {

static void append_u8(std::vector<uint8_t>& v, uint8_t x){ v.push_back(x); }
static void append_u32_le(std::vector<uint8_t>& v, uint32_t x){
  uint8_t t[4] = {
    static_cast<uint8_t>( x        & 0xFF),
    static_cast<uint8_t>((x >> 8)  & 0xFF),
    static_cast<uint8_t>((x >> 16) & 0xFF),
    static_cast<uint8_t>((x >> 24) & 0xFF),
  };
  v.insert(v.end(), t, t + 4);
}

bool random_bytes(uint8_t* buf, size_t len) {
  if (len > static_cast<size_t>(std::numeric_limits<int>::max())) {
    return false;
  }
  return RAND_bytes(buf, len) == 1;
}

// Frame (wire):
// 'F','P', version, alg, nonce_len, nonce[nonce_len], u32 ct_len, ct[ct_len]
// AAD = {'F','P', version, alg}
bool encrypt_aead_gcm(const SymKey& key,
                      Alg alg,
                      const uint8_t* plaintext, size_t pt_len,
                      Frame& out_frame) {
  if (!plaintext && pt_len) return false;
  if (alg != Alg::AES_256_GCM) return false;

  const EVP_AEAD* aead = EVP_aead_aes_256_gcm();
  EVP_AEAD_CTX ctx;
  if (!EVP_AEAD_CTX_init(&ctx, aead, key.bytes, sizeof(key.bytes), kTagLen, nullptr))
    return false;

  uint8_t nonce[kNonceLen];
  if (!random_bytes(nonce, sizeof(nonce))) { EVP_AEAD_CTX_cleanup(&ctx); return false; }

  const uint8_t aad[] = {'F','P', kVersion, static_cast<uint8_t>(alg)};

  const size_t max_out = pt_len + kTagLen;
  std::vector<uint8_t> ct(max_out);
  size_t ct_len = 0;

  if (!EVP_AEAD_CTX_seal(&ctx,
                         ct.data(), &ct_len, ct.size(),
                         nonce, sizeof(nonce),
                         plaintext, pt_len,
                         aad, sizeof(aad))) {
    EVP_AEAD_CTX_cleanup(&ctx);
    return false;
  }
  ct.resize(ct_len);

  std::vector<uint8_t> frame;
  frame.reserve(2 + 1 + 1 + 1 + sizeof(nonce) + 4 + ct.size());
  frame.push_back('F'); frame.push_back('P');
  append_u8(frame, kVersion);
  append_u8(frame, static_cast<uint8_t>(alg));
  append_u8(frame, static_cast<uint8_t>(sizeof(nonce)));
  frame.insert(frame.end(), nonce, nonce + sizeof(nonce));
  append_u32_le(frame, static_cast<uint32_t>(ct.size()));
  frame.insert(frame.end(), ct.begin(), ct.end());

  out_frame.bytes = std::move(frame);
  EVP_AEAD_CTX_cleanup(&ctx);
  return true;
}

bool decrypt_aead_gcm(const SymKey& key,
                      const uint8_t* frame_bytes, size_t frame_len,
                      std::vector<uint8_t>& out_plaintext,
                      Alg* out_alg, uint8_t* out_version) {
  if (!frame_bytes || frame_len < (2+1+1+1+4+16)) return false;

  const uint8_t* p = frame_bytes;
  const uint8_t* end = frame_bytes + frame_len;

  if (*p++ != 'F' || *p++ != 'P') return false;
  const uint8_t version = *p++;
  auto alg_u8 = *p++;
  auto alg = static_cast<Alg>(alg_u8);
  const uint8_t nonce_len = *p++;
  if (nonce_len != kNonceLen) return false;
  if (end - p < nonce_len) return false;
  const uint8_t* nonce = p; p += nonce_len;

  if (end - p < 4) return false;
  uint32_t ct_len_le; std::memcpy(&ct_len_le, p, 4); p += 4;
  const size_t ct_len = ct_len_le;

  if (ct_len > kMaxCiphertextLen) return false;
  if (ct_len > static_cast<size_t>(end - p)) return false;
  const uint8_t* ct = p;

  if (alg != Alg::AES_256_GCM) return false;
  const EVP_AEAD* aead = EVP_aead_aes_256_gcm();
  EVP_AEAD_CTX ctx;
  if (!EVP_AEAD_CTX_init(&ctx, aead, key.bytes, sizeof(key.bytes), kTagLen, nullptr))
    return false;

  const uint8_t aad[] = {'F','P', version, static_cast<uint8_t>(alg)};
  std::vector<uint8_t> pt(ct_len);
  size_t pt_out_len = 0;

  const bool ok = EVP_AEAD_CTX_open(&ctx,
                                    pt.data(), &pt_out_len, pt.size(),
                                    nonce, nonce_len,
                                    ct, ct_len,
                                    aad, sizeof(aad)) == 1;

  EVP_AEAD_CTX_cleanup(&ctx);
  if (!ok) return false;

  pt.resize(pt_out_len);
  out_plaintext = std::move(pt);
  if (out_alg) *out_alg = alg;
  if (out_version) *out_version = version;
  return true;
}

}
