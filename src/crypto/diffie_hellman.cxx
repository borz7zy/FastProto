#define OPENSSL_NO_ENGINE
#include <fast_proto/crypto/diffie_hellman.hxx>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>

using namespace FastProto::crypto;

static void handleErrors() {
  ERR_print_errors_fp(stderr);
  throw std::runtime_error("OpenSSL error");
}

class DiffieHellman::Impl {
 public:
  Impl() : keypair_(nullptr) {
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!kctx) handleErrors();
    if (EVP_PKEY_keygen_init(kctx) <= 0) handleErrors();
    if (EVP_PKEY_keygen(kctx, &keypair_) <= 0) handleErrors();
    EVP_PKEY_CTX_free(kctx);
  }

  ~Impl() { if (keypair_) EVP_PKEY_free(keypair_); }

  std::vector<uint8_t> getRawPublicKey() const {
    size_t len = 0;
    if (!EVP_PKEY_get_raw_public_key(keypair_, nullptr, &len) || len != 32) handleErrors();
    std::vector<uint8_t> out(len);
    if (!EVP_PKEY_get_raw_public_key(keypair_, out.data(), &len)) handleErrors();
    return out;
  }

  std::vector<uint8_t> computeSharedSecretFromRaw(const uint8_t* peer_raw32, std::size_t len) {
    if (len != 32) throw std::runtime_error("peer key must be 32 bytes");
    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_raw32, len);
    if (!peer) handleErrors();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(keypair_, nullptr);
    if (!ctx) handleErrors();
    if (EVP_PKEY_derive_init(ctx) <= 0) handleErrors();
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) handleErrors();

    size_t slen = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &slen) <= 0) handleErrors();
    std::vector<uint8_t> secret(slen);
    if (EVP_PKEY_derive(ctx, secret.data(), &slen) <= 0) handleErrors();
    secret.resize(slen);

    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(ctx);
    return secret;
  }
  
  std::vector<uint8_t> getPublicKey_SPki() const {
    int len = i2d_PUBKEY(keypair_, nullptr);
    if (len <= 0) handleErrors();
    std::vector<uint8_t> buf(len);
    unsigned char* p = buf.data();
    if (i2d_PUBKEY(keypair_, &p) <= 0) handleErrors();
    return buf;
  }

  std::vector<uint8_t> computeSharedSecret_SPki(const std::vector<uint8_t>& peer_der) {
    const unsigned char* p = peer_der.data();
    EVP_PKEY* peer = d2i_PUBKEY(nullptr, &p, peer_der.size());
    if (!peer) handleErrors();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(keypair_, nullptr);
    if (!ctx) handleErrors();
    if (EVP_PKEY_derive_init(ctx) <= 0) handleErrors();
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) handleErrors();

    size_t slen = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &slen) <= 0) handleErrors();
    std::vector<uint8_t> secret(slen);
    if (EVP_PKEY_derive(ctx, secret.data(), &slen) <= 0) handleErrors();
    secret.resize(slen);

    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(ctx);
    return secret;
  }

 private:
  EVP_PKEY* keypair_;
};

DiffieHellman::DiffieHellman() : impl_(std::make_unique<Impl>()) {}
DiffieHellman::~DiffieHellman() = default;
DiffieHellman::DiffieHellman(DiffieHellman&&) noexcept = default;
DiffieHellman& DiffieHellman::operator=(DiffieHellman&&) noexcept = default;

std::vector<uint8_t> DiffieHellman::getRawPublicKey() const { return impl_->getRawPublicKey(); }
std::vector<uint8_t> DiffieHellman::computeSharedSecretFromRaw(const uint8_t* p, std::size_t n) {
  return impl_->computeSharedSecretFromRaw(p, n);
}

std::vector<uint8_t> DiffieHellman::getPublicKey() const { return impl_->getPublicKey_SPki(); }
std::vector<uint8_t> DiffieHellman::computeSharedSecret(const std::vector<uint8_t>& der) {
  return impl_->computeSharedSecret_SPki(der);
}
