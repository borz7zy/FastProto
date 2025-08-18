#pragma once
#include <vector>
#include <memory>
#include <cstddef>
#include <cstdint>

#if defined(_WIN32)
#if defined(FASTPROTO_CRYPTO_BUILD)
#define FPCRYPTO_API __declspec(dllexport)
#else
#define FPCRYPTO_API __declspec(dllimport)
#endif
#else
#define FPCRYPTO_API __attribute__((visibility("default")))
#endif

namespace FastProto::crypto {

class FPCRYPTO_API DiffieHellman {
 public:
  DiffieHellman();
  ~DiffieHellman();

  DiffieHellman(const DiffieHellman&) = delete;
  DiffieHellman& operator=(const DiffieHellman&) = delete;

  DiffieHellman(DiffieHellman&&) noexcept;
  DiffieHellman& operator=(DiffieHellman&&) noexcept;

  std::vector<uint8_t> getRawPublicKey() const;

  std::vector<uint8_t> computeSharedSecretFromRaw(const std::uint8_t* peer_raw32, std::size_t len);

  std::vector<uint8_t> getPublicKey() const; // DER SPKI
  std::vector<uint8_t> computeSharedSecret(const std::vector<std::uint8_t>& peer_spki_der);

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}
