#pragma once

#include <utility>
#include <fast_proto/platform.hxx>

namespace FastProto::net {

class SocketHandle {
 public:
#ifdef _WIN32
  using handle_t = SOCKET;
  static constexpr handle_t invalid() noexcept { return INVALID_SOCKET; }
#else
  using handle_t = int;
  static constexpr handle_t invalid() noexcept { return -1; }
#endif

  SocketHandle() noexcept : fd_(invalid()) {}
  explicit SocketHandle(handle_t fd) noexcept : fd_(fd) {}

  SocketHandle(const SocketHandle&) = delete;
  SocketHandle& operator=(const SocketHandle&) = delete;

  SocketHandle(SocketHandle&& other) noexcept : fd_(other.fd_) {
    other.fd_ = invalid();
  }

  SocketHandle& operator=(SocketHandle&& other) noexcept {
    if (this != &other) {
      reset();
      fd_ = other.fd_;
      other.fd_ = invalid();
    }
    return *this;
  }

  ~SocketHandle() { reset(); }

  handle_t get() const noexcept { return fd_; }
  bool valid() const noexcept { return fd_ != invalid(); }

  handle_t release() noexcept {
    handle_t tmp = fd_;
    fd_ = invalid();
    return tmp;
  }

  void reset(handle_t new_fd = invalid()) noexcept {
    if (valid()) {
#ifdef _WIN32
      ::shutdown(fd_, SD_BOTH);
      ::closesocket(fd_);
#else
      ::shutdown(fd_, SHUT_RDWR);
      ::close(fd_);
#endif
    }
    fd_ = new_fd;
  }

 private:
  handle_t fd_;
};

}
