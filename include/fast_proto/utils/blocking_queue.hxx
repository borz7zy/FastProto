#pragma once

#include <condition_variable>
#include <deque>
#include <mutex>
#include <atomic>

#ifdef __cpp_lib_jthread
#include <stop_token>
#define HAS_JTHREAD 1
#else
#define HAS_JTHREAD 0
#endif

template<class T>
class BlockingQueue {
public:
#if HAS_JTHREAD
  bool wait_pop(T& out, std::stop_token st) {
    std::unique_lock<std::mutex> lk(m_);
    cv_.wait(lk, st, [&] { return !q_.empty(); });
    if (q_.empty())
      return false;

    out = std::move(q_.front());
    q_.pop_front();
    return true;
  }
#else
  bool wait_pop(T& out, std::shared_ptr<std::atomic<bool>> stop_flag) {
    std::unique_lock<std::mutex> lk(m_);
    cv_.wait(lk, [&] { return !q_.empty() || stop_flag->load(); });
    if (q_.empty())
      return false;

    out = std::move(q_.front());
    q_.pop_front();
    return true;
  }
#endif
  template <class U>
  void push(U&& v) {
    {
      std::lock_guard<std::mutex> lk(m_);
      q_.emplace_back(std::forward<U>(v));
    }
    cv_.notify_one();
  }

  bool try_pop(T& out) {
    std::lock_guard<std::mutex> lk(m_);
    if (q_.empty())
      return false;

    out = std::move(q_.front());
    q_.pop_front();
    return true;
  }

  void notify_all() {
    cv_.notify_all();
  }

 private:
  std::deque<T> q_;
  std::mutex m_;
  std::condition_variable_any cv_;
};
