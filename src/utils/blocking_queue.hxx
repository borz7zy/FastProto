#pragma once

#include <condition_variable>
#include <deque>
#include <mutex>
#include <stop_token>

template<class T>
class BlockingQueue {
public:
  bool wait_pop(T& out, std::stop_token st) {
    std::unique_lock<std::mutex> lk(m_);
    cv_.wait(lk, st, [&] { return !q_.empty(); });
    if (q_.empty())
      return false;

    out = std::move(q_.front());
    q_.pop_front();
    return true;
  }

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
