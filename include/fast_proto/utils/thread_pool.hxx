#pragma once

#include "blocking_queue.hxx"
#include <functional>
#include <future>
#include <memory>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>
#include <atomic>
#include <vector>

class ThreadPool {
public:
  explicit ThreadPool(unsigned requested = std::thread::hardware_concurrency()) { // constructor 
    unsigned hc = requested ? requested : 1;
    unsigned n = (hc > 2) ? (hc - 2) : 1;
    workers_.reserve(n);

#if HAS_JTHREAD
    for (unsigned i = 0; i < n; ++i)
      workers_.emplace_back(std::bind_front(&ThreadPool::worker_loop, this));
#else
    stop_flag_ = std::make_shared<std::atomic<bool>>(false);
    for (unsigned i = 0; i < n; ++i)
      workers_.emplace_back(&ThreadPool::worker_loop, this, stop_flag_);
#endif
  }

  ~ThreadPool() { // destructor
#if HAS_JTHREAD
    for (auto& t : workers_)
      t.request_stop();

    q_.notify_all();
    for (auto& t : workers_)
      if (t.joinable())
        t.join();

#else
    stop_flag_->store(true);
    q_.notify_all();

    for (auto& t : workers_)
      if (t.joinable())
        t.join();
#endif

    Task task;
    while (q_.try_pop(task))
      task();
  }

  template <class F>
  auto submit(F&& f) {
    using R = std::invoke_result_t<std::decay_t<F>&>;

    auto prom = std::make_shared<std::promise<R>>();
    auto fut = prom->get_future();

    auto wrapper = [prom, fn = std::decay_t<F>(std::forward<F>(f))]() mutable {
      try {
        if constexpr (std::is_void_v<R>) {
          fn();
          prom->set_value();
        } else
          prom->set_value(fn());
      } catch (...) {
        try {
          prom->set_exception(std::current_exception());
        } catch (...) {}
      }
    };
    q_.push(Task(std::move(wrapper)));
    return fut;
  }

private:
  using Task = std::function<void()>;

#if HAS_JTHREAD
  void worker_loop(const std::stop_token& st) {
    Task task;
    while (!st.stop_requested()) {
      if (!q_.wait_pop(task, st))
        break;
      task();
    }
  }
  std::vector<std::jthread> workers_;
#else
  void worker_loop(std::shared_ptr<std::atomic<bool>> stop_flag) { 
    Task task;
    while (!stop_flag->load()) {
      if (!q_.wait_pop(task, stop_flag))
        break;
      task();
    }
  }
  std::vector<std::thread> workers_;
  std::shared_ptr<std::atomic<bool>> stop_flag_;
#endif
  BlockingQueue<Task> q_;
};