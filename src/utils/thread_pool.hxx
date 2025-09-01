#pragma once

#include "blocking_queue.hxx"
#include <functional>
#include <future>
#include <memory>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>

class ThreadPool {
public:
  explicit ThreadPool(unsigned requested = std::thread::hardware_concurrency()) { // constructor 
    unsigned hc = requested ? requested : 1;
    unsigned n = (hc > 2) ? (hc - 2) : 1;
    workers_.reserve(n);
    for (unsigned i = 0; i < n; ++i)
      workers_.emplace_back(std::bind_front(&ThreadPool::worker_loop, this));
  }

  ~ThreadPool() { // destructor
    for (auto& t : workers_)
      t.request_stop();

    q_.notify_all();
    for (auto& t : workers_)
      if (t.joinable())
        t.join();

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
  void worker_loop(const std::stop_token& st) {
    Task task;
    while (!st.stop_requested()) {
      if (!q_.wait_pop(task, st))
        break;
      task();
    }
  }
  BlockingQueue<Task> q_;
  std::vector<std::jthread> workers_;
};