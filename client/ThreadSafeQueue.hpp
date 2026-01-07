#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>

namespace net_ops::client
{
    template <typename T>
    class ThreadSafeQueue
    {
    private:
        std::queue<T> m_queue;
        mutable std::mutex m_mutex;
        std::condition_variable m_cv;
        bool m_shutdown = false;

    public:
        void Push(T value)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_queue.push(std::move(value));
            m_cv.notify_one();
        }

        std::optional<T> Pop()
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [this]
                      { return !m_queue.empty() || m_shutdown; });

            if (m_queue.empty())
                return std::nullopt;

            T value = std::move(m_queue.front());
            m_queue.pop();
            return value;
        }

        void Shutdown()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_shutdown = true;
            m_cv.notify_all();
        }

        bool Empty() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_queue.empty();
        }
    };
}