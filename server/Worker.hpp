#pragma once

#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <vector>

#include "../common/protocol.hpp"

namespace net_ops::server {

    struct Job {
        int client_fd;
        net_ops::protocol::MessageType type;
        std::vector<uint8_t> payload;
    };

    class Worker {
    private:
        std::queue<Job> job_queue_;
        std::mutex queue_mutex_;
        std::condition_variable queue_cv_;

        std::thread worker_thread_;
        std::atomic<bool> running_;

        void ProcessLoop();
        
        void HandleLogin(int client_fd, const std::vector<uint8_t>& payload);
        void HandleRegister(int client_fd, const std::vector<uint8_t>& payload);

    public:
        Worker();
        ~Worker();

        void Start();
        void Stop();
        void AddJob(int client_fd, net_ops::protocol::MessageType type, std::vector<uint8_t> payload);
    };

}