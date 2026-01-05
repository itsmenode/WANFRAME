#pragma once

#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <atomic>
#include "../common/protocol.hpp"

namespace net_ops::server { class NetworkCore; }

namespace net_ops::server {

    struct Job {
        int client_fd;
        net_ops::protocol::MessageType type;
        std::vector<uint8_t> payload;
    };

    class Worker {
    private:
        std::thread worker_thread_;
        std::mutex queue_mutex_;
        std::condition_variable queue_cv_;
        std::queue<Job> job_queue_;
        std::atomic<bool> running_;

        NetworkCore* network_core_;

        void ProcessLoop();
        void HandleLogin(int client_fd, const std::vector<uint8_t>& payload);
        void HandleRegister(int client_fd, const std::vector<uint8_t>& payload);

        void HandleGroupCreate(int client_fd, const std::vector<uint8_t>& payload);
        void HandleGroupList(int client_fd);

    public:
        Worker();
        ~Worker();

        void Start();
        void Stop();
        
        void SetNetworkCore(NetworkCore* core) { network_core_ = core; }

        void AddJob(int client_fd, net_ops::protocol::MessageType type, std::vector<uint8_t> payload);
    };
}