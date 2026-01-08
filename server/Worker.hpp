#pragma once

#include <thread>
#include <atomic>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include "../common/protocol.hpp"

namespace net_ops::server
{
    class NetworkCore;

    struct Job
    {
        int client_fd;
        net_ops::protocol::MessageType type;
        std::vector<uint8_t> payload;
    };

    class Worker
    {
    public:
        Worker();
        ~Worker();

        void SetNetworkCore(NetworkCore *core);
        void Start();
        void Stop();
        void AddJob(int client_fd, net_ops::protocol::MessageType type, std::vector<uint8_t> payload);

    private:
        void Run();
        void ProcessJob(const Job &job);

        void HandleLogin(int client_fd, const std::vector<uint8_t> &payload);
        void HandleSignup(int client_fd, const std::vector<uint8_t> &payload);
        void HandleDeviceAdd(int client_fd, const std::vector<uint8_t> &payload);
        void HandleDeviceList(int client_fd, const std::vector<uint8_t> &payload);
        void HandleLogUpload(int client_fd, const std::vector<uint8_t> &payload);
        void HandleDeviceStatus(int client_fd, const std::vector<uint8_t> &payload);
        void HandleLogQuery(int client_fd, const std::vector<uint8_t> &payload);

        NetworkCore *m_networkCore;
        std::thread m_thread;
        std::atomic<bool> m_running;

        std::queue<Job> m_jobQueue;
        std::mutex m_queueMutex;
        std::condition_variable m_cv;
    };
}