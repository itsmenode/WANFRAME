#pragma once

#include <thread>
#include <atomic>
#include <memory>
#include <functional>
#include "ClientNetwork.hpp"
#include "ThreadSafeQueue.hpp"
#include "../common/protocol.hpp"

namespace net_ops::client
{
    struct NetworkRequest
    {
        net_ops::protocol::MessageType type;
        std::vector<uint8_t> payload;
    };

    class NetworkController
    {
    public:
        NetworkController(const std::string &host, int port);
        ~NetworkController();

        void Start();
        void Stop();

        void QueueRequest(net_ops::protocol::MessageType type, std::vector<uint8_t> payload);

        std::optional<NetworkResponse> GetNextResponse();

        bool IsConnected() const { return m_connected; }

    private:
        void Run();

        std::string m_host;
        int m_port;
        std::unique_ptr<ClientNetwork> m_network;

        std::thread m_thread;
        std::atomic<bool> m_running;
        std::atomic<bool> m_connected;

        ThreadSafeQueue<NetworkRequest> m_requestQueue;
        ThreadSafeQueue<NetworkResponse> m_responseQueue;
    };
}