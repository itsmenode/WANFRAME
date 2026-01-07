#include "NetworkController.hpp"
#include <iostream>

namespace net_ops::client
{
    NetworkController::NetworkController(const std::string &host, int port)
        : m_host(host), m_port(port), m_running(false), m_connected(false)
    {
        m_network = std::make_unique<ClientNetwork>(host, port);
    }

    NetworkController::~NetworkController()
    {
        Stop();
    }

    void NetworkController::Start()
    {
        if (m_running)
            return;
        m_running = true;
        m_thread = std::thread(&NetworkController::Run, this);
    }

    void NetworkController::Stop()
    {
        m_running = false;
        m_requestQueue.Shutdown();
        if (m_thread.joinable())
            m_thread.join();
    }

    void NetworkController::QueueRequest(net_ops::protocol::MessageType type, std::vector<uint8_t> payload)
    {
        m_requestQueue.Push({type, std::move(payload)});
    }

    std::optional<NetworkResponse> NetworkController::GetNextResponse()
    {
        if (m_responseQueue.Empty())
            return std::nullopt;
        return m_responseQueue.Pop();
    }

    void NetworkController::Run()
    {
        if (!m_network->Connect())
        {
            std::cerr << "[NetworkController] Connection failed.\n";
            m_running = false;
            return;
        }

        m_connected = true;
        std::cout << "[NetworkController] Background thread started.\n";

        while (m_running)
        {
            auto req = m_requestQueue.Pop();
            if (req && m_running)
            {
                m_network->SendRequest(req->type, req->payload);

                m_network->ReceiveResponse();
            }
        }

        m_network->Disconnect();
        m_connected = false;
    }
}