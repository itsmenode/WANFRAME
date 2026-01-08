#include "Worker.hpp"
#include "NetworkCore.hpp"
#include "DatabaseManager.hpp"
#include "SessionManager.hpp"
#include <iostream>

namespace net_ops::server
{
    Worker::Worker() : m_networkCore(nullptr), m_running(false)
    {
    }

    Worker::~Worker()
    {
        Stop();
    }

    void Worker::SetNetworkCore(NetworkCore *core)
    {
        m_networkCore = core;
    }

    void Worker::Start(size_t threadCount)
    {
        m_running = true;
        for (size_t i = 0; i < threadCount; ++i)
        {
            m_threads.emplace_back(&Worker::Run, this);
        }
    }

    void Worker::Stop()
    {
        m_running = false;
        m_cv.notify_all();
        for (auto &t : m_threads)
        {
            if (t.joinable())
                t.join();
        }
        m_threads.clear();
    }

    void Worker::AddJob(int client_fd, net_ops::protocol::MessageType type, std::vector<uint8_t> payload)
    {
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            m_jobQueue.push({client_fd, type, std::move(payload)});
        }
        m_cv.notify_one();
    }

    void Worker::Run()
    {
        while (m_running)
        {
            Job job;
            {
                std::unique_lock<std::mutex> lock(m_queueMutex);
                m_cv.wait(lock, [this]
                          { return !m_jobQueue.empty() || !m_running; });

                if (!m_running && m_jobQueue.empty())
                    break;

                job = std::move(m_jobQueue.front());
                m_jobQueue.pop();
            }

            ProcessJob(job);
        }
    }

    void Worker::ProcessJob(const Job &job)
    {
        if (!m_networkCore)
            return;

        try
        {
            switch (job.type)
            {
            case net_ops::protocol::MessageType::LoginReq:
                HandleLogin(job.client_fd, job.payload);
                break;
            case net_ops::protocol::MessageType::SignupReq:
                HandleSignup(job.client_fd, job.payload);
                break;
            case net_ops::protocol::MessageType::DeviceAddReq:
                HandleDeviceAdd(job.client_fd, job.payload);
                break;
            case net_ops::protocol::MessageType::DeviceListReq:
                HandleDeviceList(job.client_fd, job.payload);
                break;
            case net_ops::protocol::MessageType::LogUploadReq:
                HandleLogUpload(job.client_fd, job.payload);
                break;
            case net_ops::protocol::MessageType::DeviceStatusReq:
                HandleDeviceStatus(job.client_fd, job.payload);
                break;
            case net_ops::protocol::MessageType::LogQueryReq:
                HandleLogQuery(job.client_fd, job.payload);
                break;
            case net_ops::protocol::MessageType::LogoutReq:
                HandleLogout(job.client_fd, job.payload);
                break;
            default:
                std::cerr << "[Worker] Unknown message type: " << (int)job.type << "\n";
                break;
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "[Worker] Exception processing job: " << e.what() << "\n";
            std::vector<uint8_t> errPayload;
            net_ops::protocol::PackString(errPayload, "INTERNAL_SERVER_ERROR");
            m_networkCore->QueueResponse(job.client_fd, net_ops::protocol::MessageType::ErrorResp, errPayload);
        }
    }

    void Worker::HandleLogin(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;
        auto username = net_ops::protocol::UnpackString(payload, offset);
        auto password = net_ops::protocol::UnpackString(payload, offset);

        std::vector<uint8_t> response;

        if (username && password)
        {
            if (DatabaseManager::GetInstance().ValidateUser(*username, *password))
            {
                auto user = DatabaseManager::GetInstance().GetUserByName(*username);
                if (user)
                {
                    std::string token = SessionManager::GetInstance().CreateSession(user->id);
                    net_ops::protocol::PackString(response, "LOGIN_SUCCESS:" + token);
                    m_networkCore->QueueResponse(client_fd, net_ops::protocol::MessageType::LoginResp, response);
                    return;
                }
            }
        }

        net_ops::protocol::PackString(response, "LOGIN_FAILED");
        m_networkCore->QueueResponse(client_fd, net_ops::protocol::MessageType::LoginResp, response);
    }

    void Worker::HandleSignup(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;
        auto username = net_ops::protocol::UnpackString(payload, offset);
        auto password = net_ops::protocol::UnpackString(payload, offset);

        std::vector<uint8_t> response;

        if (username && password)
        {
            if (DatabaseManager::GetInstance().CreateUser(*username, *password))
            {
                net_ops::protocol::PackString(response, "SIGNUP_SUCCESS");
                m_networkCore->QueueResponse(client_fd, net_ops::protocol::MessageType::SignupResp, response);
                return;
            }
            else
            {
                net_ops::protocol::PackString(response, "SIGNUP_FAILED: User likely exists");
                m_networkCore->QueueResponse(client_fd, net_ops::protocol::MessageType::SignupResp, response);
                return;
            }
        }

        net_ops::protocol::PackString(response, "SIGNUP_FAILED: Invalid format");
        m_networkCore->QueueResponse(client_fd, net_ops::protocol::MessageType::SignupResp, response);
    }

    void Worker::HandleDeviceAdd(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;
        auto token = net_ops::protocol::UnpackString(payload, offset);
        auto name = net_ops::protocol::UnpackString(payload, offset);
        auto ip = net_ops::protocol::UnpackString(payload, offset);
        auto mac = net_ops::protocol::UnpackString(payload, offset);

        if (!token || !name || !ip || !mac)
            return;

        auto userId = SessionManager::GetInstance().GetUserId(*token);
        if (!userId)
        {
            std::vector<uint8_t> resp;
            net_ops::protocol::PackString(resp, "AUTH_FAILED");
            m_networkCore->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, resp);
            return;
        }

        bool success = DatabaseManager::GetInstance().AddDevice(*userId, *name, *ip, *mac);

        std::vector<uint8_t> response;
        net_ops::protocol::PackString(response, success ? "DEVICE_ADDED" : "DEVICE_ADD_FAILED");
        m_networkCore->QueueResponse(client_fd, net_ops::protocol::MessageType::DeviceAddResp, response);
    }

    void Worker::HandleDeviceList(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;
        auto token = net_ops::protocol::UnpackString(payload, offset);

        if (!token)
            return;

        auto userId = SessionManager::GetInstance().GetUserId(*token);
        if (!userId)
        {
            std::vector<uint8_t> resp;
            net_ops::protocol::PackString(resp, "AUTH_FAILED");
            m_networkCore->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, resp);
            return;
        }

        auto devices = DatabaseManager::GetInstance().GetAllDevicesForUser(*userId);

        std::vector<uint8_t> response;
        net_ops::protocol::PackUint32(response, static_cast<uint32_t>(devices.size()));

        for (const auto &dev : devices)
        {
            net_ops::protocol::PackUint32(response, static_cast<uint32_t>(dev.id));
            net_ops::protocol::PackString(response, dev.name);
            net_ops::protocol::PackString(response, dev.ip_address);
            net_ops::protocol::PackString(response, dev.status);
            net_ops::protocol::PackString(response, dev.info);
        }

        m_networkCore->QueueResponse(client_fd, net_ops::protocol::MessageType::DeviceListResp, response);
    }

    void Worker::HandleLogUpload(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;
        auto token = net_ops::protocol::UnpackString(payload, offset);
        auto sourceIp = net_ops::protocol::UnpackString(payload, offset);
        auto msg = net_ops::protocol::UnpackString(payload, offset);

        if (!token || !sourceIp || !msg)
            return;

        if (!SessionManager::GetInstance().GetUserId(*token))
            return;

        DatabaseManager::GetInstance().SaveLog(*sourceIp, *msg);

        std::vector<uint8_t> response;
        net_ops::protocol::PackString(response, "LOG_SAVED");
        m_networkCore->QueueResponse(client_fd, net_ops::protocol::MessageType::LogUploadResp, response);
    }

    void Worker::HandleDeviceStatus(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;
        auto token = net_ops::protocol::UnpackString(payload, offset);
        auto ip = net_ops::protocol::UnpackString(payload, offset);
        auto status = net_ops::protocol::UnpackString(payload, offset);
        auto info = net_ops::protocol::UnpackString(payload, offset);

        if (!token || !ip || !status || !info)
            return;

        if (!SessionManager::GetInstance().GetUserId(*token))
            return;

        DatabaseManager::GetInstance().UpdateDeviceStatus(*ip, *status, *info);
    }

    void Worker::HandleLogQuery(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;
        auto token = net_ops::protocol::UnpackString(payload, offset);
        auto deviceId = net_ops::protocol::UnpackUint32(payload, offset);

        if (!token || !deviceId)
        {
            std::vector<uint8_t> resp;
            net_ops::protocol::PackString(resp, "INVALID_REQUEST");
            m_networkCore->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, resp);
            return;
        }

        auto userId = SessionManager::GetInstance().GetUserId(*token);
        if (!userId)
        {
            std::vector<uint8_t> resp;
            net_ops::protocol::PackString(resp, "AUTH_FAILED");
            m_networkCore->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, resp);
            return;
        }

        if (!DatabaseManager::GetInstance().IsUserDeviceOwner(*userId, *deviceId))
        {
            std::vector<uint8_t> resp;
            net_ops::protocol::PackString(resp, "DEVICE_ACCESS_DENIED");
            m_networkCore->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, resp);
            return;
        }

        auto logs = DatabaseManager::GetInstance().GetLogsForDevice(*deviceId);

        std::vector<uint8_t> response;
        net_ops::protocol::PackUint32(response, static_cast<uint32_t>(logs.size()));

        for (const auto &l : logs)
        {
            net_ops::protocol::PackString(response, l.timestamp);
            net_ops::protocol::PackString(response, l.message);
        }

        m_networkCore->QueueResponse(client_fd, net_ops::protocol::MessageType::LogQueryResp, response);
    }

    void Worker::HandleLogout(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;
        auto token = net_ops::protocol::UnpackString(payload, offset);

        std::vector<uint8_t> response;

        if (!token)
        {
            net_ops::protocol::PackString(response, "LOGOUT_FAILED");
            m_networkCore->QueueResponse(client_fd, net_ops::protocol::MessageType::LogoutResp, response);
            return;
        }

        if (!SessionManager::GetInstance().RemoveSession(*token))
        {
            net_ops::protocol::PackString(response, "LOGOUT_FAILED");
            m_networkCore->QueueResponse(client_fd, net_ops::protocol::MessageType::LogoutResp, response);
            return;
        }

        net_ops::protocol::PackString(response, "LOGOUT_SUCCESS");
        m_networkCore->QueueResponse(client_fd, net_ops::protocol::MessageType::LogoutResp, response);
    }
}
