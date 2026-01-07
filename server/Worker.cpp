#include "Worker.hpp"
#include "NetworkCore.hpp"
#include "DatabaseManager.hpp"
#include "SessionManager.hpp"

#include <iostream>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>
#include <netinet/in.h>

namespace net_ops::server
{

    std::string ReadString(const std::vector<uint8_t> &data, size_t &offset)
    {
        if (offset + 4 > data.size())
            return "";

        uint32_t netLen = 0;
        std::memcpy(&netLen, &data[offset], 4);
        uint32_t len = ntohl(netLen);
        offset += 4;

        if (offset + len > data.size())
            return "";

        std::string str(data.begin() + offset, data.begin() + offset + len);
        offset += len;
        return str;
    }

    std::vector<uint8_t> ComputeHash(const std::string &password, const std::vector<uint8_t> &salt)
    {
        std::vector<uint8_t> combined;
        combined.insert(combined.end(), password.begin(), password.end());
        combined.insert(combined.end(), salt.begin(), salt.end());

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(combined.data(), combined.size(), hash);

        return std::vector<uint8_t>(hash, hash + SHA256_DIGEST_LENGTH);
    }

    std::string ToHex(const std::vector<uint8_t> &data)
    {
        std::stringstream ss;
        for (uint8_t byte : data)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        return ss.str();
    }

    Worker::Worker() : running_(false), network_core_(nullptr) {}

    Worker::~Worker()
    {
        Stop();
    }

    void Worker::Start()
    {
        running_ = true;
        worker_thread_ = std::thread(&Worker::ProcessLoop, this);
    }

    void Worker::Stop()
    {
        if (!running_)
            return;

        running_ = false;
        queue_cv_.notify_all();

        if (worker_thread_.joinable())
        {
            worker_thread_.join();
        }
    }

    void Worker::AddJob(int client_fd, net_ops::protocol::MessageType type, std::vector<uint8_t> payload)
    {
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            job_queue_.push({client_fd, type, payload});
        }
        queue_cv_.notify_one();
    }

    void Worker::SetNetworkCore(NetworkCore *core)
    {
        network_core_ = core;
    }

    void Worker::ProcessLoop()
    {
        while (running_)
        {
            Job current_job;
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                queue_cv_.wait(lock, [this]
                               { return !job_queue_.empty() || !running_; });

                if (!running_ && job_queue_.empty())
                    break;

                current_job = job_queue_.front();
                job_queue_.pop();
            }

            try
            {
                switch (current_job.type)
                {
                case net_ops::protocol::MessageType::LoginReq:
                    HandleLogin(current_job.client_fd, current_job.payload);
                    break;
                case net_ops::protocol::MessageType::SignupReq:
                    HandleRegister(current_job.client_fd, current_job.payload);
                    break;
                case net_ops::protocol::MessageType::GroupCreateReq:
                    HandleGroupCreate(current_job.client_fd, current_job.payload);
                    break;
                case net_ops::protocol::MessageType::GroupListReq:
                    HandleGroupList(current_job.client_fd, current_job.payload);
                    break;
                case net_ops::protocol::MessageType::GroupAddMemberReq:
                    HandleGroupAddMember(current_job.client_fd, current_job.payload);
                    break;
                case net_ops::protocol::MessageType::DeviceAddReq:
                    HandleDeviceAdd(current_job.client_fd, current_job.payload);
                    break;
                case net_ops::protocol::MessageType::DeviceListReq:
                    HandleDeviceList(current_job.client_fd, current_job.payload);
                    break;
                case net_ops::protocol::MessageType::LogUploadReq:
                    HandleLogUpload(current_job.client_fd, current_job.payload);
                    break;
                case net_ops::protocol::MessageType::DeviceStatusReq:
                    HandleStatusUpdate(current_job.client_fd, current_job.payload);
                    break;
                case net_ops::protocol::MessageType::LogQueryReq:
                    HandleLogQuery(current_job.client_fd, current_job.payload);
                    break;
                case net_ops::protocol::MessageType::LogoutReq:
                    HandleLogout(current_job.client_fd, current_job.payload);
                    break;
                default:
                    break;
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << "[Worker] Error processing job: " << e.what() << "\n";
            }
        }
    }

    void Worker::HandleLogin(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;
        std::string username = ReadString(payload, offset);
        std::string password = ReadString(payload, offset);

        auto &db = DatabaseManager::GetInstance();
        auto user = db.GetUserByName(username);

        if (!user.has_value())
        {
            std::cout << "[Worker] Login Failed: User '" << username << "' not found.\n";
            if (network_core_)
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "LOGIN_FAILURE");
            return;
        }

        std::cout << "[Login Debug] User: " << username << "\n";
        std::cout << "   - DB Salt:       " << ToHex(user->salt) << "\n";
        std::cout << "   - DB Hash:       " << ToHex(user->password_hash) << "\n";

        std::vector<uint8_t> computed_hash = ComputeHash(password, user->salt);
        std::cout << "   - Computed Hash: " << ToHex(computed_hash) << "\n";

        if (computed_hash == user->password_hash)
        {
            std::cout << "[Worker] Login SUCCESS.\n";
            std::string token = SessionManager::GetInstance().CreateSession(user->id);
            if (network_core_)
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::LoginResp, "LOGIN_SUCCESS:" + token);
        }
        else
        {
            std::cout << "[Worker] Login Mismatch.\n";
            if (network_core_)
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "LOGIN_FAILURE");
        }
    }

    void Worker::HandleRegister(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;
        std::string username = ReadString(payload, offset);
        std::string password = ReadString(payload, offset);

        std::vector<uint8_t> salt(16);
        if (RAND_bytes(salt.data(), 16) != 1)
            return;

        std::vector<uint8_t> hash = ComputeHash(password, salt);

        std::cout << "[Register Debug] User: " << username << "\n";
        std::cout << "   - Generated Salt: " << ToHex(salt) << "\n";
        std::cout << "   - Generated Hash: " << ToHex(hash) << "\n";

        if (DatabaseManager::GetInstance().CreateUser(username, hash, salt))
        {
            if (network_core_)
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::SignupResp, "SIGNUP_SUCCESS");
        }
        else
        {
            if (network_core_)
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "SIGNUP_FAILURE");
        }
    }

    void Worker::HandleGroupCreate(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;

        std::string token = ReadString(payload, offset);
        std::string group_name = ReadString(payload, offset);

        if (token.empty() || group_name.empty())
        {
            if (network_core_)
            {
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "Invalid payload");
            }
            return;
        }

        auto userIdOpt = SessionManager::GetInstance().GetUserId(token);

        if (!userIdOpt.has_value())
        {
            std::cout << "[Worker] Group Create Denied: Invalid Session Token.\n";
            if (network_core_)
            {
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "AUTH_FAILED: Invalid Token");
            }
            return;
        }

        int owner_id = userIdOpt.value();

        auto &db = DatabaseManager::GetInstance();
        int group_id = db.CreateGroup(group_name, owner_id);

        if (group_id != -1)
        {
            std::cout << "[Worker] Group Created: '" << group_name << "' by UserID: " << owner_id << "\n";
            if (network_core_)
            {
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::GroupCreateResp, "GROUP_CREATED");
            }
        }
        else
        {
            std::cout << "[Worker] Group Creation Failed (Name taken?)\n";
            if (network_core_)
            {
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "GROUP_CREATION_FAILED");
            }
        }
    }

    void Worker::HandleGroupList(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;
        std::string token = ReadString(payload, offset);

        auto userIdOpt = SessionManager::GetInstance().GetUserId(token);
        if (!userIdOpt.has_value())
        {
            if (network_core_)
            {
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "AUTH_FAILED");
            }
            return;
        }

        int userId = userIdOpt.value();

        auto &db = DatabaseManager::GetInstance();
        auto groups = db.GetGroupsForUser(userId);

        std::string response;
        if (groups.empty())
        {
            response = "NO_GROUPS";
        }
        else
        {
            for (const auto &g : groups)
            {
                response += std::to_string(g.id) + ":" + g.name + ",";
            }
        }

        if (network_core_)
        {
            network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::GroupListResp, response);
        }
    }

    void Worker::HandleGroupAddMember(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;

        std::string token = ReadString(payload, offset);

        if (offset + 4 > payload.size())
            return;

        uint32_t net_group_id = 0;
        std::memcpy(&net_group_id, &payload[offset], 4);
        int group_id = static_cast<int>(ntohl(net_group_id));
        offset += 4;

        std::string new_member_name = ReadString(payload, offset);

        auto userIdOpt = SessionManager::GetInstance().GetUserId(token);
        if (!userIdOpt.has_value())
        {
            if (network_core_)
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "AUTH_FAILED");
            return;
        }
        int requestor_id = userIdOpt.value();

        auto &db = DatabaseManager::GetInstance();

        if (!db.IsGroupOwner(group_id, requestor_id))
        {
            std::cout << "[Worker] Access Denied: User " << requestor_id << " tried to modify Group " << group_id << "\n";
            if (network_core_)
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "ACCESS_DENIED: Not Owner");
            return;
        }

        auto targetUser = db.GetUserByName(new_member_name);
        if (!targetUser.has_value())
        {
            if (network_core_)
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "USER_NOT_FOUND");
            return;
        }

        if (db.AddMemberToGroup(targetUser->id, group_id))
        {
            std::cout << "[Worker] User " << new_member_name << " added to Group " << group_id << "\n";
            if (network_core_)
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::GroupAddMemberResp, "MEMBER_ADDED");
        }
        else
        {
            if (network_core_)
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "ADD_FAILED");
        }
    }

    void Worker::HandleDeviceAdd(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;
        std::string token = ReadString(payload, offset);

        auto userId = SessionManager::GetInstance().GetUserId(token);
        if (!userId.has_value())
        {
            network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "AUTH_FAILED");
            return;
        }

        uint32_t netGroupId = 0;
        std::memcpy(&netGroupId, &payload[offset], 4);
        int group_id = static_cast<int>(ntohl(netGroupId));
        offset += 4;

        std::string name = ReadString(payload, offset);
        std::string ip = ReadString(payload, offset);
        std::string mac = ReadString(payload, offset);

        if (DatabaseManager::GetInstance().AddDevice(userId.value(), group_id, name, ip, mac))
        {
            network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::DeviceAddResp, "DEVICE_ADDED");
        }
        else
        {
            network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "ADD_FAILED");
        }
    }

    void Worker::HandleDeviceList(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;
        std::string token = ReadString(payload, offset);

        auto userIdOpt = SessionManager::GetInstance().GetUserId(token);
        if (!userIdOpt.has_value())
        {
            if (network_core_)
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "AUTH_FAILED");
            return;
        }
        int user_id = userIdOpt.value();

        auto &db = DatabaseManager::GetInstance();
        auto devices = db.GetAllDevicesForUser(user_id);

        std::string response;
        if (devices.empty())
        {
            response = "NO_DEVICES";
        }
        else
        {
            for (const auto &d : devices)
            {
                response += std::to_string(d.id) + ":" + d.name + ":" + d.ip_address + ":" + d.status + ":" + std::to_string(d.group_id) + ":" + d.info + ",";
            }
        }

        if (network_core_)
        {
            network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::DeviceListResp, response);
        }
    }

    void Worker::HandleLogUpload(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;
        std::string token = ReadString(payload, offset);
        std::string device_ip = ReadString(payload, offset);
        std::string log_msg = ReadString(payload, offset);

        if (!SessionManager::GetInstance().GetUserId(token).has_value())
            return;

        DatabaseManager::GetInstance().SaveLog(device_ip, log_msg);
        std::cout << "[Worker] Processed log from " << device_ip << "\n";
    }

    void Worker::HandleStatusUpdate(int fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;
        std::string token = ReadString(payload, offset);
        std::string ip = ReadString(payload, offset);
        std::string status = ReadString(payload, offset);
        std::string info = ReadString(payload, offset);

        auto userIdOpt = SessionManager::GetInstance().GetUserId(token);
        if (!userIdOpt)
            return;

        DatabaseManager::GetInstance().UpdateDeviceStatus(ip, status, info);
    }

    void Worker::HandleLogQuery(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;

        std::string token = ReadString(payload, offset);

        if (offset + 4 > payload.size())
            return;

        uint32_t netDevId = 0;
        std::memcpy(&netDevId, &payload[offset], 4);
        int device_id = static_cast<int>(ntohl(netDevId));
        offset += 4;

        if (!SessionManager::GetInstance().GetUserId(token).has_value())
        {
            if (network_core_)
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "AUTH_FAILED");
            return;
        }

        auto logs = DatabaseManager::GetInstance().GetLogsForDevice(device_id);
        std::cout << "[Worker] Fetching " << logs.size() << " logs for Device " << device_id << "\n";

        std::vector<uint8_t> response;

        net_ops::protocol::PackUint32(response, static_cast<uint32_t>(logs.size()));

        for (const auto &log : logs)
        {
            net_ops::protocol::PackString(response, log.timestamp);
            net_ops::protocol::PackString(response, log.message);
        }

        if (network_core_)
        {
            std::string binaryPayload(response.begin(), response.end());
            network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::LogQueryResp, binaryPayload);
        }
    }

    void Worker::HandleLogout(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;
        std::string token = ReadString(payload, offset);

        if (!token.empty())
        {
            SessionManager::GetInstance().RemoveSession(token);
            std::cout << "[Worker] Session invalidated for Client FD: " << client_fd << "\n";
        }

        if (network_core_)
        {
            network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::LogoutResp, "LOGOUT_SUCCESS");
        }
    }
}