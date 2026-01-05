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

namespace net_ops::server
{

    std::string ReadString(const std::vector<uint8_t> &data, size_t &offset)
    {
        if (offset + 4 > data.size())
            return "";

        uint32_t len = 0;
        std::memcpy(&len, &data[offset], 4);
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
                    // CHANGED: Now passing payload
                    HandleGroupList(current_job.client_fd, current_job.payload);
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

    void Worker::HandleLogin(int client_fd, const std::vector<uint8_t>& payload) {
        size_t offset = 0;
        std::string username = ReadString(payload, offset);
        std::string password = ReadString(payload, offset);

        if (username.empty() || password.empty()) {
            if (network_core_) {
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "Invalid payload format");
            }
            return;
        }

        auto& db = DatabaseManager::GetInstance();
        auto user = db.GetUserByName(username);

        if (!user.has_value()) {
            std::cout << "[Worker] Login Failed: User '" << username << "' not found.\n";
            if (network_core_) {
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::LoginResp, "LOGIN_FAILURE: User not found");
            }
            return;
        }

        std::vector<uint8_t> computed_hash = ComputeHash(password, user->salt);

        if (computed_hash == user->password_hash) {
            std::cout << "[Worker] Login SUCCESS for user: " << username << "\n";
            
            std::string token = SessionManager::GetInstance().CreateSession(user->id);
            
            std::string response = "LOGIN_SUCCESS:" + token;

            if (network_core_) {
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::LoginResp, response);
            }
        } else {
            std::cout << "[Worker] Login Failed: Incorrect password for " << username << "\n";
            if (network_core_) {
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::LoginResp, "LOGIN_FAILURE: Incorrect Password");
            }
        }
    }

    void Worker::HandleRegister(int client_fd, const std::vector<uint8_t> &payload)
    {
        size_t offset = 0;
        std::string username = ReadString(payload, offset);
        std::string password = ReadString(payload, offset);

        if (username.empty() || password.empty())
        {
            if (network_core_)
            {
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "Invalid payload format");
            }
            return;
        }

        auto &db = DatabaseManager::GetInstance();

        std::vector<uint8_t> salt(16);
        if (RAND_bytes(salt.data(), 16) != 1)
        {
            std::cerr << "[Worker] OpenSSL RNG failed.\n";
            return;
        }

        std::vector<uint8_t> hash = ComputeHash(password, salt);

        if (db.CreateUser(username, hash, salt))
        {
            std::cout << "[Worker] Register SUCCESS: Created user '" << username << "'\n";
            if (network_core_)
            {
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::SignupResp, "SIGNUP_SUCCESS");
            }
        }
        else
        {
            std::cout << "[Worker] Register Failed: User '" << username << "' probably exists.\n";
            if (network_core_)
            {
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::SignupResp, "SIGNUP_FAILURE: User exists");
            }
        }
    }

    void Worker::HandleGroupCreate(int client_fd, const std::vector<uint8_t>& payload) {
        size_t offset = 0;
        
        std::string token = ReadString(payload, offset);
        std::string group_name = ReadString(payload, offset);

        if (token.empty() || group_name.empty()) {
            if (network_core_) {
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "Invalid payload");
            }
            return;
        }

        auto userIdOpt = SessionManager::GetInstance().GetUserId(token);
        
        if (!userIdOpt.has_value()) {
            std::cout << "[Worker] Group Create Denied: Invalid Session Token.\n";
            if (network_core_) {
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "AUTH_FAILED: Invalid Token");
            }
            return;
        }

        int owner_id = userIdOpt.value();

        auto& db = DatabaseManager::GetInstance();
        int group_id = db.CreateGroup(group_name, owner_id);

        if (group_id != -1) {
            std::cout << "[Worker] Group Created: '" << group_name << "' by UserID: " << owner_id << "\n";
            if (network_core_) {
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::GroupCreateResp, "GROUP_CREATED");
            }
        } else {
            std::cout << "[Worker] Group Creation Failed (Name taken?)\n";
            if (network_core_) {
                network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, "GROUP_CREATION_FAILED");
            }
        }
    }

    void Worker::HandleGroupList(int client_fd, const std::vector<uint8_t>& payload)
    {
        size_t offset = 0;
        std::string token = ReadString(payload, offset);

        auto userIdOpt = SessionManager::GetInstance().GetUserId(token);
        if (!userIdOpt.has_value()) {
            if (network_core_) {
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
}