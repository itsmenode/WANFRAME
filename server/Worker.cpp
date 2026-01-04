#include "Worker.hpp"
#include "DatabaseManager.hpp"
#include <iostream>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>

namespace net_ops::server {

    std::string ReadString(const std::vector<uint8_t>& data, size_t& offset) {
        if (offset + 4 > data.size()) return "";
        
        uint32_t len = 0;
        std::memcpy(&len, &data[offset], 4);
        offset += 4;

        if (offset + len > data.size()) return "";

        std::string str(data.begin() + offset, data.begin() + offset + len);
        offset += len;
        return str;
    }

    std::vector<uint8_t> ComputeHash(const std::string& password, const std::vector<uint8_t>& salt) {
        std::vector<uint8_t> combined;
        combined.insert(combined.end(), password.begin(), password.end());
        combined.insert(combined.end(), salt.begin(), salt.end());

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(combined.data(), combined.size(), hash);

        return std::vector<uint8_t>(hash, hash + SHA256_DIGEST_LENGTH);
    }

    Worker::Worker() : running_(false) {}

    Worker::~Worker() {
        Stop();
    }

    void Worker::Start() {
        running_ = true;
        worker_thread_ = std::thread(&Worker::ProcessLoop, this);
    }

    void Worker::Stop() {
        if (!running_) return;

        running_ = false;
        queue_cv_.notify_all();
        
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
    }

    void Worker::AddJob(int client_fd, net_ops::protocol::MessageType type, std::vector<uint8_t> payload) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            job_queue_.push({client_fd, type, payload});
        }
        queue_cv_.notify_one();
    }

    void Worker::ProcessLoop() {
        while (running_) {
            Job current_job;

            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                
                queue_cv_.wait(lock, [this] {
                    return !job_queue_.empty() || !running_;
                });

                if (!running_ && job_queue_.empty()) break;

                current_job = job_queue_.front();
                job_queue_.pop();
            }

            try {
                switch (current_job.type) {
                    case net_ops::protocol::MessageType::LoginReq: 
                        HandleLogin(current_job.client_fd, current_job.payload);
                        break;
                    
                    case net_ops::protocol::MessageType::SignupReq:
                        HandleRegister(current_job.client_fd, current_job.payload);
                        break;

                    default:
                        break;
                }
            } catch (const std::exception& e) {
                std::cerr << "[Worker] Error: " << e.what() << "\n";
            }
        }
    }

    void Worker::HandleLogin(int client_fd, const std::vector<uint8_t>& payload) {
        size_t offset = 0;
        std::string username = ReadString(payload, offset);
        std::string password = ReadString(payload, offset);

        if (username.empty() || password.empty()) {
            std::cerr << "[Worker] Login Failed: Invalid payload format.\n";
            return;
        }

        auto& db = DatabaseManager::GetInstance();
        auto user = db.GetUserByName(username);

        if (!user.has_value()) {
            std::cout << "[Worker] Login Failed: User '" << username << "' not found.\n";
            return;
        }
        std::vector<uint8_t> computed_hash = ComputeHash(password, user->salt);

        if (computed_hash == user->password_hash) {
            std::cout << "[Worker] Login SUCCESS for user: " << username << "\n";

        } else {
            std::cout << "[Worker] Login Failed: Incorrect password for " << username << "\n";

        }
    }

    void Worker::HandleRegister(int client_fd, const std::vector<uint8_t>& payload) {
        size_t offset = 0;
        std::string username = ReadString(payload, offset);
        std::string password = ReadString(payload, offset);

        if (username.empty() || password.empty()) {
            std::cerr << "[Worker] Register Failed: Invalid payload format.\n";
            return;
        }

        auto& db = DatabaseManager::GetInstance();

        std::vector<uint8_t> salt(16);
        if (RAND_bytes(salt.data(), 16) != 1) {
            std::cerr << "[Worker] OpenSSL RNG failed.\n";
            return;
        }

        std::vector<uint8_t> hash = ComputeHash(password, salt);

        if (db.CreateUser(username, hash, salt)) {
            std::cout << "[Worker] Register SUCCESS: Created user '" << username << "'\n";

        } else {
            std::cout << "[Worker] Register Failed: User '" << username << "' probably exists.\n";

        }
    }
}