#include "Worker.hpp"
#include "NetworkCore.hpp"
#include "DatabaseManager.hpp"
#include "SessionManager.hpp"
#include <iostream>

namespace net_ops::server
{
    Worker::Worker() : running_(false), network_core_(nullptr) {}
    Worker::~Worker() { Stop(); }

    void Worker::Start() {
        running_ = true;
        worker_thread_ = std::thread(&Worker::ProcessLoop, this);
    }

    void Worker::Stop() {
        running_ = false;
        queue_cv_.notify_all();
        if (worker_thread_.joinable()) worker_thread_.join();
    }

    void Worker::SetNetworkCore(NetworkCore *core) { network_core_ = core; }

    void Worker::AddJob(int client_fd, net_ops::protocol::MessageType type, std::vector<uint8_t> payload) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            job_queue_.push({client_fd, type, payload});
        }
        queue_cv_.notify_one();
    }

    std::optional<int> Worker::Authorize(int client_fd, const std::optional<std::string>& token) {
        if (!token) {
            SendError(client_fd, "MISSING_TOKEN");
            return std::nullopt;
        }
        auto uid = SessionManager::GetInstance().GetUserId(*token);
        if (!uid) {
            SendError(client_fd, "INVALID_SESSION");
            return std::nullopt;
        }
        return uid;
    }

    void Worker::SendError(int client_fd, const std::string& message) {
        std::vector<uint8_t> resp;
        net_ops::protocol::PackString(resp, message);
        network_core_->QueueResponse(client_fd, net_ops::protocol::MessageType::ErrorResp, resp);
    }

    void Worker::ProcessLoop() {
        while (running_) {
            Job job;
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                queue_cv_.wait(lock, [this] { return !job_queue_.empty() || !running_; });
                if (!running_ && job_queue_.empty()) break;
                job = job_queue_.front();
                job_queue_.pop();
            }

            switch (job.type) {
                case net_ops::protocol::MessageType::LoginReq: HandleLogin(job.client_fd, job.payload); break;
                case net_ops::protocol::MessageType::SignupReq: HandleRegister(job.client_fd, job.payload); break;
                case net_ops::protocol::MessageType::DeviceAddReq: HandleDeviceAdd(job.client_fd, job.payload); break;
                case net_ops::protocol::MessageType::DeviceListReq: HandleDeviceList(job.client_fd, job.payload); break;
                case net_ops::protocol::MessageType::LogUploadReq: HandleLogUpload(job.client_fd, job.payload); break;
                case net_ops::protocol::MessageType::DeviceStatusReq: HandleStatusUpdate(job.client_fd, job.payload); break;
                case net_ops::protocol::MessageType::LogQueryReq: HandleLogQuery(job.client_fd, job.payload); break;
                case net_ops::protocol::MessageType::LogoutReq: HandleLogout(job.client_fd, job.payload); break;
                default: break;
            }
        }
    }

    void Worker::HandleLogin(int fd, const std::vector<uint8_t> &p) {
        size_t off = 0;
        auto u = net_ops::protocol::UnpackString(p, off);
        auto pw = net_ops::protocol::UnpackString(p, off);
        
        if (!u || !pw) { SendError(fd, "MALFORMED_LOGIN"); return; }

        if (DatabaseManager::GetInstance().ValidateUser(*u, *pw)) {
            auto user = DatabaseManager::GetInstance().GetUserByName(*u);
            if (user) {
                std::string token = SessionManager::GetInstance().CreateSession(user->id);
                std::vector<uint8_t> resp;
                net_ops::protocol::PackString(resp, "LOGIN_SUCCESS:" + token);
                network_core_->QueueResponse(fd, net_ops::protocol::MessageType::LoginResp, resp);
                return;
            }
        }
        SendError(fd, "INVALID_CREDENTIALS");
    }

    void Worker::HandleRegister(int fd, const std::vector<uint8_t> &p) {
        size_t off = 0;
        auto u = net_ops::protocol::UnpackString(p, off);
        auto pw = net_ops::protocol::UnpackString(p, off);
        
        if (u && pw && DatabaseManager::GetInstance().CreateUser(*u, *pw)) {
            std::vector<uint8_t> resp; net_ops::protocol::PackString(resp, "SIGNUP_SUCCESS");
            network_core_->QueueResponse(fd, net_ops::protocol::MessageType::SignupResp, resp);
        } else {
            SendError(fd, "SIGNUP_FAILED");
        }
    }

    void Worker::HandleDeviceAdd(int fd, const std::vector<uint8_t> &p) {
        size_t off = 0;
        auto token = net_ops::protocol::UnpackString(p, off);
        auto uid = Authorize(fd, token);
        if (!uid) return;

        auto name = net_ops::protocol::UnpackString(p, off);
        auto ip = net_ops::protocol::UnpackString(p, off);
        auto mac = net_ops::protocol::UnpackString(p, off);

        if (name && ip && mac && DatabaseManager::GetInstance().AddDevice(*uid, *name, *ip, *mac)) {
            std::vector<uint8_t> resp; net_ops::protocol::PackString(resp, "DEVICE_ADDED");
            network_core_->QueueResponse(fd, net_ops::protocol::MessageType::DeviceAddResp, resp);
        } else {
            SendError(fd, "DEVICE_ADD_FAILED");
        }
    }

    void Worker::HandleDeviceList(int fd, const std::vector<uint8_t> &p) {
        size_t off = 0;
        auto token = net_ops::protocol::UnpackString(p, off);
        auto uid = Authorize(fd, token);
        if (!uid) return;

        auto devs = DatabaseManager::GetInstance().GetAllDevicesForUser(*uid);
        std::vector<uint8_t> resp;
        net_ops::protocol::PackUint32(resp, static_cast<uint32_t>(devs.size()));
        for (const auto &d : devs) {
            net_ops::protocol::PackUint32(resp, d.id);
            net_ops::protocol::PackString(resp, d.name);
            net_ops::protocol::PackString(resp, d.ip_address);
            net_ops::protocol::PackString(resp, d.status);
            net_ops::protocol::PackString(resp, d.info);
        }
        network_core_->QueueResponse(fd, net_ops::protocol::MessageType::DeviceListResp, resp);
    }

    void Worker::HandleLogUpload(int fd, const std::vector<uint8_t> &p) {
        size_t off = 0;
        auto token = net_ops::protocol::UnpackString(p, off);
        if (!Authorize(fd, token)) return;

        auto ip = net_ops::protocol::UnpackString(p, off);
        auto msg = net_ops::protocol::UnpackString(p, off);
        
        if (ip && msg) {
            DatabaseManager::GetInstance().SaveLog(*ip, *msg);
            std::vector<uint8_t> ack; net_ops::protocol::PackString(ack, "LOG_OK");
            network_core_->QueueResponse(fd, net_ops::protocol::MessageType::LogUploadResp, ack);
        }
    }

    void Worker::HandleStatusUpdate(int fd, const std::vector<uint8_t> &p) {
        size_t off = 0;
        auto token = net_ops::protocol::UnpackString(p, off);
        if (!Authorize(fd, token)) return;

        auto ip = net_ops::protocol::UnpackString(p, off);
        auto st = net_ops::protocol::UnpackString(p, off);
        auto inf = net_ops::protocol::UnpackString(p, off);
        
        if (ip && st && inf) {
            DatabaseManager::GetInstance().UpdateDeviceStatus(*ip, *st, *inf);
            std::vector<uint8_t> ack; net_ops::protocol::PackString(ack, "STATUS_OK");
            network_core_->QueueResponse(fd, net_ops::protocol::MessageType::DeviceStatusResp, ack);
        }
    }

    void Worker::HandleLogQuery(int fd, const std::vector<uint8_t> &p) {
        size_t off = 0;
        auto token = net_ops::protocol::UnpackString(p, off);
        if (!Authorize(fd, token)) return;

        auto dev_id = net_ops::protocol::UnpackUint32(p, off);
        if (dev_id) {
            auto logs = DatabaseManager::GetInstance().GetLogsForDevice(*dev_id);
            std::vector<uint8_t> resp;
            net_ops::protocol::PackUint32(resp, (uint32_t)logs.size());
            for (const auto &l : logs) {
                net_ops::protocol::PackString(resp, l.timestamp);
                net_ops::protocol::PackString(resp, l.message);
            }
            network_core_->QueueResponse(fd, net_ops::protocol::MessageType::LogQueryResp, resp);
        }
    }

    void Worker::HandleLogout(int fd, const std::vector<uint8_t> &p) {
        size_t off = 0;
        auto t = net_ops::protocol::UnpackString(p, off);
        if (t) SessionManager::GetInstance().RemoveSession(*t);
        std::vector<uint8_t> resp; net_ops::protocol::PackString(resp, "LOGOUT_OK");
        network_core_->QueueResponse(fd, net_ops::protocol::MessageType::LogoutResp, resp);
    }
}