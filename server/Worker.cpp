#include "Worker.hpp"
#include "NetworkCore.hpp"
#include "DatabaseManager.hpp"
#include "SessionManager.hpp"
#include <iostream>
#include <cstring>
#include <netinet/in.h>

namespace net_ops::server
{
    Worker::Worker() : running_(false), network_core_(nullptr) {}
    Worker::~Worker() { Stop(); }

    void Worker::Start()
    {
        running_ = true;
        worker_thread_ = std::thread(&Worker::ProcessLoop, this);
    }

    void Worker::Stop()
    {
        running_ = false;
        queue_cv_.notify_all();
        if (worker_thread_.joinable())
            worker_thread_.join();
    }

    void Worker::SetNetworkCore(NetworkCore *core) { network_core_ = core; }

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
            Job job;
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                queue_cv_.wait(lock, [this]
                               { return !job_queue_.empty() || !running_; });
                if (!running_ && job_queue_.empty())
                    break;
                job = job_queue_.front();
                job_queue_.pop();
            }

            switch (job.type)
            {
            case net_ops::protocol::MessageType::LoginReq:
                HandleLogin(job.client_fd, job.payload);
                break;
            case net_ops::protocol::MessageType::SignupReq:
                HandleRegister(job.client_fd, job.payload);
                break;
            case net_ops::protocol::MessageType::GroupCreateReq:
                HandleGroupCreate(job.client_fd, job.payload);
                break;
            case net_ops::protocol::MessageType::GroupListReq:
                HandleGroupList(job.client_fd, job.payload);
                break;
            case net_ops::protocol::MessageType::GroupAddMemberReq:
                HandleGroupAddMember(job.client_fd, job.payload);
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
                HandleStatusUpdate(job.client_fd, job.payload);
                break;
            case net_ops::protocol::MessageType::LogQueryReq:
                HandleLogQuery(job.client_fd, job.payload);
                break;
            case net_ops::protocol::MessageType::LogoutReq:
                HandleLogout(job.client_fd, job.payload);
                break;
            default:
                break;
            }
        }
    }

    void Worker::HandleLogin(int fd, const std::vector<uint8_t> &p)
    {
        size_t off = 0;
        auto u = net_ops::protocol::UnpackString(p, off);
        auto pw = net_ops::protocol::UnpackString(p, off);

        if (!u || !pw)
        {
            network_core_->QueueResponse(fd, net_ops::protocol::MessageType::ErrorResp, "MALFORMED_REQUEST");
            return;
        }

        if (DatabaseManager::GetInstance().ValidateUser(*u, *pw))
        {
            auto user = DatabaseManager::GetInstance().GetUserByName(*u);
            if (user && network_core_)
            {
                std::string token = SessionManager::GetInstance().CreateSession(user->id);
                network_core_->QueueResponse(fd, net_ops::protocol::MessageType::LoginResp, "LOGIN_SUCCESS:" + token);
                return;
            }
        }
        network_core_->QueueResponse(fd, net_ops::protocol::MessageType::ErrorResp, "LOGIN_FAILURE");
    }

    void Worker::HandleRegister(int fd, const std::vector<uint8_t> &p)
    {
        size_t off = 0;
        auto u = net_ops::protocol::UnpackString(p, off);
        auto pw = net_ops::protocol::UnpackString(p, off);
        if (u && pw && DatabaseManager::GetInstance().CreateUser(*u, *pw))
            network_core_->QueueResponse(fd, net_ops::protocol::MessageType::SignupResp, "SIGNUP_SUCCESS");
        else
            network_core_->QueueResponse(fd, net_ops::protocol::MessageType::ErrorResp, "SIGNUP_FAILURE");
    }

    void Worker::HandleGroupCreate(int fd, const std::vector<uint8_t> &p)
    {
        size_t off = 0;
        auto t = net_ops::protocol::UnpackString(p, off);
        auto n = net_ops::protocol::UnpackString(p, off);
        if (t && n)
        {
            auto uid = SessionManager::GetInstance().GetUserId(*t);
            if (uid && DatabaseManager::GetInstance().CreateGroup(*n, *uid) != -1)
            {
                network_core_->QueueResponse(fd, net_ops::protocol::MessageType::GroupCreateResp, "GROUP_CREATED");
                return;
            }
        }
        network_core_->QueueResponse(fd, net_ops::protocol::MessageType::ErrorResp, "GROUP_CREATION_FAILED");
    }

    void Worker::HandleGroupList(int fd, const std::vector<uint8_t> &p)
    {
        size_t off = 0;
        auto t = net_ops::protocol::UnpackString(p, off);
        auto uid = t ? SessionManager::GetInstance().GetUserId(*t) : std::nullopt;
        if (!uid)
        {
            network_core_->QueueResponse(fd, net_ops::protocol::MessageType::ErrorResp, "AUTH_FAILED");
            return;
        }
        auto groups = DatabaseManager::GetInstance().GetGroupsForUser(*uid);
        std::string res = groups.empty() ? "NO_GROUPS" : "";
        for (const auto &g : groups)
            res += std::to_string(g.id) + ":" + g.name + ",";
        network_core_->QueueResponse(fd, net_ops::protocol::MessageType::GroupListResp, res);
    }

    void Worker::HandleGroupAddMember(int fd, const std::vector<uint8_t> &p)
    {
        size_t off = 0;
        auto t = net_ops::protocol::UnpackString(p, off);
        auto gid = net_ops::protocol::UnpackUint32(p, off);
        auto member = net_ops::protocol::UnpackString(p, off);

        auto uid = t ? SessionManager::GetInstance().GetUserId(*t) : std::nullopt;
        if (!uid || !gid || !member || !DatabaseManager::GetInstance().IsGroupOwner(*gid, *uid))
        {
            network_core_->QueueResponse(fd, net_ops::protocol::MessageType::ErrorResp, "ACCESS_DENIED");
            return;
        }
        auto target = DatabaseManager::GetInstance().GetUserByName(*member);
        if (target && DatabaseManager::GetInstance().AddMemberToGroup(target->id, *gid))
            network_core_->QueueResponse(fd, net_ops::protocol::MessageType::GroupAddMemberResp, "MEMBER_ADDED");
        else
            network_core_->QueueResponse(fd, net_ops::protocol::MessageType::ErrorResp, "ADD_FAILED");
    }

    void Worker::HandleDeviceAdd(int fd, const std::vector<uint8_t> &p)
    {
        size_t off = 0;
        auto t = net_ops::protocol::UnpackString(p, off);
        auto gid = net_ops::protocol::UnpackUint32(p, off);
        auto n = net_ops::protocol::UnpackString(p, off);
        auto ip = net_ops::protocol::UnpackString(p, off);
        auto mac = net_ops::protocol::UnpackString(p, off);

        auto uid = t ? SessionManager::GetInstance().GetUserId(*t) : std::nullopt;
        if (uid && gid && n && ip && mac && DatabaseManager::GetInstance().AddDevice(*uid, *gid, *n, *ip, *mac))
            network_core_->QueueResponse(fd, net_ops::protocol::MessageType::DeviceAddResp, "DEVICE_ADDED");
        else
            network_core_->QueueResponse(fd, net_ops::protocol::MessageType::ErrorResp, "ADD_FAILED");
    }

    void Worker::HandleDeviceList(int fd, const std::vector<uint8_t> &p)
    {
        size_t off = 0;
        auto t = net_ops::protocol::UnpackString(p, off);
        auto uid = t ? SessionManager::GetInstance().GetUserId(*t) : std::nullopt;
        if (!uid)
        {
            network_core_->QueueResponse(fd, net_ops::protocol::MessageType::ErrorResp, "AUTH_FAILED");
            return;
        }
        auto devs = DatabaseManager::GetInstance().GetAllDevicesForUser(*uid);
        std::string res = devs.empty() ? "NO_DEVICES" : "";
        for (const auto &d : devs)
            res += std::to_string(d.id) + ":" + d.name + ":" + d.ip_address + ":" + d.status + ":" + std::to_string(d.group_id) + ":" + d.info + ",";
        network_core_->QueueResponse(fd, net_ops::protocol::MessageType::DeviceListResp, res);
    }

    void Worker::HandleLogUpload(int fd, const std::vector<uint8_t> &p)
    {
        size_t off = 0;
        auto token = net_ops::protocol::UnpackString(p, off);
        auto ip = net_ops::protocol::UnpackString(p, off);
        auto msg = net_ops::protocol::UnpackString(p, off);

        if (token && ip && msg && SessionManager::GetInstance().GetUserId(*token))
        {
            DatabaseManager::GetInstance().SaveLog(*ip, *msg);
        }
    }

    void Worker::HandleStatusUpdate(int fd, const std::vector<uint8_t> &p)
    {
        size_t off = 0;
        auto t = net_ops::protocol::UnpackString(p, off);
        auto ip = net_ops::protocol::UnpackString(p, off);
        auto st = net_ops::protocol::UnpackString(p, off);
        auto inf = net_ops::protocol::UnpackString(p, off);
        if (t && ip && st && inf && SessionManager::GetInstance().GetUserId(*t))
            DatabaseManager::GetInstance().UpdateDeviceStatus(*ip, *st, *inf);
    }

    void Worker::HandleLogQuery(int fd, const std::vector<uint8_t> &p)
    {
        size_t off = 0;
        auto t = net_ops::protocol::UnpackString(p, off);
        auto dev_id = net_ops::protocol::UnpackUint32(p, off);
        if (t && dev_id && SessionManager::GetInstance().GetUserId(*t))
        {
            auto logs = DatabaseManager::GetInstance().GetLogsForDevice(*dev_id);
            std::vector<uint8_t> res;
            net_ops::protocol::PackUint32(res, (uint32_t)logs.size());
            for (const auto &l : logs)
            {
                net_ops::protocol::PackString(res, l.timestamp);
                net_ops::protocol::PackString(res, l.message);
            }
            network_core_->QueueResponse(fd, net_ops::protocol::MessageType::LogQueryResp, std::string(res.begin(), res.end()));
        }
        else
        {
            network_core_->QueueResponse(fd, net_ops::protocol::MessageType::ErrorResp, "AUTH_FAILED");
        }
    }

    void Worker::HandleLogout(int fd, const std::vector<uint8_t> &p)
    {
        size_t off = 0;
        auto t = net_ops::protocol::UnpackString(p, off);
        if (t)
            SessionManager::GetInstance().RemoveSession(*t);
        network_core_->QueueResponse(fd, net_ops::protocol::MessageType::LogoutResp, "LOGOUT_SUCCESS");
    }
}