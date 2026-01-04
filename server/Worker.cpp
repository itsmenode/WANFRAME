#include "Worker.hpp"
#include <iostream>

namespace net_ops::server {

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
            } catch (...) {}
        }
    }

    void Worker::HandleLogin(int client_fd, const std::vector<uint8_t>& payload) {
        std::cout << "[Worker] Processing Login for Client " << client_fd << "\n";
    }

    void Worker::HandleRegister(int client_fd, const std::vector<uint8_t>& payload) {
        std::cout << "[Worker] Processing Signup for Client " << client_fd << "\n";
    }
}