#include "../client/SyslogCollector.hpp"
#include "../client/NetworkController.hpp"

int main()
{
    auto controller = std::make_shared<net_ops::client::NetworkController>("server_ip", 8888);
    auto collector = std::make_shared<net_ops::client::SyslogCollector>("/var/log/syslog", 514);

    collector->Start([controller](const net_ops::client::DataRecord &record)
                     {
        std::vector<uint8_t> payload;
        net_ops::protocol::PackString(payload, "AGENT_TOKEN");
        net_ops::protocol::PackString(payload, record.ip);
        net_ops::protocol::PackString(payload, record.message);
        controller->QueueRequest(net_ops::protocol::MessageType::LogUploadReq, payload); });

    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
}