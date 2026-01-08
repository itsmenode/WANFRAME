#include "../client/SyslogCollector.hpp"
#include "../client/NetworkController.hpp"
#include <iostream>

int main(int argc, char* argv[])
{
    if (argc < 3) {
        std::cout << "Usage: ./Agent <ServerIP> <ServerPort> [SyslogPort]\n";
        return 1;
    }

    std::string serverIp = argv[1];
    int serverPort = std::stoi(argv[2]);
    int syslogPort = (argc > 3) ? std::stoi(argv[3]) : 514;

    auto controller = std::make_shared<net_ops::client::NetworkController>(serverIp, serverPort);
    auto collector = std::make_shared<net_ops::client::SyslogCollector>("/var/log/syslog", syslogPort);

    collector->Start([controller](const net_ops::client::DataRecord &record)
    {
        std::vector<uint8_t> payload;
        net_ops::protocol::PackString(payload, "AGENT_TOKEN_123"); 
        net_ops::protocol::PackString(payload, record.ip);
        net_ops::protocol::PackString(payload, record.message);
        controller->QueueRequest(net_ops::protocol::MessageType::LogUploadReq, payload); 
    });

    std::cout << "[Agent] Running. Forwarding to " << serverIp << ":" << serverPort << "\n";
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
}