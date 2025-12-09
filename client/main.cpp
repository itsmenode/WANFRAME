#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <cstring> // For std::memset

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "../common/protocol.hpp"

#define PORT 8080

int main() {
    int sockfd;
    struct sockaddr_in servaddr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        std::cerr << "Socket creation failed...\n";
        return -1;
    }

    std::memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(PORT);

    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
        std::cerr << "Connection to server failed. Is the server running?\n";
        return -1;
    }
    std::cout << "Connected to server. Starting Stress Test...\n";

    std::string payload = "AdminUser";
    
    net_ops::protocol::Header header;
    header.magic = net_ops::protocol::EXPECTED_MAGIC;
    header.msg_type = static_cast<uint8_t>(net_ops::protocol::MessageType::LoginReq);
    header.payload_length = static_cast<uint32_t>(payload.size());
    header.reserved = 0;
    uint8_t header_buf[net_ops::protocol::HEADER_SIZE];
    net_ops::protocol::SerializeHeader(header, header_buf);

    
    std::cout << "[Test] Sending first 4 bytes of header...\n";
    send(sockfd, header_buf, 4, 0); 
    
    std::cout << "[Test] Sleeping for 2 seconds (simulating lag)...\n";
    std::this_thread::sleep_for(std::chrono::seconds(2));

    std::cout << "[Test] Sending remaining 4 bytes of header...\n";
    send(sockfd, header_buf + 4, 4, 0);

    std::cout << "[Test] Sleeping for 1 second...\n";
    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::cout << "[Test] Sending Payload...\n";
    send(sockfd, payload.data(), payload.size(), 0);

    std::cout << "[Test] Waiting for response...\n";
    
    uint8_t recv_buf[1024];
    ssize_t n = recv(sockfd, recv_buf, sizeof(recv_buf), 0);

    if (n > 0) {
        std::cout << "SUCCESS: Received " << n << " bytes from server!\n";
        
        if (n >= net_ops::protocol::HEADER_SIZE) {
            auto resp_header = net_ops::protocol::DeserializeHeader(recv_buf);
            if (resp_header.msg_type == static_cast<uint8_t>(net_ops::protocol::MessageType::LoginResp)) {
                std::cout << "Packet Type Verified: LoginResp\n";
            }
        }
    } else {
        std::cout << "FAILURE: Server closed connection or error.\n";
    }

    close(sockfd);
    return 0;
}