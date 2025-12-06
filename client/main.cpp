#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <cstring>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "../common/protocol.hpp"

#define PORT 8080
#define SA struct sockaddr

int main() {
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1) {
        std::cout << "socket creation failed...\n";
        exit(0);
    }
    else std::cout << "Socket successfully created...\n";

    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(PORT);

    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
        std::cout << "connection with the servre failed..\n";
        exit(0);
    }
    else std::cout << "connected to server..\n";


    std::string test_payload = "HelloServer";
    net_ops::protocol::Header PacketHeader;
    PacketHeader.magic = net_ops::protocol::EXPECTED_MAGIC;
    PacketHeader.msg_type = static_cast<uint8_t> (net_ops::protocol::MessageType::LoginReq);
    PacketHeader.payload_length = sizeof(test_payload);

    std::uint8_t* buffer;

    SerializeHeader(PacketHeader, buffer);

    

    close(sockfd);

    return 0;
}