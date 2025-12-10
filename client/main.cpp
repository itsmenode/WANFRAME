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

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../common/protocol.hpp"

#define PORT 8080

void ShowCerts(SSL* ssl) {
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert != nullptr) {
        std::cout << "[Client] Server Certificate Subject: " 
                  << X509_NAME_oneline(X509_get_subject_name(cert), 0, 0) << std::endl;
        X509_free(cert);
    } else {
        std::cout << "[Client] Info: No certificates configured.\n";
    }
}

int main() {
    int sockfd;
    struct sockaddr_in servaddr;

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "Unable to create SSL context\n";
        return -1;
    }

    if (SSL_CTX_load_verify_locations(ctx, "certs/ca.crt", nullptr) <= 0) {
        std::cerr << "Failed to load Root CA (certs/ca.crt). Verification will fail.\n";
    }

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
        std::cerr << "Connection to server failed.\n";
        return -1;
    }
    std::cout << "[Client] TCP Connected.\n";

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        std::cerr << "[Client] TLS Handshake Failed!\n";
        return -1;
    }

    std::cout << "[Client] TLS Handshake Success! Cipher: " << SSL_get_cipher(ssl) << std::endl;
    ShowCerts(ssl);

    
    std::string payload = "AdminUser";
    net_ops::protocol::Header header;
    header.magic = net_ops::protocol::EXPECTED_MAGIC;
    header.msg_type = static_cast<uint8_t>(net_ops::protocol::MessageType::LoginReq);
    header.payload_length = static_cast<uint32_t>(payload.size());
    header.reserved = 0;

    uint8_t header_buf[net_ops::protocol::HEADER_SIZE];
    net_ops::protocol::SerializeHeader(header, header_buf);

    std::cout << "\n--- Starting Fragmentation Test ---\n";

    std::cout << "[Test] Sending Partial Header (4 bytes)...\n";
    SSL_write(ssl, header_buf, 4); 
    
    std::cout << "[Test] Sleeping 2s...\n";
    std::this_thread::sleep_for(std::chrono::seconds(2));

    std::cout << "[Test] Sending Remaining Header...\n";
    SSL_write(ssl, header_buf + 4, 4);

    std::cout << "[Test] Sleeping 1s...\n";
    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::cout << "[Test] Sending Payload...\n";
    SSL_write(ssl, payload.data(), payload.size());

    std::cout << "[Test] Waiting for encrypted response...\n";
    
    uint8_t recv_buf[1024];
    int bytes = SSL_read(ssl, recv_buf, sizeof(recv_buf));

    if (bytes > 0) {
        std::cout << "SUCCESS: Decrypted " << bytes << " bytes from server.\n";

        if (bytes >= net_ops::protocol::HEADER_SIZE) {
            auto resp_header = net_ops::protocol::DeserializeHeader(recv_buf);
            if (resp_header.msg_type == static_cast<uint8_t>(net_ops::protocol::MessageType::LoginResp)) {
                std::cout << "Packet Verification: Type LoginResp (Correct)\n";
                
                std::string body((char*)recv_buf + net_ops::protocol::HEADER_SIZE, 
                                 bytes - net_ops::protocol::HEADER_SIZE);
                std::cout << "Server Says: " << body << std::endl;
            }
        }
    } else {
        std::cerr << "FAILURE: Empty response or error.\n";
        ERR_print_errors_fp(stderr);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}