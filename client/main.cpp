#include <QApplication>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include "NetworkController.hpp"
#include "LoginWindow.hpp"
#include "MainWindow.hpp"
#include "SyslogCollector.hpp"
#include "DeviceMonitor.hpp"

std::string autoDetectServerIP()
{
    std::cout << "[AutoDetect] Looking for Server...\n";
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return "127.0.0.1";

    int broadcast = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8081);                         
    addr.sin_addr.s_addr = inet_addr("255.255.255.255");
    for (int i = 0; i < 3; ++i)
    {
        const char *msg = "WANFRAME_LOOKING";
        sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&addr, sizeof(addr));

        char buf[256];
        struct sockaddr_in serverAddr;
        socklen_t len = sizeof(serverAddr);

        if (recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&serverAddr, &len) > 0)
        {
            std::string serverIP = inet_ntoa(serverAddr.sin_addr);
            std::cout << "[AutoDetect] Found Server at: " << serverIP << "\n";
            close(sock);
            return serverIP;
        }
    }

    std::cout << "[AutoDetect] Server not found. Defaulting to localhost.\n";
    close(sock);
    return "127.0.0.1";
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    std::string serverIP = autoDetectServerIP();

    auto controller = std::make_shared<net_ops::client::NetworkController>(serverIP, 8080);
    controller->Start();

    auto agent = std::make_shared<net_ops::client::SyslogCollector>("");
    auto monitor = std::make_shared<net_ops::client::DeviceMonitor>();

    net_ops::client::LoginWindow loginWin(controller);
    net_ops::client::MainWindow mainWin(controller, monitor);

    QObject::connect(&loginWin, &net_ops::client::LoginWindow::loginSuccessful,
                     [&](const std::string &token)
                     {
                         mainWin.SetToken(token);
                         int syslogPort = 55555;
                         agent->Start(syslogPort, [controller, token](const std::string &source, const std::string &msg)
                                      {
                            std::vector<uint8_t> payload;
                            net_ops::protocol::PackString(payload, token);
                            net_ops::protocol::PackString(payload, source);
                            net_ops::protocol::PackString(payload, msg);
                            controller->QueueRequest(net_ops::protocol::MessageType::LogUploadReq, payload); });

                         monitor->Start([controller, token](const std::string &ip, const std::string &status, const std::string &desc)
                                        {
                            std::vector<uint8_t> payload;
                            net_ops::protocol::PackString(payload, token);
                            net_ops::protocol::PackString(payload, ip);
                            net_ops::protocol::PackString(payload, status);
                            net_ops::protocol::PackString(payload, desc);
                            controller->QueueRequest(net_ops::protocol::MessageType::DeviceStatusReq, payload); });

                         loginWin.hide();
                         mainWin.show();
                     });

    loginWin.show();
    int ret = app.exec();

    std::cout << "[Main] Shutting down...\n";
    monitor->Stop();
    agent->Stop();
    controller->Stop();
    return ret;
}