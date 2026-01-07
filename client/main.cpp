#include <QApplication>
#include "NetworkController.hpp"
#include "LoginWindow.hpp"
#include "MainWindow.hpp"
#include "SyslogCollector.hpp"
#include "DeviceMonitor.hpp"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    auto controller = std::make_shared<net_ops::client::NetworkController>("127.0.0.1", 8080);
    controller->Start();

    net_ops::client::SyslogCollector agent("/var/log/syslog");
    agent.Start(514, [controller](const std::string &source, const std::string &msg)
                {
        std::vector<uint8_t> payload;
        net_ops::protocol::PackString(payload, source);
        net_ops::protocol::PackString(payload, msg);
        controller->QueueRequest(net_ops::protocol::MessageType::LogUploadReq, payload); });

    auto monitor = std::make_shared<net_ops::client::DeviceMonitor>();
    
    monitor->Start([controller](const std::string& ip, const std::string& status, const std::string& desc) {
        std::vector<uint8_t> payload;
        net_ops::protocol::PackString(payload, ip);
        net_ops::protocol::PackString(payload, status);
        net_ops::protocol::PackString(payload, desc);
        controller->QueueRequest(net_ops::protocol::MessageType::DeviceStatusReq, payload);
    });

    net_ops::client::LoginWindow loginWin(controller);
    
    net_ops::client::MainWindow mainWin(controller, monitor); 

    QObject::connect(&loginWin, &net_ops::client::LoginWindow::loginSuccessful, [&]()
                     {
        loginWin.hide();
        mainWin.show(); });

    loginWin.show();

    int ret = app.exec();

    monitor->Stop();
    agent.Stop();
    controller->Stop();
    return ret;
}