#include <QApplication>
#include "NetworkController.hpp"
#include "LoginWindow.hpp"
#include "MainWindow.hpp"
#include "SyslogCollector.hpp"

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

    net_ops::client::LoginWindow loginWin(controller);
    net_ops::client::MainWindow mainWin(controller);

    QObject::connect(&loginWin, &net_ops::client::LoginWindow::loginSuccessful, [&]()
                     {
        loginWin.hide();
        mainWin.show(); });

    loginWin.show();

    int ret = app.exec();

    agent.Stop();
    controller->Stop();
    return ret;
}