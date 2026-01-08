#include <QApplication>
#include <iostream>
#include <cstdlib>
#include "NetworkController.hpp"
#include "LoginWindow.hpp"
#include "MainWindow.hpp"
#include "SyslogCollector.hpp"
#include "DeviceMonitor.hpp"
#include "SnmpMonitor.hpp"
#include "DataSourceRegistry.hpp"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    auto controller = std::make_shared<net_ops::client::NetworkController>("127.0.0.1", 8080);
    controller->Start();

    int syslogPort = 55555;
    auto agent = std::make_shared<net_ops::client::SyslogCollector>("", syslogPort);
    const bool syslogAgentEnabled = std::getenv("WANFRAME_SYSLOG_AGENT") != nullptr;

    auto monitor = std::make_shared<net_ops::client::DeviceMonitor>();
    auto snmpMonitor = std::make_shared<net_ops::client::SnmpMonitor>();
    net_ops::client::DataSourceRegistry registry;
    if (syslogAgentEnabled)
        registry.RegisterSource("syslog", agent);
    registry.RegisterSource("monitor", monitor);
    registry.RegisterSource("snmp", snmpMonitor);

    net_ops::client::LoginWindow loginWin(controller);
    net_ops::client::MainWindow mainWin(controller, monitor, snmpMonitor);

    QObject::connect(&loginWin, &net_ops::client::LoginWindow::loginSuccessful,
                     [&](const std::string &token)
                     {
                         mainWin.SetToken(token);

                         registry.StartAll([controller, token](const net_ops::client::DataRecord &record)
                         {
                             std::vector<uint8_t> payload;
                             switch (record.type)
                             {
                             case net_ops::client::DataRecordType::Syslog:
                                 net_ops::protocol::PackString(payload, token);
                                 net_ops::protocol::PackString(payload, record.ip);
                                 net_ops::protocol::PackString(payload, record.message);
                                 controller->QueueRequest(net_ops::protocol::MessageType::LogUploadReq, payload);
                                 break;
                             case net_ops::client::DataRecordType::DeviceStatus:
                             case net_ops::client::DataRecordType::SnmpStatus:
                                 net_ops::protocol::PackString(payload, token);
                                 net_ops::protocol::PackString(payload, record.ip);
                                 net_ops::protocol::PackString(payload, record.status);
                                 net_ops::protocol::PackString(payload, record.info);
                                 controller->QueueRequest(net_ops::protocol::MessageType::DeviceStatusReq, payload);
                                 break;
                             }
                         });

                         loginWin.hide();
                         mainWin.show();
                     });

    loginWin.show();

    int ret = app.exec();

    std::cout << "[Main] Shutting down...\n";
    registry.StopAll();
    controller->Stop();
    
    return ret;
}
