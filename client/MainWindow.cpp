#include "MainWindow.hpp"
#include "Scanner.hpp"
#include "DeviceMonitor.hpp"
#include <QHeaderView>
#include <iostream>
#include <QMessageBox>
#include <unistd.h>
#include <QApplication>
#include <set>
#include <random>

namespace net_ops::client
{

    MainWindow::MainWindow(std::shared_ptr<NetworkController> controller, std::shared_ptr<DeviceMonitor> monitor, QWidget *parent)
        : QMainWindow(parent), m_controller(controller), m_monitor(monitor), m_isScanning(false), m_selectedDeviceId(-1), m_onlineCount(0)
    {
        setupUi();
        m_syslogCollector = std::make_unique<SyslogCollector>("syslog.txt");
        
        m_dataTimer = new QTimer(this);
        connect(m_dataTimer, &QTimer::timeout, this, &MainWindow::pollData);

        m_discoveryTimer = new QTimer(this);
        connect(m_discoveryTimer, &QTimer::timeout, this, &MainWindow::performContinuousScan);

        m_simTimer = new QTimer(this);
        connect(m_simTimer, &QTimer::timeout, this, &MainWindow::runSimulationStep);
    }

    MainWindow::~MainWindow()
    {
        if (m_monitor) m_monitor->Stop();
        if (m_syslogCollector) m_syslogCollector->Stop();
        if (m_scanThread.joinable()) m_scanThread.join();
    }

    void MainWindow::SetToken(const std::string &token)
    {
        m_sessionToken = token;
        
        int port = m_syslogCollector->Start(5140, [this](const std::string &ip, const std::string &msg)
        {
            if (m_sessionToken.empty()) return;
            std::vector<uint8_t> p;
            net_ops::protocol::PackString(p, m_sessionToken);
            net_ops::protocol::PackString(p, ip);
            net_ops::protocol::PackString(p, msg);
            m_controller->QueueRequest(net_ops::protocol::MessageType::LogUploadReq, p); 
        });
        
        m_syslogPort = port;

        if (m_monitor) {
            m_monitor->Start([this](const std::string &ip, const std::string &status, const std::string &info) {
                 if (m_sessionToken.empty()) return;
                 std::vector<uint8_t> p;
                 net_ops::protocol::PackString(p, m_sessionToken);
                 net_ops::protocol::PackString(p, ip);
                 net_ops::protocol::PackString(p, status);
                 net_ops::protocol::PackString(p, info);
                 m_controller->QueueRequest(net_ops::protocol::MessageType::DeviceStatusReq, p);
            });
        }
    }

    void MainWindow::showEvent(QShowEvent *event)
    {
        QMainWindow::showEvent(event);
        if (!m_dataTimer->isActive())
        {
            m_dataTimer->start(1000); 
            sendDeviceListRequest();
        }
    }

    void MainWindow::setupUi()
    {
        auto central = new QWidget();
        auto mainLayout = new QVBoxLayout(central);

        auto topLayout = new QHBoxLayout();
        
        m_scanBtn = new QPushButton("Start Continuous Monitoring");
        m_scanBtn->setCheckable(true);
        connect(m_scanBtn, &QPushButton::clicked, this, &MainWindow::onScanClicked);
        topLayout->addWidget(m_scanBtn);

        m_simBtn = new QPushButton("Start Traffic Simulation");
        m_simBtn->setCheckable(true);
        m_simBtn->setStyleSheet("background-color: #e6f7ff; color: #004d80; font-weight: bold;");
        connect(m_simBtn, &QPushButton::clicked, this, &MainWindow::onSimulateClicked);
        topLayout->addWidget(m_simBtn);
        
        m_logoutBtn = new QPushButton("Logout");
        m_logoutBtn->setStyleSheet("background-color: #ffcccc;");
        connect(m_logoutBtn, &QPushButton::clicked, this, &MainWindow::onLogoutClicked);
        topLayout->addWidget(m_logoutBtn);

        mainLayout->addLayout(topLayout);

        m_statsLabel = new QLabel("<b>Network Status:</b> Idle");
        m_statsLabel->setStyleSheet("padding: 5px; background-color: #f0f0f0; border: 1px solid #ccc;");
        mainLayout->addWidget(m_statsLabel);

        mainLayout->addWidget(new QLabel("<b>Managed Devices:</b>"));
        m_deviceTable = new QTableWidget(0, 5);
        m_deviceTable->setHorizontalHeaderLabels({"Name", "IP", "MAC", "Status / Metrics", "ID"});
        m_deviceTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        m_deviceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_deviceTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_deviceTable->hideColumn(4);
        connect(m_deviceTable, &QTableWidget::cellClicked, this, &MainWindow::onDeviceSelected);
        mainLayout->addWidget(m_deviceTable);

        auto filterLayout = new QHBoxLayout();
        filterLayout->addWidget(new QLabel("<b>Filter Logs:</b>"));
        m_filterInput = new QLineEdit();
        m_filterInput->setPlaceholderText("Type to filter logs by IP or Message...");
        connect(m_filterInput, &QLineEdit::textChanged, this, &MainWindow::onFilterLogs);
        filterLayout->addWidget(m_filterInput);
        mainLayout->addLayout(filterLayout);

        m_logTable = new QTableWidget(0, 2);
        m_logTable->setHorizontalHeaderLabels({"Timestamp", "Message"});
        m_logTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        mainLayout->addWidget(m_logTable);

        setCentralWidget(central);
        setWindowTitle("WANFRAME Monitoring Dashboard - DEBUG MODE");
        resize(950, 750);
    }

    void MainWindow::onSimulateClicked()
    {
        if (m_simBtn->isChecked()) {
            m_simBtn->setText("Stop Traffic Simulation");
            m_simBtn->setStyleSheet("background-color: #ffe6e6; color: #cc0000; font-weight: bold;");
            
            createFakeDevices();
            m_simTimer->start(2000);
        } else {
            m_simBtn->setText("Start Traffic Simulation");
            m_simBtn->setStyleSheet("background-color: #e6f7ff; color: #004d80; font-weight: bold;");
            m_simTimer->stop();
        }
    }

    void MainWindow::createFakeDevices()
    {
        if (m_sessionToken.empty()) return;

        m_fakeIps = {
            "192.168.254.101", "192.168.254.102", "192.168.254.103",
            "192.168.254.104", "192.168.254.105"
        };
        std::vector<std::string> names = {
            "Sim-Core-Router", "Sim-Switch-Floor1", "Sim-Firewall-Ext",
            "Sim-Auth-Server", "Sim-Wifi-Controller"
        };

        for (size_t i = 0; i < m_fakeIps.size(); ++i) {
            std::vector<uint8_t> p;
            net_ops::protocol::PackString(p, m_sessionToken);
            net_ops::protocol::PackString(p, names[i]);
            net_ops::protocol::PackString(p, m_fakeIps[i]);
            net_ops::protocol::PackString(p, "AA:BB:CC:DD:EE:0" + std::to_string(i));
            m_controller->QueueRequest(net_ops::protocol::MessageType::DeviceAddReq, p);

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            std::vector<uint8_t> statusP;
            net_ops::protocol::PackString(statusP, m_sessionToken);
            net_ops::protocol::PackString(statusP, m_fakeIps[i]);
            net_ops::protocol::PackString(statusP, "Online");
            net_ops::protocol::PackString(statusP, "Simulated");
            m_controller->QueueRequest(net_ops::protocol::MessageType::DeviceStatusReq, statusP);
        }
        
        sendDeviceListRequest();
    }

    void MainWindow::runSimulationStep()
    {
        if (m_fakeIps.empty() || m_sessionToken.empty()) return;

        int idx = rand() % m_fakeIps.size();
        std::string ip = m_fakeIps[idx];

        std::vector<std::string> messages = {
            "Interface GigabitEthernet0/1 changed state to DOWN",
            "Interface GigabitEthernet0/1 changed state to UP",
            "%SEC-W-LOGINFAIL: User admin failed login from 10.0.0.5",
            "%SYS-5-CONFIG_I: Configured from console by vty0",
            "Cpu usage threshold exceeded: 92%",
            "Packet loss detected on uplink",
            "Fan 2 failed, temperature rising",
            "BGP neighbor 10.2.2.2 is Down"
        };
        std::string msg = messages[rand() % messages.size()];

        std::vector<uint8_t> p;
        net_ops::protocol::PackString(p, m_sessionToken);
        net_ops::protocol::PackString(p, ip);
        net_ops::protocol::PackString(p, msg);
        m_controller->QueueRequest(net_ops::protocol::MessageType::LogUploadReq, p);

        if (rand() % 10 == 0) {
            std::vector<uint8_t> sp;
            net_ops::protocol::PackString(sp, m_sessionToken);
            net_ops::protocol::PackString(sp, ip);
            net_ops::protocol::PackString(sp, "Offline");
            net_ops::protocol::PackString(sp, "Timeout");
            m_controller->QueueRequest(net_ops::protocol::MessageType::DeviceStatusReq, sp);
        } else if (rand() % 10 == 1) {
            std::vector<uint8_t> sp;
            net_ops::protocol::PackString(sp, m_sessionToken);
            net_ops::protocol::PackString(sp, ip);
            net_ops::protocol::PackString(sp, "Online");
            net_ops::protocol::PackString(sp, "Active");
            m_controller->QueueRequest(net_ops::protocol::MessageType::DeviceStatusReq, sp);
        }
    }

    void MainWindow::onScanClicked()
    {
        if (m_sessionToken.empty()) return;

        if (geteuid() != 0) {
            QMessageBox::critical(this, "Permission Denied",
                                  "Network scanning requires root privileges.\nPlease run: sudo ./Client");
            m_scanBtn->setChecked(false);
            return;
        }

        if (m_scanBtn->isChecked()) {
            m_scanBtn->setText("Stop Monitoring Loop");
            m_scanBtn->setStyleSheet("background-color: #ccffcc;");
            performContinuousScan();
            m_discoveryTimer->start(15000); 
        } else {
            m_scanBtn->setText("Start Continuous Monitoring");
            m_scanBtn->setStyleSheet("");
            m_discoveryTimer->stop();
            m_isScanning = false;
        }
    }

    void MainWindow::performContinuousScan()
    {
        if (m_isScanning) return;
        m_isScanning = true;

        if (m_scanThread.joinable()) m_scanThread.join();

        std::string token = m_sessionToken;

        m_scanThread = std::thread([this, token]() {
            try {
                auto hosts = NetworkScanner::ScanLocalNetwork(); 
                for (const auto& h : hosts) {
                    std::vector<uint8_t> p;
                    net_ops::protocol::PackString(p, token);
                    net_ops::protocol::PackString(p, h.name);
                    net_ops::protocol::PackString(p, h.ip);
                    net_ops::protocol::PackString(p, h.mac);
                    m_controller->QueueRequest(net_ops::protocol::MessageType::DeviceAddReq, p);
                    
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                    std::vector<uint8_t> statusP;
                    net_ops::protocol::PackString(statusP, token);
                    net_ops::protocol::PackString(statusP, h.ip);
                    net_ops::protocol::PackString(statusP, "Online");
                    net_ops::protocol::PackString(statusP, "Scanned");
                    m_controller->QueueRequest(net_ops::protocol::MessageType::DeviceStatusReq, statusP);
                } 
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                
                std::vector<uint8_t> listP;
                net_ops::protocol::PackString(listP, token);
                m_controller->QueueRequest(net_ops::protocol::MessageType::DeviceListReq, listP); 
            } catch(...) {}
            m_isScanning = false; 
        });
    }

    void MainWindow::pollData() {
        static int c = 0; 
        c++;
        
        if (c % 2 == 0) {
            sendLogQueryRequest();
            sendDeviceListRequest();
        }
        
        while (auto resp = m_controller->GetNextResponse()) {
            if (resp->type == net_ops::protocol::MessageType::DeviceListResp) updateDeviceList(resp->data);
            else if (resp->type == net_ops::protocol::MessageType::LogQueryResp) { 
                size_t offset = 0;
                auto count = net_ops::protocol::UnpackUint32(resp->data, offset);
                if (count) {
                    m_logTable->setRowCount(0);
                    for (uint32_t i = 0; i < *count; ++i) {
                        auto ts = net_ops::protocol::UnpackString(resp->data, offset);
                        auto msg = net_ops::protocol::UnpackString(resp->data, offset);
                        if (ts && msg) addLogEntry(*ts, *msg);
                    }
                    updateStats();
                }
            }
        }
    }

    void MainWindow::updateDeviceList(const std::vector<uint8_t> &data) {
        size_t offset = 0;
        auto count = net_ops::protocol::UnpackUint32(data, offset);
        if (!count) return;

        std::vector<std::string> monitorIPs;
        std::set<uint32_t> seenIds;
        m_onlineCount = 0;

        for (uint32_t i = 0; i < *count; ++i) {
            auto id = net_ops::protocol::UnpackUint32(data, offset);
            auto name = net_ops::protocol::UnpackString(data, offset);
            auto ip = net_ops::protocol::UnpackString(data, offset);
            auto status = net_ops::protocol::UnpackString(data, offset);
            auto info = net_ops::protocol::UnpackString(data, offset);

            if (id) seenIds.insert(*id);
            if (ip) monitorIPs.push_back(*ip);
            
            QString statusText = QString::fromStdString(*status);
            QString infoText = QString::fromStdString(*info);
            bool isOnline = (statusText == "Online" || statusText == "ACTIVE");

            if (isOnline) {
                statusText = "Online";
                m_onlineCount++;
            }

            QString displayStr = statusText + " " + infoText;
            QColor bgColor = isOnline ? QColor("#ccffcc") : QColor("#ffcccc");

            bool found = false;
            for(int r = 0; r < m_deviceTable->rowCount(); ++r) {
                auto idItem = m_deviceTable->item(r, 4);
                if (idItem && idItem->text().toUInt() == *id) {
                    found = true;
                    m_deviceTable->item(r, 1)->setText(QString::fromStdString(*ip));
                    m_deviceTable->item(r, 3)->setText(displayStr);
                    m_deviceTable->item(r, 3)->setBackground(bgColor);
                    break;
                }
            }
            if (!found) {
                int row = m_deviceTable->rowCount();
                m_deviceTable->insertRow(row);
                m_deviceTable->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(*name)));
                m_deviceTable->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(*ip)));
                m_deviceTable->setItem(row, 2, new QTableWidgetItem("Unknown"));
                auto statusItem = new QTableWidgetItem(displayStr);
                statusItem->setBackground(bgColor);
                m_deviceTable->setItem(row, 3, statusItem);
                m_deviceTable->setItem(row, 4, new QTableWidgetItem(QString::number(*id)));
            }
        }

        for (int r = m_deviceTable->rowCount() - 1; r >= 0; --r) {
             auto idItem = m_deviceTable->item(r, 4);
             if (idItem && seenIds.find(idItem->text().toUInt()) == seenIds.end()) {
                 m_deviceTable->removeRow(r);
             }
        }

        if (m_monitor) m_monitor->SetTargets(monitorIPs);
        updateStats();
    }

    void MainWindow::sendDeviceListRequest()
    {
        if (m_sessionToken.empty()) return;
        std::vector<uint8_t> p;
        net_ops::protocol::PackString(p, m_sessionToken);
        m_controller->QueueRequest(net_ops::protocol::MessageType::DeviceListReq, p);
    }

    void MainWindow::onLogoutClicked() {
        if (!m_sessionToken.empty()) {
            std::vector<uint8_t> p;
            net_ops::protocol::PackString(p, m_sessionToken);
            m_controller->QueueRequest(net_ops::protocol::MessageType::LogoutReq, p);
        }
        QApplication::quit();
    }

    void MainWindow::updateStats() {
        QString stats = QString("<b>Devices:</b> %1 | <b>Online:</b> %2 | <b>Total Logs:</b> %3 | <b>Syslog Port:</b> %4")
                        .arg(m_deviceTable->rowCount())
                        .arg(m_onlineCount)
                        .arg(m_logTable->rowCount())
                        .arg(m_syslogPort);
        m_statsLabel->setText(stats);
    }

    void MainWindow::onFilterLogs(const QString &text) {
        for(int i = 0; i < m_logTable->rowCount(); ++i) {
            bool match = false;
            if (text.isEmpty()) {
                match = true;
            } else {
                auto itemTime = m_logTable->item(i, 0);
                auto itemMsg = m_logTable->item(i, 1);
                if ((itemTime && itemTime->text().contains(text, Qt::CaseInsensitive)) ||
                    (itemMsg && itemMsg->text().contains(text, Qt::CaseInsensitive))) {
                    match = true;
                }
            }
            m_logTable->setRowHidden(i, !match);
        }
    }

    void MainWindow::onDeviceSelected(int row, int col)
    {
        auto idItem = m_deviceTable->item(row, 4);
        if (idItem)
        {
            m_selectedDeviceId = idItem->text().toInt();
            m_logTable->setRowCount(0);
            sendLogQueryRequest();
        }
    }

    void MainWindow::sendLogQueryRequest()
    {
        if (m_selectedDeviceId == -1 || m_sessionToken.empty()) return;

        std::vector<uint8_t> p;
        net_ops::protocol::PackString(p, m_sessionToken);
        net_ops::protocol::PackUint32(p, static_cast<uint32_t>(m_selectedDeviceId));
        m_controller->QueueRequest(net_ops::protocol::MessageType::LogQueryReq, p);
    }

    void MainWindow::addLogEntry(const std::string &timestamp, const std::string &msg)
    {
        int row = m_logTable->rowCount();
        m_logTable->insertRow(row);
        m_logTable->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(timestamp)));
        m_logTable->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(msg)));
        
        QString filter = m_filterInput->text();
        if (!filter.isEmpty()) {
            bool match = QString::fromStdString(timestamp).contains(filter, Qt::CaseInsensitive) ||
                         QString::fromStdString(msg).contains(filter, Qt::CaseInsensitive);
            m_logTable->setRowHidden(row, !match);
        }
        
        m_logTable->scrollToBottom();
    }
}