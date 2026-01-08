#include "MainWindow.hpp"
#include "Scanner.hpp"
#include "DeviceMonitor.hpp"
#include <QHeaderView>
#include <iostream>
#include <QMessageBox>
#include <unistd.h>
#include <QApplication>
namespace net_ops::client
{

    MainWindow::MainWindow(std::shared_ptr<NetworkController> controller, std::shared_ptr<DeviceMonitor> monitor, QWidget *parent)
        : QMainWindow(parent), m_controller(controller), m_monitor(monitor), m_isScanning(false), m_selectedDeviceId(-1), m_onlineCount(0)
    {
        setupUi();
        m_syslogCollector = std::make_unique<SyslogCollector>("syslog.txt");
        m_dataTimer = new QTimer(this);
        connect(m_dataTimer, &QTimer::timeout, this, &MainWindow::pollData);
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
        
        m_syslogCollector->Start(5140, [this](const std::string &ip, const std::string &msg)
        {
            if (m_sessionToken.empty()) return;
            std::vector<uint8_t> p;
            net_ops::protocol::PackString(p, m_sessionToken);
            net_ops::protocol::PackString(p, ip);
            net_ops::protocol::PackString(p, msg);
            m_controller->QueueRequest(net_ops::protocol::MessageType::LogUploadReq, p); 
        });

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
            m_dataTimer->start(500);
            sendDeviceListRequest();
        }
    }

    void MainWindow::sendDeviceListRequest()
    {
        if (m_sessionToken.empty()) return;
        std::vector<uint8_t> p;
        net_ops::protocol::PackString(p, m_sessionToken);
        m_controller->QueueRequest(net_ops::protocol::MessageType::DeviceListReq, p);
    }

    void MainWindow::sendLogQueryRequest()
    {
        if (m_selectedDeviceId == -1 || m_sessionToken.empty()) return;

        std::vector<uint8_t> p;
        net_ops::protocol::PackString(p, m_sessionToken);
        net_ops::protocol::PackUint32(p, static_cast<uint32_t>(m_selectedDeviceId));
        m_controller->QueueRequest(net_ops::protocol::MessageType::LogQueryReq, p);
    }

    void MainWindow::setupUi()
    {
        auto central = new QWidget();
        auto mainLayout = new QVBoxLayout(central);

        auto topLayout = new QHBoxLayout();
        
        m_scanBtn = new QPushButton("Scan Network (Root Req)");
        connect(m_scanBtn, &QPushButton::clicked, this, &MainWindow::onScanClicked);
        topLayout->addWidget(m_scanBtn);

        auto testLogBtn = new QPushButton("Send Test Log");
        connect(testLogBtn, &QPushButton::clicked, [this]() {
                if (m_sessionToken.empty()) return;
                std::vector<uint8_t> payload;
                net_ops::protocol::PackString(payload, m_sessionToken);
                net_ops::protocol::PackString(payload, "127.0.0.1");
                net_ops::protocol::PackString(payload, "Manual Test Log Event");
                m_controller->QueueRequest(net_ops::protocol::MessageType::LogUploadReq, payload); 
        });
        topLayout->addWidget(testLogBtn);
        
        m_logoutBtn = new QPushButton("Logout");
        m_logoutBtn->setStyleSheet("background-color: #ffcccc;");
        connect(m_logoutBtn, &QPushButton::clicked, this, &MainWindow::onLogoutClicked);
        topLayout->addWidget(m_logoutBtn);

        mainLayout->addLayout(topLayout);

        m_statsLabel = new QLabel("<b>Network Status:</b> Loading...");
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
        setWindowTitle("WANFRAME Monitoring Dashboard");
        resize(950, 750);
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
        QString stats = QString("<b>Devices:</b> %1 | <b>Online:</b> %2 | <b>Total Logs:</b> %3")
                        .arg(m_deviceTable->rowCount())
                        .arg(m_onlineCount)
                        .arg(m_logTable->rowCount());
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

    void MainWindow::onScanClicked()
    {
        if (m_sessionToken.empty()) return;
        if (m_isScanning) return;

        if (geteuid() != 0) {
            QMessageBox::critical(this, "Permission Denied",
                                  "Network scanning requires root privileges.\nPlease run: sudo ./Client");
            return;
        }

        m_isScanning = true;
        m_scanBtn->setText("Scanning...");
        m_scanBtn->setEnabled(false);

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
        if (!m_isScanning && !m_scanBtn->isEnabled()) {
            m_scanBtn->setText("Scan Network (Root Req)");
            m_scanBtn->setEnabled(true);
        }

        static int c = 0; if (++c % 4 == 0) sendLogQueryRequest();
        
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
        m_onlineCount = 0;

        for (uint32_t i = 0; i < *count; ++i) {
            auto id = net_ops::protocol::UnpackUint32(data, offset);
            auto name = net_ops::protocol::UnpackString(data, offset);
            auto ip = net_ops::protocol::UnpackString(data, offset);
            auto status = net_ops::protocol::UnpackString(data, offset);
            auto info = net_ops::protocol::UnpackString(data, offset);

            if (ip) monitorIPs.push_back(*ip);
            
            if (status && *status == "Online") m_onlineCount++;

            bool found = false;
            for(int r = 0; r < m_deviceTable->rowCount(); ++r) {
                if (m_deviceTable->item(r, 4)->text().toUInt() == *id) {
                    found = true;
                    m_deviceTable->item(r, 1)->setText(QString::fromStdString(*ip));
                    m_deviceTable->item(r, 3)->setText(QString::fromStdString(*status + " " + *info));
                    break;
                }
            }
            if (!found) {
                int row = m_deviceTable->rowCount();
                m_deviceTable->insertRow(row);
                m_deviceTable->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(*name)));
                m_deviceTable->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(*ip)));
                m_deviceTable->setItem(row, 2, new QTableWidgetItem("Unknown"));
                m_deviceTable->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(*status + " " + *info)));
                m_deviceTable->setItem(row, 4, new QTableWidgetItem(QString::number(*id)));
            }
        }
        if (m_monitor) m_monitor->SetTargets(monitorIPs);
        updateStats();
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