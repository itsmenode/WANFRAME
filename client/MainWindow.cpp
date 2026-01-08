#include "MainWindow.hpp"
#include "Scanner.hpp"
#include "DeviceMonitor.hpp"
#include <QHeaderView>
#include <iostream>

namespace net_ops::client
{

    MainWindow::MainWindow(std::shared_ptr<NetworkController> controller,
                           std::shared_ptr<DeviceMonitor> monitor,
                           QWidget *parent)
        : QMainWindow(parent), m_controller(controller), m_monitor(monitor), m_isScanning(false), m_selectedDeviceId(-1)
    {
        setupUi();
        m_dataTimer = new QTimer(this);
        connect(m_dataTimer, &QTimer::timeout, this, &MainWindow::pollData);
    }

    MainWindow::~MainWindow()
    {
        if (m_scanThread.joinable())
            m_scanThread.join();
    }

    void MainWindow::SetToken(const std::string &token)
    {
        m_sessionToken = token;
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
        net_ops::protocol::PackUint32(p, static_cast<uint32_t>(m_selectedDeviceId));
        m_controller->QueueRequest(net_ops::protocol::MessageType::LogQueryReq, p);
    }

    void MainWindow::setupUi()
    {
        auto central = new QWidget();
        auto layout = new QVBoxLayout(central);

        m_scanBtn = new QPushButton("Scan Network");
        connect(m_scanBtn, &QPushButton::clicked, this, &MainWindow::onScanClicked);
        layout->addWidget(m_scanBtn);

        auto testLogBtn = new QPushButton("Send Test Log");
        connect(testLogBtn, &QPushButton::clicked, [this]()
            {
                if (m_sessionToken.empty()) return;

                std::vector<uint8_t> payload;
                net_ops::protocol::PackString(payload, m_sessionToken);
                net_ops::protocol::PackString(payload, "127.0.0.1");
                net_ops::protocol::PackString(payload, "Manual Test Log Entry from Client UI");
    
                m_controller->QueueRequest(net_ops::protocol::MessageType::LogUploadReq, payload);
            });
        layout->addWidget(testLogBtn);

        m_deviceTable = new QTableWidget(0, 5);
        m_deviceTable->setHorizontalHeaderLabels({"Name", "IP", "MAC", "Status", "ID"});
        m_deviceTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        m_deviceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_deviceTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_deviceTable->hideColumn(4);
        
        connect(m_deviceTable, &QTableWidget::cellClicked, this, &MainWindow::onDeviceSelected);

        layout->addWidget(m_deviceTable);

        m_logTable = new QTableWidget(0, 2);
        m_logTable->setHorizontalHeaderLabels({"Timestamp", "Message"});
        m_logTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        layout->addWidget(m_logTable);

        setCentralWidget(central);
        setWindowTitle("WANFRAME Dashboard");
        resize(900, 700);
    }

    void MainWindow::onDeviceSelected(int row, int col)
    {
        auto idItem = m_deviceTable->item(row, 4);
        if (idItem) {
            m_selectedDeviceId = idItem->text().toInt();
            m_logTable->setRowCount(0);
            sendLogQueryRequest();
        }
    }

    void MainWindow::onScanClicked()
    {
        if (m_sessionToken.empty()) return;
        if (m_isScanning) return; 

        m_isScanning = true;
        m_scanBtn->setText("Scanning...");
        m_scanBtn->setEnabled(false);

        if (m_scanThread.joinable())
            m_scanThread.join();

        std::string token = m_sessionToken;

        m_scanThread = std::thread([this, token]()
        {
            auto hosts = NetworkScanner::ScanLocalNetwork(); 
            for (const auto& h : hosts) {
                std::vector<uint8_t> p;
                net_ops::protocol::PackString(p, token);
                net_ops::protocol::PackString(p, h.name);
                net_ops::protocol::PackString(p, h.ip);
                net_ops::protocol::PackString(p, h.mac);
                m_controller->QueueRequest(net_ops::protocol::MessageType::DeviceAddReq, p);
            } 
            
            std::vector<uint8_t> listP;
            net_ops::protocol::PackString(listP, token);
            m_controller->QueueRequest(net_ops::protocol::MessageType::DeviceListReq, listP); 
            
            m_isScanning = false;
        });
    }

    void MainWindow::pollData()
    {
        if (!m_isScanning && !m_scanBtn->isEnabled()) {
            m_scanBtn->setText("Scan Network");
            m_scanBtn->setEnabled(true);
        }
        
        static int counter = 0;
        if (++counter % 2 == 0) {
             sendLogQueryRequest();
        }

        while (auto resp = m_controller->GetNextResponse())
        {
            if (resp->type == net_ops::protocol::MessageType::DeviceListResp)
            {
                updateDeviceList(resp->data);
            }
            else if (resp->type == net_ops::protocol::MessageType::LogQueryResp)
            {
                size_t offset = 0;
                auto count = net_ops::protocol::UnpackUint32(resp->data, offset);
                if (count)
                {
                    m_logTable->setRowCount(0);
                    for (uint32_t i = 0; i < *count; ++i)
                    {
                        auto ts = net_ops::protocol::UnpackString(resp->data, offset);
                        auto msg = net_ops::protocol::UnpackString(resp->data, offset);
                        if (ts && msg)
                            addLogEntry(*ts, *msg);
                    }
                }
            }
        }
    }

    void MainWindow::addLogEntry(const std::string &timestamp, const std::string &msg)
    {
        int row = m_logTable->rowCount();
        m_logTable->insertRow(row);
        m_logTable->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(timestamp)));
        m_logTable->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(msg)));
        m_logTable->scrollToBottom();
    }

    void MainWindow::updateDeviceList(const std::vector<uint8_t> &data)
    {
        size_t offset = 0;
        auto count = net_ops::protocol::UnpackUint32(data, offset);
        if (!count) return;

        int savedId = m_selectedDeviceId;
        m_deviceTable->setRowCount(0);

        std::vector<std::string> monitorIPs;

        for (uint32_t i = 0; i < *count; ++i)
        {
            auto id = net_ops::protocol::UnpackUint32(data, offset);
            auto name = net_ops::protocol::UnpackString(data, offset);
            auto ip = net_ops::protocol::UnpackString(data, offset);
            auto status = net_ops::protocol::UnpackString(data, offset);
            auto info = net_ops::protocol::UnpackString(data, offset);

            int row = m_deviceTable->rowCount();
            m_deviceTable->insertRow(row);
            m_deviceTable->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(*name)));
            m_deviceTable->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(*ip)));
            m_deviceTable->setItem(row, 2, new QTableWidgetItem(QString::fromStdString("Unknown MAC")));
            m_deviceTable->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(*status + " " + *info)));
            
            m_deviceTable->setItem(row, 4, new QTableWidgetItem(QString::number(*id)));

            if (ip) monitorIPs.push_back(*ip);
            
            if (savedId != -1 && (int)*id == savedId) {
                m_deviceTable->selectRow(row);
            }
        }

        if (m_monitor) {
            m_monitor->SetTargets(monitorIPs);
        }
    }
}