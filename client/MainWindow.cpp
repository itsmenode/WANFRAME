#include "MainWindow.hpp"
#include "Scanner.hpp"
#include "DeviceMonitor.hpp"
#include <QHeaderView>
#include <iostream>
#include <QMessageBox>
#include <unistd.h>
#include <QStatusBar>
#include <QLabel>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

namespace net_ops::client
{

    MainWindow::MainWindow(std::shared_ptr<NetworkController> controller,
                           std::shared_ptr<DeviceMonitor> monitor,
                           std::shared_ptr<SnmpMonitor> snmpMonitor,
                           QWidget *parent)
        : QMainWindow(parent),
          m_controller(controller),
          m_monitor(monitor),
          m_snmpMonitor(snmpMonitor),
          m_isScanning(false),
          m_selectedDeviceId(-1)
    {
        m_dataTimer = new QTimer(this);

        connect(m_controller.get(), &NetworkController::responseReceived, this, &MainWindow::pollData);

        setupUi();
    }

    MainWindow::~MainWindow()
    {
        if (m_scanThread.joinable())
            m_scanThread.join();
    }

    void MainWindow::SetToken(const std::string &token)
    {
        m_sessionToken = token;
        m_dashboardConfigLoaded = false;
        sendDashboardConfigRequest();
    }

    void MainWindow::showEvent(QShowEvent *event)
    {
        QMainWindow::showEvent(event);
        if (!m_dataTimer->isActive())
        {
            m_dataTimer->start(5000);
            sendDeviceListRequest();
            sendMetricsRequest();
        }
    }

    void MainWindow::sendDeviceListRequest()
    {
        if (m_sessionToken.empty())
            return;
        std::vector<uint8_t> p;
        net_ops::protocol::PackString(p, m_sessionToken);
        m_controller->QueueRequest(net_ops::protocol::MessageType::DeviceListReq, p);
    }

    void MainWindow::sendMetricsRequest()
    {
        std::vector<uint8_t> p;
        m_controller->QueueRequest(net_ops::protocol::MessageType::MetricsReq, p);
    }

    void MainWindow::sendLogQueryRequest()
    {
        if (m_selectedDeviceId == -1 || m_sessionToken.empty())
            return;

        std::vector<uint8_t> p;
        net_ops::protocol::PackString(p, m_sessionToken);
        net_ops::protocol::PackUint32(p, static_cast<uint32_t>(m_selectedDeviceId));

        m_controller->QueueRequest(net_ops::protocol::MessageType::LogQueryReq, p);
    }

    void MainWindow::setupUi()
    {
        auto central = new QWidget();
        auto layout = new QVBoxLayout(central);

        auto actionLayout = new QHBoxLayout();
        m_scanBtn = new QPushButton("Scan Network (Requires Root)");
        connect(m_scanBtn, &QPushButton::clicked, this, &MainWindow::onScanClicked);
        actionLayout->addWidget(m_scanBtn);

        m_saveLayoutBtn = new QPushButton("Save Dashboard Layout");
        m_saveLayoutBtn->setToolTip("Save column visibility/order preferences");
        connect(m_saveLayoutBtn, &QPushButton::clicked, this, &MainWindow::onSaveLayoutClicked);
        actionLayout->addWidget(m_saveLayoutBtn);

        layout->addLayout(actionLayout);

        auto metricsLabel = new QLabel("<b>Network Incident Metrics (Logs per Device)</b>");
        layout->addWidget(metricsLabel);

        m_metricsTable = new QTableWidget(0, 3);
        m_metricsTable->setHorizontalHeaderLabels({"Device ID", "Total Logs", "Current Status"});
        m_metricsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        layout->addWidget(m_metricsTable);

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

        statusBar()->showMessage("Connected - Real-time Updates Active");
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
        if (m_sessionToken.empty())
            return;
        if (m_isScanning)
            return;

        if (geteuid() != 0)
        {
            QMessageBox::critical(this, "Permission Denied",
                                  "Network scanning requires root privileges.\nPlease run: sudo ./Client");
            return;
        }

        m_isScanning = true;
        m_scanBtn->setText("Scanning... (Please Wait)");
        m_scanBtn->setEnabled(false);

        if (m_scanThread.joinable())
            m_scanThread.join();

        std::string token = m_sessionToken;

        m_scanThread = std::thread([this, token]()
                                   {
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
            } catch(...) {
                std::cerr << "[MainWindow] Scan thread crashed.\n";
            }
            
            m_isScanning = false; });
    }

    void MainWindow::pollData()
    {
        while (auto resp = m_controller->GetNextResponse())
        {
            switch (resp->type)
            {
            case net_ops::protocol::MessageType::LogQueryResp:
            {
                size_t offset = 0;
                auto count = net_ops::protocol::UnpackUint32(resp->data, offset);
                if (count && offset < resp->data.size())
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
                else
                {
                    offset = 0;
                    auto ip = net_ops::protocol::UnpackString(resp->data, offset);
                    auto msg = net_ops::protocol::UnpackString(resp->data, offset);
                    if (ip && msg)
                        addLogEntry("LIVE", "[" + *ip + "] " + *msg);
                }
                break;
            }

            case net_ops::protocol::MessageType::DeviceListResp:
                updateDeviceList(resp->data);
                break;

            case net_ops::protocol::MessageType::MetricsResp:
            {
                size_t offset = 0;
                auto count = net_ops::protocol::UnpackUint32(resp->data, offset);
                if (count)
                {
                    m_metricsTable->setRowCount(0);
                    for (uint32_t i = 0; i < *count; ++i)
                    {
                        auto id = net_ops::protocol::UnpackUint32(resp->data, offset);
                        auto logCnt = net_ops::protocol::UnpackUint32(resp->data, offset);
                        auto status = net_ops::protocol::UnpackString(resp->data, offset);

                        int row = m_metricsTable->rowCount();
                        m_metricsTable->insertRow(row);
                        m_metricsTable->setItem(row, 0, new QTableWidgetItem(QString::number(*id)));
                        m_metricsTable->setItem(row, 1, new QTableWidgetItem(QString::number(*logCnt)));
                        m_metricsTable->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(status.value_or("N/A"))));
                    }
                }
                break;
            }

            case net_ops::protocol::MessageType::DashboardConfigResp:
            {
                size_t offset = 0;
                auto status = net_ops::protocol::UnpackString(resp->data, offset);
                auto config = net_ops::protocol::UnpackString(resp->data, offset);
                if (status && *status == "OK" && config && !config->empty())
                {
                    applyDashboardConfig(*config);
                    m_dashboardConfigLoaded = true;
                    statusBar()->showMessage("Dashboard layout loaded.", 3000);
                }
                else if (status && *status == "OK")
                {
                    statusBar()->showMessage("Dashboard layout saved.", 3000);
                }
                break;
            }

            case net_ops::protocol::MessageType::ErrorResp:
            {
                size_t offset = 0;
                auto msg = net_ops::protocol::UnpackString(resp->data, offset);
                if (msg)
                    QMessageBox::warning(this, "Server Error", QString::fromStdString(*msg));
                break;
            }

            default:
                break;
            }
        }
    }

    void MainWindow::onSaveLayoutClicked()
    {
        if (m_sessionToken.empty())
            return;
        sendDashboardConfigSave();
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
        if (!count)
            return;

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
            m_deviceTable->setItem(row, 2, new QTableWidgetItem(QString::fromStdString("Unknown")));
            m_deviceTable->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(*status + " " + *info)));
            m_deviceTable->setItem(row, 4, new QTableWidgetItem(QString::number(*id)));

            if (ip)
                monitorIPs.push_back(*ip);

            if (savedId != -1 && (int)*id == savedId)
            {
                m_deviceTable->selectRow(row);
            }
        }

        if (m_monitor)
            m_monitor->SetTargets(monitorIPs);
        if (m_snmpMonitor)
            m_snmpMonitor->SetTargets(monitorIPs);
    }

    void MainWindow::sendDashboardConfigRequest()
    {
        if (m_sessionToken.empty() || !m_controller)
            return;
        std::vector<uint8_t> payload;
        net_ops::protocol::PackString(payload, m_sessionToken);
        net_ops::protocol::PackUint32(payload, 0);
        m_controller->QueueRequest(net_ops::protocol::MessageType::DashboardConfigReq, payload);
    }

    void MainWindow::sendDashboardConfigSave()
    {
        if (m_sessionToken.empty() || !m_controller)
            return;
        std::vector<uint8_t> payload;
        net_ops::protocol::PackString(payload, m_sessionToken);
        net_ops::protocol::PackUint32(payload, 1);
        net_ops::protocol::PackString(payload, buildDashboardConfig());
        m_controller->QueueRequest(net_ops::protocol::MessageType::DashboardConfigReq, payload);
    }

    std::string MainWindow::buildDashboardConfig() const
    {
        auto serializeTable = [](const QTableWidget *table)
        {
            QJsonObject tableObj;
            QJsonArray orderArray;
            QJsonArray hiddenArray;
            QJsonArray widthArray;
            auto header = table->horizontalHeader();
            int count = table->columnCount();
            for (int visual = 0; visual < count; ++visual)
                orderArray.append(header->logicalIndex(visual));
            for (int logical = 0; logical < count; ++logical)
            {
                hiddenArray.append(table->isColumnHidden(logical));
                widthArray.append(table->columnWidth(logical));
            }
            tableObj["order"] = orderArray;
            tableObj["hidden"] = hiddenArray;
            tableObj["widths"] = widthArray;
            return tableObj;
        };

        QJsonObject root;
        root["version"] = 1;
        root["deviceTable"] = serializeTable(m_deviceTable);
        root["metricsTable"] = serializeTable(m_metricsTable);
        root["logTable"] = serializeTable(m_logTable);

        QJsonDocument doc(root);
        return doc.toJson(QJsonDocument::Compact).toStdString();
    }

    void MainWindow::applyDashboardConfig(const std::string &config)
    {
        QJsonParseError error;
        auto doc = QJsonDocument::fromJson(QByteArray::fromStdString(config), &error);
        if (error.error != QJsonParseError::NoError || !doc.isObject())
            return;

        auto applyTable = [](QTableWidget *table, const QJsonObject &tableObj)
        {
            auto header = table->horizontalHeader();
            auto orderArray = tableObj.value("order").toArray();
            auto hiddenArray = tableObj.value("hidden").toArray();
            auto widthArray = tableObj.value("widths").toArray();
            int count = table->columnCount();

            if (orderArray.size() == count)
            {
                for (int visual = 0; visual < count; ++visual)
                {
                    int logical = orderArray.at(visual).toInt();
                    int current = header->visualIndex(logical);
                    header->moveSection(current, visual);
                }
            }

            for (int logical = 0; logical < count; ++logical)
            {
                if (logical < hiddenArray.size())
                    table->setColumnHidden(logical, hiddenArray.at(logical).toBool());
                if (logical < widthArray.size())
                    table->setColumnWidth(logical, widthArray.at(logical).toInt());
            }
        };

        QJsonObject root = doc.object();
        if (root.contains("deviceTable"))
            applyTable(m_deviceTable, root.value("deviceTable").toObject());
        if (root.contains("metricsTable"))
            applyTable(m_metricsTable, root.value("metricsTable").toObject());
        if (root.contains("logTable"))
            applyTable(m_logTable, root.value("logTable").toObject());
    }
}
