#include "MainWindow.hpp"
#include "Scanner.hpp"
#include <QHeaderView>

namespace net_ops::client {

    MainWindow::MainWindow(std::shared_ptr<NetworkController> controller, QWidget *parent)
        : QMainWindow(parent), m_controller(controller) {
        setupUi();
        m_dataTimer = new QTimer(this);
        connect(m_dataTimer, &QTimer::timeout, this, &MainWindow::pollData);
        m_dataTimer->start(200);

        m_controller->QueueRequest(net_ops::protocol::MessageType::DeviceListReq, {});
    }

    void MainWindow::setupUi() {
        auto central = new QWidget();
        auto layout = new QVBoxLayout(central);

        auto scanBtn = new QPushButton("Scan Network");
        connect(scanBtn, &QPushButton::clicked, this, &MainWindow::onScanClicked);
        layout->addWidget(scanBtn);

        m_deviceTable = new QTableWidget(0, 4);
        m_deviceTable->setHorizontalHeaderLabels({"Name", "IP", "MAC", "Status"});
        m_deviceTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        layout->addWidget(m_deviceTable);

        m_logTable = new QTableWidget(0, 2);
        m_logTable->setHorizontalHeaderLabels({"Timestamp", "Message"});
        m_logTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        layout->addWidget(m_logTable);

        setCentralWidget(central);
        setWindowTitle("WANFRAME Dashboard");
        resize(900, 700);
    }

    void MainWindow::onScanClicked() {
        // Run scanner in a background thread to avoid freezing UI
        std::thread([this]() {
            auto hosts = NetworkScanner::ScanLocalNetwork(); //
            for (const auto& h : hosts) {
                std::vector<uint8_t> p;
                net_ops::protocol::PackString(p, h.name);
                net_ops::protocol::PackString(p, h.ip);
                net_ops::protocol::PackString(p, h.mac);
                m_controller->QueueRequest(net_ops::protocol::MessageType::DeviceAddReq, p);
            }
        }).detach();
    }

    void MainWindow::pollData() {
        while (auto resp = m_controller->GetNextResponse()) {
            if (resp->type == net_ops::protocol::MessageType::DeviceListResp) {
                updateDeviceList(resp->data);
            } else if (resp->type == net_ops::protocol::MessageType::LogUploadResp) {
            }
        }
    }

    void MainWindow::updateDeviceList(const std::vector<uint8_t>& data) {
        size_t offset = 0;
        auto count = net_ops::protocol::UnpackUint32(data, offset);
        if (!count) return;

        m_deviceTable->setRowCount(0);
        for (uint32_t i = 0; i < *count; ++i) {
            auto id = net_ops::protocol::UnpackUint32(data, offset);
            auto name = net_ops::protocol::UnpackString(data, offset);
            auto ip = net_ops::protocol::UnpackString(data, offset);
            auto status = net_ops::protocol::UnpackString(data, offset);
            auto info = net_ops::protocol::UnpackString(data, offset);

            int row = m_deviceTable->rowCount();
            m_deviceTable->insertRow(row);
            m_deviceTable->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(*name)));
            m_deviceTable->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(*ip)));
            m_deviceTable->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(*status)));
        }
    }
}