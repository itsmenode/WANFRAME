#pragma once

#include <QMainWindow>
#include <QTableWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QTimer>
#include <QShowEvent>
#include <memory>
#include "NetworkController.hpp"
#include "DeviceMonitor.hpp"

namespace net_ops::client
{

    class MainWindow : public QMainWindow
    {
        Q_OBJECT

    public:
        explicit MainWindow(std::shared_ptr<NetworkController> controller,
                            std::shared_ptr<DeviceMonitor> monitor,
                            QWidget *parent = nullptr);

        void SetToken(const std::string &token);

    protected:
        void showEvent(QShowEvent *event) override;

    private slots:
        void onScanClicked();
        void pollData();

    private:
        std::shared_ptr<NetworkController> m_controller;
        std::shared_ptr<DeviceMonitor> m_monitor;
        QTableWidget *m_deviceTable;
        QTableWidget *m_logTable;
        QTimer *m_dataTimer;
        std::string m_sessionToken;

        void setupUi();
        void updateDeviceList(const std::vector<uint8_t> &data);
        void addLogEntry(const std::string &timestamp, const std::string &msg);
        void sendDeviceListRequest();
    };
}