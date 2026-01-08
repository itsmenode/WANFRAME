#pragma once

#include <QMainWindow>
#include <QTableWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QTimer>
#include <QShowEvent>
#include <memory>
#include <thread>
#include <atomic>
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
        ~MainWindow();

        void SetToken(const std::string &token);

    protected:
        void showEvent(QShowEvent *event) override;

    private slots:
        void onScanClicked();
        void pollData();
        void onDeviceSelected(int row, int col);

    private:
        std::shared_ptr<NetworkController> m_controller;
        std::shared_ptr<DeviceMonitor> m_monitor;
        QTableWidget *m_deviceTable;
        QTableWidget *m_logTable;
        QTimer *m_dataTimer;
        std::string m_sessionToken;
        QPushButton *m_scanBtn;

        std::thread m_scanThread;
        std::atomic<bool> m_isScanning;

        int m_selectedDeviceId = -1;

        void setupUi();
        void updateDeviceList(const std::vector<uint8_t> &data);
        void addLogEntry(const std::string &timestamp, const std::string &msg);
        void sendDeviceListRequest();
        void sendLogQueryRequest();
    };
}