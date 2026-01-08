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
#include "SnmpMonitor.hpp"

namespace net_ops::client
{

    class MainWindow : public QMainWindow
    {
        Q_OBJECT

    public:
        explicit MainWindow(std::shared_ptr<NetworkController> controller,
                            std::shared_ptr<DeviceMonitor> monitor,
                            std::shared_ptr<SnmpMonitor> snmpMonitor,
                            QWidget *parent = nullptr);
        ~MainWindow();

        void SetToken(const std::string &token);

    protected:
        void showEvent(QShowEvent *event) override;

    private slots:
        void onScanClicked();
        void pollData();
        void onDeviceSelected(int row, int col);
        void onSaveLayoutClicked();

    private:
        std::shared_ptr<NetworkController> m_controller;
        std::shared_ptr<DeviceMonitor> m_monitor;
        std::shared_ptr<SnmpMonitor> m_snmpMonitor;
        QTableWidget *m_deviceTable;
        QTableWidget *m_logTable;
        QTableWidget *m_metricsTable;
        QTimer *m_dataTimer;
        std::string m_sessionToken;
        QPushButton *m_scanBtn;
        QPushButton *m_saveLayoutBtn;

        std::thread m_scanThread;
        std::atomic<bool> m_isScanning;

        int m_selectedDeviceId = -1;
        bool m_dashboardConfigLoaded = false;

        void setupUi();
        void updateDeviceList(const std::vector<uint8_t> &data);
        void addLogEntry(const std::string &timestamp, const std::string &msg);
        void sendDeviceListRequest();
        void sendLogQueryRequest();
        void sendMetricsRequest();
        void sendDashboardConfigRequest();
        void sendDashboardConfigSave();
        std::string buildDashboardConfig() const;
        void applyDashboardConfig(const std::string &config);
    };
}
