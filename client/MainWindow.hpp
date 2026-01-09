#pragma once

#include <QMainWindow>
#include <QTableWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QTimer>
#include <QShowEvent>
#include <memory>
#include <thread>
#include <atomic>
#include <vector>
#include "NetworkController.hpp"
#include "DeviceMonitor.hpp"
#include "SyslogCollector.hpp"

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
        void onSimulateClicked();
        void onLogoutClicked();
        void pollData();
        void performContinuousScan();
        void runSimulationStep();
        void onDeviceSelected(int row, int col);
        void onFilterLogs(const QString &text);

    private:
        std::shared_ptr<NetworkController> m_controller;
        std::shared_ptr<DeviceMonitor> m_monitor;
        std::unique_ptr<SyslogCollector> m_syslogCollector;
        
        QTableWidget *m_deviceTable;
        QTableWidget *m_logTable;
        QLineEdit *m_filterInput;
        QLabel *m_statsLabel;
        
        QTimer *m_dataTimer;
        QTimer *m_discoveryTimer;
        QTimer *m_simTimer;
        
        std::string m_sessionToken;
        QPushButton *m_scanBtn;
        QPushButton *m_simBtn;
        QPushButton *m_logoutBtn;

        std::thread m_scanThread;
        std::atomic<bool> m_isScanning;

        int m_selectedDeviceId = -1;
        int m_onlineCount = 0;
        int m_syslogPort = 0;
        
        std::vector<std::string> m_fakeIps;

        void setupUi();
        void updateDeviceList(const std::vector<uint8_t> &data);
        void addLogEntry(const std::string &timestamp, const std::string &msg);
        void sendDeviceListRequest();
        void sendLogQueryRequest();
        void updateStats();
        
        void createFakeDevices();
    };
}