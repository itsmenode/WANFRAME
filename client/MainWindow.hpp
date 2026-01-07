#pragma once

#include <QMainWindow>
#include <QTableWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QTimer>
#include <QShowEvent>
#include <memory>
#include "NetworkController.hpp"

namespace net_ops::client
{

    class MainWindow : public QMainWindow
    {
        Q_OBJECT

    public:
        explicit MainWindow(std::shared_ptr<NetworkController> controller, QWidget *parent = nullptr);

    protected:
        void showEvent(QShowEvent *event) override;

    private slots:
        void onScanClicked();
        void pollData();

    private:
        std::shared_ptr<NetworkController> m_controller;
        QTableWidget *m_deviceTable;
        QTableWidget *m_logTable;
        QTimer *m_dataTimer;

        void setupUi();
        void updateDeviceList(const std::vector<uint8_t> &data);
        void addLogEntry(const std::string &timestamp, const std::string &msg);
    };
}