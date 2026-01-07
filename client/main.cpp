#include <QApplication>
#include <QMainWindow>
#include <QTimer>
#include <iostream>
#include "NetworkController.hpp"

class MainWindow : public QMainWindow {
public:
    MainWindow(std::shared_ptr<net_ops::client::NetworkController> controller) 
        : m_controller(controller) 
    {
        this->setWindowTitle("WANFRAME - Network Monitor");
        this->resize(800, 600);

        m_pollTimer = new QTimer(this);
        connect(m_pollTimer, &QTimer::timeout, this, &MainWindow::processNetworkResponses);
        m_pollTimer->start(100);
    }

private slots:
    void processNetworkResponses() {
        auto resp = m_controller->GetNextResponse();
        while (resp) {
            std::cout << "[UI] Received message type: " << (int)resp->type << "\n";
            
            if (resp->type == net_ops::protocol::MessageType::LoginResp) {
            }

            resp = m_controller->GetNextResponse();
        }
    }

private:
    std::shared_ptr<net_ops::client::NetworkController> m_controller;
    QTimer* m_pollTimer;
};

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    auto controller = std::make_shared<net_ops::client::NetworkController>("127.0.0.1", 8080);
    controller->Start();

    MainWindow win(controller);
    win.show();

    int result = app.exec();

    controller->Stop();
    return result;
}