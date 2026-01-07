#include <QApplication>
#include "NetworkController.hpp"
#include "LoginWindow.hpp"
#include "MainWindow.hpp"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    auto controller = std::make_shared<net_ops::client::NetworkController>("127.0.0.1", 8080);
    controller->Start();

    net_ops::client::LoginWindow loginWin(controller);
    net_ops::client::MainWindow mainWin(controller);

    // When login is successful, hide login and show main
    QObject::connect(&loginWin, &net_ops::client::LoginWindow::loginSuccessful, [&]() {
        loginWin.hide();
        mainWin.show();
    });

    loginWin.show();

    int ret = app.exec();
    controller->Stop();
    return ret;
}