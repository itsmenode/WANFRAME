#pragma once

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QLabel>
#include <QTimer>
#include <memory>
#include "NetworkController.hpp"

namespace net_ops::client {

    class LoginWindow : public QWidget {
        Q_OBJECT

    public:
        explicit LoginWindow(std::shared_ptr<NetworkController> controller, QWidget *parent = nullptr);

    signals:
        void loginSuccessful();

    private slots:
        void onLoginClicked();
        void checkNetworkResponses();

    private:
        std::shared_ptr<NetworkController> m_controller;
        QLineEdit *m_usernameField;
        QLineEdit *m_passwordField;
        QPushButton *m_loginButton;
        QLabel *m_statusLabel;
        QTimer *m_responseTimer;

        void setupUi();
    };
}