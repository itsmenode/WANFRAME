#include "LoginWindow.hpp"
#include <iostream>

namespace net_ops::client
{

    LoginWindow::LoginWindow(std::shared_ptr<NetworkController> controller, QWidget *parent)
        : QWidget(parent), m_controller(controller)
    {
        setupUi();
        m_responseTimer = new QTimer(this);
        connect(m_responseTimer, &QTimer::timeout, this, &LoginWindow::checkNetworkResponses);
        m_responseTimer->start(100);
    }

    void LoginWindow::setupUi()
    {
        auto layout = new QVBoxLayout(this);
        m_usernameField = new QLineEdit();
        m_passwordField = new QLineEdit();
        m_passwordField->setEchoMode(QLineEdit::Password);

        auto btnLayout = new QHBoxLayout();
        m_loginButton = new QPushButton("Login");
        m_signupButton = new QPushButton("Sign Up");
        btnLayout->addWidget(m_loginButton);
        btnLayout->addWidget(m_signupButton);

        layout->addWidget(new QLabel("Username:"));
        layout->addWidget(m_usernameField);
        layout->addWidget(new QLabel("Password:"));
        layout->addWidget(m_passwordField);
        layout->addLayout(btnLayout);
        m_statusLabel = new QLabel("Ready");
        layout->addWidget(m_statusLabel);

        connect(m_loginButton, &QPushButton::clicked, this, &LoginWindow::onLoginClicked);
        connect(m_signupButton, &QPushButton::clicked, this, &LoginWindow::onSignupClicked);
        setWindowTitle("WANFRAME Auth");
        resize(300, 200);
    }

    void LoginWindow::onLoginClicked()
    {
        std::vector<uint8_t> p;
        net_ops::protocol::PackString(p, m_usernameField->text().toStdString());
        net_ops::protocol::PackString(p, m_passwordField->text().toStdString());
        m_controller->QueueRequest(net_ops::protocol::MessageType::LoginReq, p);
        m_statusLabel->setText("Authenticating...");
        m_loginButton->setEnabled(false);
        m_signupButton->setEnabled(false);
    }

    void LoginWindow::onSignupClicked()
    {
        std::vector<uint8_t> p;
        net_ops::protocol::PackString(p, m_usernameField->text().toStdString());
        net_ops::protocol::PackString(p, m_passwordField->text().toStdString());
        m_controller->QueueRequest(net_ops::protocol::MessageType::SignupReq, p);
        m_statusLabel->setText("Creating account...");
        m_loginButton->setEnabled(false);
        m_signupButton->setEnabled(false);
    }

    void LoginWindow::checkNetworkResponses()
    {
        auto resp = m_controller->GetNextResponse();
        if (!resp)
            return;

        size_t off = 0;
        auto msg = net_ops::protocol::UnpackString(resp->data, off);

        if (resp->type == net_ops::protocol::MessageType::LoginResp)
        {
            if (msg && msg->find("LOGIN_SUCCESS") != std::string::npos)
            {
                std::string token = "";
                size_t delimiterPos = msg->find(':');
                if (delimiterPos != std::string::npos) {
                    token = msg->substr(delimiterPos + 1);
                }

                m_responseTimer->stop();
                emit loginSuccessful(token);
            }
            else
                m_statusLabel->setText("Login failed.");
        }
        else if (resp->type == net_ops::protocol::MessageType::SignupResp)
        {
            if (msg && msg->find("SIGNUP_SUCCESS") != std::string::npos)
                m_statusLabel->setText("Success! Now Login.");
            else
                m_statusLabel->setText("Signup failed.");
        }
        else
        {
            m_statusLabel->setText(QString::fromStdString(msg.value_or("Error")));
        }

        m_loginButton->setEnabled(true);
        m_signupButton->setEnabled(true);
    }
}