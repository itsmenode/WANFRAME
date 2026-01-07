#include "LoginWindow.hpp"

namespace net_ops::client {

    LoginWindow::LoginWindow(std::shared_ptr<NetworkController> controller, QWidget *parent)
        : QWidget(parent), m_controller(controller) {
        setupUi();
        m_responseTimer = new QTimer(this);
        connect(m_responseTimer, &QTimer::timeout, this, &LoginWindow::checkNetworkResponses);
        m_responseTimer->start(100);
    }

    void LoginWindow::setupUi() {
        auto layout = new QVBoxLayout(this);
        layout->addWidget(new QLabel("Username:"));
        m_usernameField = new QLineEdit();
        layout->addWidget(m_usernameField);

        layout->addWidget(new QLabel("Password:"));
        m_passwordField = new QLineEdit();
        m_passwordField->setEchoMode(QLineEdit::Password);
        layout->addWidget(m_passwordField);

        m_loginButton = new QPushButton("Login");
        layout->addWidget(m_loginButton);

        m_statusLabel = new QLabel("");
        layout->addWidget(m_statusLabel);

        connect(m_loginButton, &QPushButton::clicked, this, &LoginWindow::onLoginClicked);
        this->setWindowTitle("WANFRAME - Login");
    }

    void LoginWindow::onLoginClicked() {
        std::string user = m_usernameField->text().toStdString();
        std::string pass = m_passwordField->text().toStdString();
        if (user.empty() || pass.empty()) return;

        std::vector<uint8_t> payload;
        net_ops::protocol::PackString(payload, user);
        net_ops::protocol::PackString(payload, pass);

        m_controller->QueueRequest(net_ops::protocol::MessageType::LoginReq, payload); //
        m_statusLabel->setText("Authenticating...");
        m_loginButton->setEnabled(false);
    }

    void LoginWindow::checkNetworkResponses() {
        auto resp = m_controller->GetNextResponse();
        if (!resp) return;

        if (resp->type == net_ops::protocol::MessageType::LoginResp) {
            std::string data(resp->data.begin(), resp->data.end());
            if (data.find("LOGIN_SUCCESS") != std::string::npos) {
                emit loginSuccessful();
            } else {
                m_statusLabel->setText("Invalid credentials.");
                m_loginButton->setEnabled(true);
            }
        }
    }
}