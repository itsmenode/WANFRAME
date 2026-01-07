#include "LoginWindow.hpp"

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

        layout->addWidget(new QLabel("Username:"));
        m_usernameField = new QLineEdit();
        m_usernameField->setPlaceholderText("Enter username...");
        layout->addWidget(m_usernameField);

        layout->addWidget(new QLabel("Password:"));
        m_passwordField = new QLineEdit();
        m_passwordField->setEchoMode(QLineEdit::Password);
        m_passwordField->setPlaceholderText("Enter password...");
        layout->addWidget(m_passwordField);

        auto buttonLayout = new QHBoxLayout();
        m_loginButton = new QPushButton("Login");
        m_signupButton = new QPushButton("Sign Up");
        buttonLayout->addWidget(m_loginButton);
        buttonLayout->addWidget(m_signupButton);
        layout->addLayout(buttonLayout);

        m_statusLabel = new QLabel("");
        m_statusLabel->setAlignment(Qt::AlignCenter);
        layout->addWidget(m_statusLabel);

        connect(m_loginButton, &QPushButton::clicked, this, &LoginWindow::onLoginClicked);
        connect(m_signupButton, &QPushButton::clicked, this, &LoginWindow::onSignupClicked);

        this->setWindowTitle("WANFRAME - Authentication");
        this->setMinimumWidth(320);
    }

    void LoginWindow::onLoginClicked()
    {
        std::string user = m_usernameField->text().toStdString();
        std::string pass = m_passwordField->text().toStdString();
        if (user.empty() || pass.empty())
        {
            m_statusLabel->setText("Fields cannot be empty.");
            return;
        }

        std::vector<uint8_t> payload;
        net_ops::protocol::PackString(payload, user);
        net_ops::protocol::PackString(payload, pass);

        m_controller->QueueRequest(net_ops::protocol::MessageType::LoginReq, payload);
        m_statusLabel->setText("Authenticating...");
        m_loginButton->setEnabled(false);
        m_signupButton->setEnabled(false);
    }

    void LoginWindow::onSignupClicked()
    {
        std::string user = m_usernameField->text().toStdString();
        std::string pass = m_passwordField->text().toStdString();
        if (user.empty() || pass.empty())
        {
            m_statusLabel->setText("Fields cannot be empty.");
            return;
        }

        std::vector<uint8_t> payload;
        net_ops::protocol::PackString(payload, user);
        net_ops::protocol::PackString(payload, pass);

        m_controller->QueueRequest(net_ops::protocol::MessageType::SignupReq, payload);
        m_statusLabel->setText("Creating account...");
        m_loginButton->setEnabled(false);
        m_signupButton->setEnabled(false);
    }

    void LoginWindow::checkNetworkResponses()
    {
        auto resp = m_controller->GetNextResponse();
        if (!resp)
            return;

        if (resp->type == net_ops::protocol::MessageType::LoginResp)
        {
            std::string data(resp->data.begin(), resp->data.end());
            if (data.find("LOGIN_SUCCESS") != std::string::npos)
            {
                emit loginSuccessful();
            }
            else
            {
                m_statusLabel->setText("Invalid credentials.");
                m_loginButton->setEnabled(true);
                m_signupButton->setEnabled(true);
            }
        }
        else if (resp->type == net_ops::protocol::MessageType::SignupResp)
        {
            std::string data(resp->data.begin(), resp->data.end());
            if (data.find("SIGNUP_SUCCESS") != std::string::npos)
            {
                m_statusLabel->setText("Account created! You can now login.");
            }
            else
            {
                m_statusLabel->setText("Signup failed. User may already exist.");
            }
            m_loginButton->setEnabled(true);
            m_signupButton->setEnabled(true);
        }
        else if (resp->type == net_ops::protocol::MessageType::ErrorResp)
        {
            m_statusLabel->setText("Server Error: Check connection.");
            m_loginButton->setEnabled(true);
            m_signupButton->setEnabled(true);
        }
    }
}