#include "mainwindow.hpp"
#include "fileexplorerwindow.hpp"
#include "ui_mainwindow.h"
#include <qtoolbutton.h>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow) // Initialize the UI pointer
{
    // This function converts the XML .ui file into actual C++ widgets
    ui->setupUi(this);

    // Connect to server on startup
    if (!client.connect("10.100.0.30", PORT)) {
        QMessageBox::critical(this, "Connection Error", "Could not connect to server at 10.100.0.30:" + QString::number(PORT));
    }

    // --- YOUR LOGIC GOES HERE ---

    // Connect the Show Password button
    connect(ui->toolButton_showPw, &QToolButton::toggled, this, [=](bool checked) {
        if (checked) {
            ui->lineEdit_2->setEchoMode(QLineEdit::Normal);
        } else {
            ui->lineEdit_2->setEchoMode(QLineEdit::Password);
        }
    });

    // Connect the LOGIN button (pushButton)
    connect(ui->pushButton, &QPushButton::clicked, this, [=]() {
        QString username = ui->lineEdit->text();
        QString password = ui->lineEdit_2->text();
        
        if(username.isEmpty() || password.isEmpty()) {
            QMessageBox::warning(this, "Login Failed", "Please enter both username and password.");
            return;
        }

        unsigned long token = client.login(username.toStdString(), password.toStdString());
        
        if (token != 0) {
            //QMessageBox::information(this, "Login Success", "Logged in! Token: " + QString::number(token));
            client.send_link_packet(token);

            if(!fileWindow) {
                fileWindow = new FileExplorerWindow(&client, this);
            }
            fileWindow->show();
            this->hide();
            ui->lineEdit->clear();
            ui->lineEdit_2->clear();
        } else {
            QMessageBox::warning(this, "Login Failed", "Invalid username or password.");
        }
    });

    // Connect the REGISTER button (pushButton_2)
    connect(ui->pushButton_2, &QPushButton::clicked, this, [=]() {
        QString username = ui->lineEdit->text();
        QString password = ui->lineEdit_2->text();

        if(username.isEmpty() || password.isEmpty()) {
            QMessageBox::warning(this, "Register Failed", "Please enter both username and password.");
            return;
        }

        int result = client.register_user(username.toStdString(), password.toStdString());
        
        if (result == 1) {
            QMessageBox::information(this, "Register", "Registration successful! You can now login.");
        } else if (result == 2) {
            QMessageBox::warning(this, "Register Failed", "Username already taken.");
        } else {
            QMessageBox::critical(this, "Register Failed", "Database or Server error.");
        }
    });
}

MainWindow::~MainWindow() {
    delete ui; // Cleanup
}