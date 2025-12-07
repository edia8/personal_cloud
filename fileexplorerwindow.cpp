#include "fileexplorerwindow.hpp"
#include "mainwindow.hpp"
#include "ui_fileexplorerwindow.h"
#include <QFileDialog>
#include <QMessageBox>

FileExplorerWindow::FileExplorerWindow(ClientBackend* client, QWidget *parent) :
    QWidget(nullptr), // Set parent to nullptr to make it a top-level window
    ui(new Ui::FileExplorerWindow),
    client(client)
{
    mw = qobject_cast<MainWindow*>(parent); // Store the parent (MainWindow) for later use
    ui->setupUi(this);

    // Connect Upload Button
    connect(ui->pushButton, &QPushButton::clicked, this, [=]() {
        QString fileName = QFileDialog::getOpenFileName(this, "Select File to Upload");
        if (!fileName.isEmpty()) {
            std::string path = fileName.toStdString();
            std::string response = client->upload(path);
            
            if (response.rfind("Error:", 0) == 0) {
                QMessageBox::critical(this, "Upload Failed", QString::fromStdString(response));
            } else {
                // Success: Update the label with the server's response
                ui->label->setText(QString::fromStdString(response));
                QMessageBox::information(this, "Upload", "Upload successful!");
            }
        }
    });
    // Connect Download Button
    connect(ui->pushButton_2, &QPushButton::clicked, this, [=]() {
        const string path = "Verficare download.";    
        string response = client->download(path);
            
            if (response.rfind("Error:", 0) == 0) {
                QMessageBox::critical(this, "Download Failed", QString::fromStdString(response));
            }else {
                // Success: Update the label with the server's response
                ui->label->setText(QString::fromStdString(response));
                QMessageBox::information(this, "Download", "Download successful!");
            }
    });
    connect(ui->pushButton_5, &QPushButton::clicked, this, [=]() {
        mw->show();
        this->hide();
        ui->label->setText(QString::fromStdString(string("Proba")));
        client->close_client();
    });
    connect(ui->pushButton_4, &QPushButton::clicked, this, [=]() {
        const string str = "Apasat delete.";
        string response = client->del(str);

        if(response.rfind("Error:",0) == 0) {
            QMessageBox::critical(this, "Delete Failed", QString::fromStdString(response));
        }else {
            ui->label->setText(QString::fromStdString(response));
            QMessageBox::information(this,"Delete","Delete succesfull!");
        }
    });
}

FileExplorerWindow::~FileExplorerWindow()
{
    delete ui;
}