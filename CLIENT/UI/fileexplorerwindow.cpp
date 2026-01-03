#include "fileexplorerwindow.hpp"
#include "mainwindow.hpp"
#include "ui_fileexplorerwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QFileInfo>
#include <QDir>
#include <QInputDialog>

static void upload_callback(int result, void* arg) {
    FileExplorerWindow* window = (FileExplorerWindow*)arg;
    QMetaObject::invokeMethod(window, "onUploadFinished", Qt::QueuedConnection, Q_ARG(int, result));
}

FileExplorerWindow::FileExplorerWindow(ClientBackend* client, QWidget *parent) :
    QWidget(nullptr),
    ui(new Ui::FileExplorerWindow),
    client(client)
{
    cout<<"Fereastra construita\n";
    mw = qobject_cast<MainWindow*>(parent);
    ui->setupUi(this);

    // Connect Upload Button
    connect(ui->pushButton, &QPushButton::clicked, this, [=]() {
        QString fileName = QFileDialog::getOpenFileName(this, "Select File to Upload");
        if (!fileName.isEmpty()) {
            std::string path = fileName.toStdString();
            client->upload_async(path, upload_callback, this);
        }
    });

    // Connect Download Button
    connect(ui->pushButton_2, &QPushButton::clicked, this, [=]() {
        QListWidgetItem* item = ui->fileList->currentItem();
        if (!item) {
            QMessageBox::warning(this, "Download", "Please select a file.");
            return;
        }
        // Remove [DIR] prefix if present (though it shouldn't be for files)
        string filename = item->text().toStdString();
        if (0 != client->download(filename) ) {
            QMessageBox::critical(this, "Download Failed", QString::fromStdString("Download Failed"));
        } else {
             QMessageBox::information(this, "Download", "Download successful!");
        }
    });

    // Connect Delete Button
    connect(ui->pushButton_4, &QPushButton::clicked, this, [=]() {
        QListWidgetItem* item = ui->fileList->currentItem();
        if (!item) {
            QMessageBox::warning(this, "Delete", "Please select a file.");
            return;
        }
        string filename = item->text().toStdString();

        string response = client->del(filename);

        if(response.rfind("Error:",0) == 0) {
            QMessageBox::critical(this, "Delete Failed", QString::fromStdString(response));
        }else {
            QMessageBox::information(this,"Delete","Delete succesfull!");
            refresh_list();
        }
    });

    // Connect Refresh Button
    connect(ui->pushButton_Refresh, &QPushButton::clicked, this, &FileExplorerWindow::refresh_list);

    // Connect Share Button
    connect(ui->pushButton_Share, &QPushButton::clicked, this, [=]() {
        QListWidgetItem* item = ui->fileList->currentItem();
        if (!item) {
            QMessageBox::warning(this, "Share", "Please select a file to share first.");
            return;
        }
        string filename = item->text().toStdString();

        bool ok;
        QString targetUser = QInputDialog::getText(this, "Share File",
                                                 "Share '" + item->text() + "' with user:",
                                                 QLineEdit::Normal,
                                                 "", &ok);
        
        if (ok && !targetUser.isEmpty()) {
            string userStr = targetUser.toStdString();
            string result = client->share_file(filename, userStr);

            if (result.find("Error") != string::npos) {
                QMessageBox::critical(this, "Share Failed", QString::fromStdString(result));
            } else {
                QMessageBox::information(this, "Share Success", QString::fromStdString(result));
            }
        }
    });

    // Logout
    connect(ui->pushButton_5, &QPushButton::clicked, this, [=]() {
        mw->show();
        this->hide();
        client->close_client();
        this->~FileExplorerWindow();
    });

    refresh_list();
}

FileExplorerWindow::~FileExplorerWindow()
{
    delete ui;
}

void FileExplorerWindow::refresh_list() {
    ui->fileList->clear();
    vector<FileInfo> files = client->list_files();
    for (const auto& f : files) {
        QListWidgetItem* item = new QListWidgetItem(QString::fromStdString(f.name));
        item->setData(Qt::UserRole, f.id);
        ui->fileList->addItem(item);
    }
}

void FileExplorerWindow::onUploadFinished(int result) {
    if (result != 0) {
        if(result == 4) {
             QMessageBox::critical(this, "Upload Failed", "You have another file with the same name in this directory");
        } else {
            QMessageBox::critical(this, "Upload Failed", "Upload failed with error code: " + QString::number(result));
        }
    } else {
        QMessageBox::information(this, "Upload", "Upload successful!");
        refresh_list();
    }
}