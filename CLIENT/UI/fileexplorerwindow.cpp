#include "fileexplorerwindow.hpp"
#include "mainwindow.hpp"
#include "ui_fileexplorerwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QFileInfo>
#include <QDir>
#include <QInputDialog>
#include <QHeaderView>

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

    // Configure columns to be equal width (50/50) and not resizable by user
    ui->fileList->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    ui->fileList->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->fileList->header()->setSectionResizeMode(2, QHeaderView::Stretch);

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
        QTreeWidgetItem* item = ui->fileList->currentItem();
        if (!item) {
            QMessageBox::warning(this, "Download", "Please select a file.");
            return;
        }
        // Remove [DIR] prefix if present (though it shouldn't be for files)
        string filename = item->text(0).toStdString();
        if (0 != client->download(filename) ) {
            QMessageBox::critical(this, "Download Failed", QString::fromStdString("Download Failed"));
        } else {
             QMessageBox::information(this, "Download", "Download successful!");
        }
    });

    // Connect Delete Button
    connect(ui->pushButton_4, &QPushButton::clicked, this, [=]() {
        QTreeWidgetItem* item = ui->fileList->currentItem();
        if (!item) {
            QMessageBox::warning(this, "Delete", "Please select a file.");
            return;
        }
        string filename = item->text(0).toStdString();

        string response = client->del(filename);

        if(response.find("Failed") != string::npos || response.rfind("Error:",0) == 0) {
            QMessageBox::critical(this, "Delete Failed", QString::fromStdString(response));
        }else {
            QMessageBox::information(this,"Delete", QString::fromStdString(response));
            refresh_list();
        }
    });

    // Connect Refresh Button
    connect(ui->pushButton_Refresh, &QPushButton::clicked, this, &FileExplorerWindow::refresh_list);

    // Connect Share Button
    connect(ui->pushButton_Share, &QPushButton::clicked, this, [=]() {
        QTreeWidgetItem* item = ui->fileList->currentItem();
        if (!item) {
            QMessageBox::warning(this, "Share", "Please select a file to share first.");
            return;
        }
        string filename = item->text(0).toStdString();

        bool ok;
        QString targetUser = QInputDialog::getText(this, "Share File",
                                                 "Share '" + item->text(0) + "' with user:",
                                                 QLineEdit::Normal,
                                                 "", &ok);
        
        if (ok && !targetUser.isEmpty()) {
            string userStr = targetUser.toStdString();
            string result = client->share_file(filename, userStr);
            
            cout << "[DEBUG] UI Share Result: " << result << endl;

            if (result.find("Success") != string::npos) {
                QMessageBox::information(this, "Share Success", QString::fromStdString(result));
            } else {
                QMessageBox::critical(this, "Share Failed", QString::fromStdString(result));
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

string sizeFormatter(unsigned long size) {
    stringstream s;
    string number,dimension;
    double nr = size;
    if(size > 1024*1024*1024) {
        nr /= (1024*1024*1024);
        dimension = "GB";
    } else if (size > 1024*1024) {
        nr /= (1024*1024);
        dimension = "MB";
    } else if (size > 1024) {
        nr /= 1024;
        dimension = "KB";
    } else {
        nr = size;
        dimension = "bytes";
    }


    if(dimension == "bytes") {
        s<<nr;
    } else {
        s << fixed << setprecision(2) << nr;
    }

    number = s.str();
    return number+" "+dimension;
}

void FileExplorerWindow::refresh_list() {
    ui->fileList->clear();
    vector<FileInfo> files = client->list_files();
    for (const auto& f : files) {
        QTreeWidgetItem* item = new QTreeWidgetItem(ui->fileList);
        item->setText(0, QString::fromStdString(f.name));
        item->setText(1, QString::fromStdString(sizeFormatter(f.size)));        item->setText(2, QString::fromStdString(f.owner));        item->setData(0, Qt::UserRole, f.id);
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