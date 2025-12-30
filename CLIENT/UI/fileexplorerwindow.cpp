#include "fileexplorerwindow.hpp"
#include "mainwindow.hpp"
#include "ui_fileexplorerwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QFileInfo>
#include <QDir>

static void upload_callback(int result, void* arg) {
    FileExplorerWindow* window = (FileExplorerWindow*)arg;
    QMetaObject::invokeMethod(window, "onUploadFinished", Qt::QueuedConnection, Q_ARG(int, result));
}

FileExplorerWindow::FileExplorerWindow(ClientBackend* client, QWidget *parent) :
    QWidget(nullptr),
    ui(new Ui::FileExplorerWindow),
    client(client)
{
    mw = qobject_cast<MainWindow*>(parent);
    ui->setupUi(this);

    // Connect Navigation
    connect(ui->btnBack, &QPushButton::clicked, this, &FileExplorerWindow::goUp);
    connect(ui->btnForward, &QPushButton::clicked, this, [=]() {
        QListWidgetItem* item = ui->fileList->currentItem();
        if (item) enterFolder(item);
    });
    connect(ui->fileList, &QListWidget::itemDoubleClicked, this, &FileExplorerWindow::enterFolder);

    // Connect Upload Button
    connect(ui->pushButton, &QPushButton::clicked, this, [=]() {
        QString fileName = QFileDialog::getOpenFileName(this, "Select File to Upload");
        if (!fileName.isEmpty()) {
            std::string path = fileName.toStdString();
            client->upload_async(path,current_folder_id, upload_callback, this);
        }
    });

    // Connect Download Button
    connect(ui->pushButton_2, &QPushButton::clicked, this, [=]() {
        QListWidgetItem* item = ui->fileList->currentItem();
        if (!item) {
            QMessageBox::warning(this, "Download", "Please select a file.");
            return;
        }
        if (item->data(Qt::UserRole + 1).toBool()) { // Is folder
             QMessageBox::warning(this, "Download", "Cannot download a folder.");
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
        // Remove [DIR] prefix if present
        if (item->data(Qt::UserRole + 1).toBool()) {
             filename = filename.substr(6); // Remove "[DIR] "
        }

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

    // Logout
    connect(ui->pushButton_5, &QPushButton::clicked, this, [=]() {
        mw->show();
        this->hide();
        client->close_client();
    });

    refresh_list();
}

FileExplorerWindow::~FileExplorerWindow()
{
    delete ui;
}

void FileExplorerWindow::refresh_list() {
    ui->fileList->clear();
    vector<FileInfo> files = client->list_files(current_folder_id);
    for (const auto& f : files) {
        QListWidgetItem* item = new QListWidgetItem(QString::fromStdString(f.name));
        item->setData(Qt::UserRole, f.id);
        item->setData(Qt::UserRole + 1, f.is_folder);
        if (f.is_folder) {
            // item->setIcon(QIcon::fromTheme("folder")); 
            item->setText("[DIR] " + item->text());
        } else {
            // item->setIcon(QIcon::fromTheme("text-x-generic"));
        }
        ui->fileList->addItem(item);
    }
}

void FileExplorerWindow::goUp() {
    if (!folder_history.empty()) {
        current_folder_id = folder_history.top();
        folder_history.pop();
        refresh_list();
    }
}

void FileExplorerWindow::enterFolder(QListWidgetItem* item) {
    if (item->data(Qt::UserRole + 1).toBool()) {
        folder_history.push(current_folder_id);
        current_folder_id = item->data(Qt::UserRole).toInt();
        refresh_list();
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