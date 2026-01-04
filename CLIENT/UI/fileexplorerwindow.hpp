#pragma once

#include <QWidget>
#include <QTreeWidgetItem>
#include <stack>
#include "client.hpp"

class MainWindow;

namespace Ui {
class FileExplorerWindow;
}

class FileExplorerWindow : public QWidget
{
    Q_OBJECT

public:
    explicit FileExplorerWindow(ClientBackend* client, QWidget *parent = nullptr);
    ~FileExplorerWindow();

public slots:
    void onUploadFinished(int result);

private:
    Ui::FileExplorerWindow *ui;
    MainWindow *mw = nullptr;
    ClientBackend* client;
    void refresh_list();
};