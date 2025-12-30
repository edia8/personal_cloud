#pragma once

#include <QWidget>
#include <QListWidgetItem>
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
    int current_folder_id = 0;
    std::stack<int> folder_history;

    void refresh_list();
    void goUp();
    void enterFolder(QListWidgetItem* item);
};