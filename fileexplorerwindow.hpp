#pragma once

#include <QWidget>
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

private:
    Ui::FileExplorerWindow *ui;
    MainWindow *mw = nullptr;
    ClientBackend* client;
};