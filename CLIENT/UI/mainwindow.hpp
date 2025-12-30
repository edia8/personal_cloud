#pragma once

#include <QMainWindow>
#include "client.hpp"

class FileExplorerWindow;

// This namespace is where the "Generated" code lives
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT // Necessary macro for Signals/Slots

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    // This pointer is your gateway to the UI elements (buttons, inputs)
    Ui::MainWindow *ui; 
    ClientBackend client;
    FileExplorerWindow *fileWindow = nullptr;
};