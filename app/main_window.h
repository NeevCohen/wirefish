#include <chrono>

#include <QMainWindow>
#include <QWidget>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QAction>

#include "ui_mainwindow.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    MainWindow();
    void populate_interface_selector();

private:
    void start_capture_pressed();
    void stop_capture_pressed();
    void start_capturing();

private:
    std::chrono::steady_clock sc;
    std::chrono::steady_clock::time_point recording_start;

private:
    Ui::MainWindow *ui;
};