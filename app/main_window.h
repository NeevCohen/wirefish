#include <chrono>

#include <QMainWindow>
#include <QWidget>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QAction>
#include <QThread>

#include "libsniff.h"

#include "ui_mainwindow.h"
#include "capture_reader.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    MainWindow();

signals:
    void start_capturing();
    void stop_capturing();

public slots:
    void packet_captured(const EthernetFrame &ethernet_frame);
    void capture_thread_stopped();
    void start_capture_failed(const std::string &error_message);

private:
    void populate_interface_selector();
    void start_capture_pressed();
    void stop_capture_pressed();

private:
    std::chrono::steady_clock m_sc;
    std::chrono::steady_clock::time_point m_recording_start;
    CaptureReader *m_capture_reader = nullptr;

private:
    QThread *m_capture_thread = nullptr;
    Ui::MainWindow *m_ui = nullptr;
};