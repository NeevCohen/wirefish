#include <string>

#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QAction>
#include <QTableWidgetItem>

#include "main_window.h"
#include "libsniff.h"

MainWindow::MainWindow() : m_ui(new Ui::MainWindow)
{
    m_ui->setupUi(this);
    populate_interface_selector();
    connect(m_ui->start_capture_button, &QPushButton::released, this, &MainWindow::start_capture_pressed);
    connect(m_ui->stop_capture_button, &QPushButton::released, this, &MainWindow::stop_capture_pressed);
}

void MainWindow::start_capture_pressed()
{
    m_ui->capture_table->setRowCount(0);
    m_recording_start = m_sc.now();
    m_capture_reader = new CaptureReader(SnifferOptions{.interface_name = m_ui->interface_selector->currentText().toStdString()});
    m_capture_thread = new QThread(this);
    m_capture_reader->moveToThread(m_capture_thread);
    connect(m_capture_reader, &CaptureReader::new_capture, this, &MainWindow::packet_captured);
    connect(m_capture_thread, &QThread::finished, m_capture_reader, &QObject::deleteLater);
    connect(m_capture_thread, &QThread::finished, this, &MainWindow::capture_thread_stopped);
    connect(m_capture_thread, &QThread::started, m_capture_reader, &CaptureReader::start_capturing);
    connect(this, &MainWindow::start_capturing, m_capture_reader, &CaptureReader::start_capturing);
    connect(this, &MainWindow::stop_capturing, m_capture_reader, &CaptureReader::stop_capturing);
    connect(m_capture_reader, &CaptureReader::start_capture_failed, this, &MainWindow::start_capture_failed);
    m_capture_thread->start();
    m_ui->start_capture_button->setEnabled(false);
    m_ui->stop_capture_button->setEnabled(!m_ui->start_capture_button->isEnabled());
}

void MainWindow::start_capture_failed(const std::string &error_message)
{
    qWarning() << error_message;
}

void MainWindow::stop_capture_pressed()
{
    emit stop_capturing();
    m_capture_thread->quit();
    m_ui->stop_capture_button->setEnabled(false);
    m_ui->start_capture_button->setEnabled(!m_ui->stop_capture_button->isEnabled());
}

void MainWindow::capture_thread_stopped()
{
    if (m_capture_thread != nullptr)
    {
        delete m_capture_thread;
        m_capture_thread = nullptr;
    }
}

void MainWindow::populate_interface_selector()
{
    auto interfaces = get_interfaces_names();
    for (auto &interface : interfaces)
    {
        m_ui->interface_selector->addItem(QString::fromStdString(interface));
    }
}

void MainWindow::packet_captured(const EthernetFrame &ethernet_frame)
{
    QTableWidget *table = m_ui->capture_table;
    int row = table->rowCount();
    table->insertRow(row);
    for (int col = 0; col < table->columnCount(); col++)
    {
        QTableWidgetItem *item = new QTableWidgetItem;
        if (col == 0)
        {
            auto timestamp = static_cast<std::chrono::duration<double>>(m_sc.now() - m_recording_start);
            item->setText(tr("%1").arg(timestamp.count()));
        }
        else if (col == 1)
        {
            item->setText(QString::fromStdString(parse_mac_address(ethernet_frame.ethernet_header->ether_shost)));
        }
        else if (col == 2)
        {
            item->setText(QString::fromStdString(parse_mac_address(ethernet_frame.ethernet_header->ether_dhost)));
        }
        else
        {
            item->setText(tr("item %1").arg(col));
        }
        table->setItem(row, col, item);
    }
    table->scrollToBottom();
}
