#include <string>

#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QAction>
#include <QTableWidgetItem>
#include <QDebug>

#include "main_window.h"
#include "libsniff.h"

MainWindow::MainWindow() : ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    populate_interface_selector();
    connect(ui->start_capture_button, &QPushButton::released, this, &MainWindow::start_capture_pressed);
    connect(ui->stop_capture_button, &QPushButton::released, this, &MainWindow::stop_capture_pressed);
}

void MainWindow::start_capture_pressed()
{
    recording_start = sc.now();
    ui->start_capture_button->setEnabled(false);
    ui->stop_capture_button->setEnabled(!ui->start_capture_button->isEnabled());
    start_capturing();
}

void MainWindow::stop_capture_pressed()
{
    ui->start_capture_button->setEnabled(true);
    ui->stop_capture_button->setEnabled(!ui->start_capture_button->isEnabled());
}

void MainWindow::populate_interface_selector()
{
    auto interfaces = get_interfaces_names();
    for (auto &interface : interfaces)
    {
        ui->interface_selector->addItem(QString::fromStdString(interface));
    }
}

void MainWindow::start_capturing()
{
    // TODO: start a thread that captures packets using libsniff
    QTableWidget *table = ui->capture_table;
    int row = table->rowCount();
    table->insertRow(row);
    for (int col = 0; col < table->columnCount(); col++)
    {
        QTableWidgetItem *item = new QTableWidgetItem;
        if (col == 0)
        {
            auto timestamp = static_cast<std::chrono::duration<double>>(recording_start - sc.now());
            item->setText(tr("%1").arg(timestamp.count()));
        }
        else
        {
            item->setText(tr("item %1").arg(col));
        }
        table->setItem(row, col, item);
    }
}
