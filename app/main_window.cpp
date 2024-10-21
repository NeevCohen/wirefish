#include <string>

#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QAction>

#include "main_window.h"
#include "libsniff.h"

MainWindow::MainWindow() : ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    centralWidget()->layout()->setContentsMargins(0, 0, 0, 0);
    menuBar()->setNativeMenuBar(false);
    create_actions();
}

void MainWindow::create_actions()
{
    auto interfaces = get_interfaces_names();
    for (auto &interface : interfaces)
    {
        ui->menuStart_Capture->addAction(new QAction(QString::fromStdString(interface), this));
    }
}
