#include <string>

#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>

#include "main_window.h"

MainWindow::MainWindow() : ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    centralWidget()->layout()->setContentsMargins(0, 0, 0, 0);
    menuBar()->setNativeMenuBar(false);
}
