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
    void create_actions();

private:
    QWidget *m_window;
    QAction *m_action;

    Ui::MainWindow *ui;
};