#include <string>
#include <QApplication>
#include <QHBoxLayout>
#include <QPushButton>
#include <QMainWindow>
#include <QLabel>
#include <QWidget>

class MainWindow : public QMainWindow
{
public:
    explicit MainWindow(QWidget *parent = nullptr)
    {
        m_layout = new QHBoxLayout;
        m_label = new QLabel(std::to_string(m_pressed).c_str(), this);
        m_increase_button = new QPushButton("+1", this);
        m_decrease_button = new QPushButton("-1", this);
        connect(m_increase_button, &QPushButton::released, this, &MainWindow::handle_increase);
        connect(m_decrease_button, &QPushButton::released, this, &MainWindow::handle_decrease);

        m_layout->addWidget(m_label);
        m_layout->addWidget(m_increase_button);
        m_layout->addWidget(m_decrease_button);

        QWidget *window = new QWidget();
        window->setLayout(m_layout);

        // Set QWidget as the central layout of the main window
        setCentralWidget(window);
    }
private slots:
    void handle_increase()
    {
        m_pressed++;
        m_label->setText(std::to_string(m_pressed).c_str());
    }

    void handle_decrease()
    {
        if (m_pressed == 0)
        {
            return;
        }
        m_pressed--;
        m_label->setText(std::to_string(m_pressed).c_str());
    }

private:
    size_t m_pressed = 0;

private:
    QWidget *m_window;
    QHBoxLayout *m_layout;
    QLabel *m_label;
    QPushButton *m_increase_button;
    QPushButton *m_decrease_button;
};

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    MainWindow mainWindow;
    mainWindow.show();
    return app.exec();
}