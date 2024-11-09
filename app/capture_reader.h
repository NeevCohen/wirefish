#include <QObject>

#include "libsniff.h"

#pragma once

class CaptureReader : public QObject
{
    Q_OBJECT
public:
    explicit CaptureReader(const SnifferOptions &sniffer_options, QObject *parent = nullptr);

signals:
    void new_capture(const EthernetFrame &ethernet_frame);
    void start_capture_failed(const std::string &error_message);

public slots:
    void start_capturing();
    void stop_capturing();

private:
    Sniffer m_sniffer;
    std::atomic_bool m_stop_capturing = false;
};