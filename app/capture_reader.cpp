#include <chrono>

#include <QCoreApplication>

#include "capture_reader.h"

CaptureReader::CaptureReader(const SnifferOptions &sniffer_options, QObject *parent) : QObject(parent), m_sniffer(sniffer_options) {};

void CaptureReader::start_capturing()
{
    try
    {
        m_stop_capturing = false;
        m_sniffer.attach_bpf();
        while (!m_stop_capturing)
        {
            auto capture = m_sniffer.read_next_capture(m_stop_capturing);
            if (capture.has_value())
            {
                emit new_capture(EthernetFrame(capture.value()));
            }
            QCoreApplication::processEvents();
        }
    }
    catch (const std::exception &e)
    {
        emit start_capture_failed(e.what());
    }
}

void CaptureReader::stop_capturing()
{
    m_stop_capturing = true;
}