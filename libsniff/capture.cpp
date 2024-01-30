#include "capture.h"

Capture::Capture(std::unique_ptr<char[]> buffer, size_t buffer_size)
    : internal_buffer(std::move(buffer)), data(internal_buffer.get()),
      buffer_size(buffer_size){};

Capture::Capture(size_t buffer_size) : buffer_size(buffer_size) {
  internal_buffer = std::make_unique<char[]>(buffer_size);
  data = internal_buffer.get();
};

Capture::Capture(Capture &&other)
    : internal_buffer(std::move(other.internal_buffer)),
      data(internal_buffer.get()), buffer_size(other.buffer_size){};

Capture::~Capture() {
  data = nullptr;
  buffer_size = 0;
};

EthernetFrame::EthernetFrame(std::unique_ptr<char[]> buffer, size_t buffer_size)
    : Capture(std::move(buffer), buffer_size),
      ethernet_header((ether_header_t *)internal_buffer.get()),
      ethernet_data(internal_buffer.get() + sizeof(ether_header_t)){};

EthernetFrame::EthernetFrame(size_t buffer_size)
    : Capture(buffer_size), ethernet_header(nullptr), ethernet_data(nullptr){};

EthernetFrame::EthernetFrame(EthernetFrame &&other)
    : Capture(std::move(other.internal_buffer), other.buffer_size),
      ethernet_header((ether_header_t *)internal_buffer.get()),
      ethernet_data(internal_buffer.get() + sizeof(ether_header_t)){};

EthernetFrame::EthernetFrame(Capture &capture)
    : Capture(std::move(capture)),
      ethernet_header((ether_header_t *)internal_buffer.get()),
      ethernet_data(internal_buffer.get() + sizeof(ether_header_t)){};

IPPacket::IPPacket(std::unique_ptr<char[]> buffer, size_t buffer_size)
    : EthernetFrame(std::move(buffer), buffer_size),
      ip_header((struct ip *)ethernet_data),
      ip_data(internal_buffer.get() + ip_header->ip_hl){};

IPPacket::IPPacket(size_t buffer_size)
    : EthernetFrame(buffer_size), ip_header(nullptr), ip_data(nullptr){};

IPPacket::IPPacket(EthernetFrame &frame)
    : EthernetFrame(std::move(frame)), ip_header((struct ip *)ethernet_data),
      ip_data(internal_buffer.get() + ip_header->ip_hl){};

IPPacket::IPPacket(IPPacket &&other)
    : EthernetFrame(std::move(other.internal_buffer), other.buffer_size),
      ip_header((struct ip *)ethernet_data),
      ip_data(internal_buffer.get() + ip_header->ip_hl){};
