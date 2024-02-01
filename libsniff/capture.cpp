#include "capture.h"

Capture::Capture(std::vector<char> buffer): internal_buffer(std::move(buffer)), data(internal_buffer.data()){};

Capture::Capture(size_t buffer_size) {
  internal_buffer = std::vector<char>(buffer_size);
  data = internal_buffer.data();
};

Capture::Capture(Capture &&other): internal_buffer(std::move(other.internal_buffer)), data(internal_buffer.data()){};

Capture::~Capture() {
  data = nullptr;
};

EthernetFrame::EthernetFrame(std::vector<char> buffer): Capture(std::move(buffer)) {
	ethernet_header = (ether_header_t *)internal_buffer.data();
	ethernet_data = (char*)ethernet_header + sizeof(ether_header_t);
};

EthernetFrame::EthernetFrame(size_t buffer_size)
    : Capture(buffer_size), ethernet_header(nullptr), ethernet_data(nullptr){};

EthernetFrame::EthernetFrame(EthernetFrame &&other): Capture(std::move(other.internal_buffer)) {
	ethernet_header = (ether_header_t *)internal_buffer.data();
	ethernet_data = (char*)ethernet_header + sizeof(ether_header_t);
};

EthernetFrame::EthernetFrame(Capture &capture): Capture(std::move(capture)) {
	ethernet_header = (ether_header_t *)internal_buffer.data();
	ethernet_data = (char*)ethernet_header + sizeof(ether_header_t);
};

IPPacket::IPPacket(std::vector<char> buffer): EthernetFrame(std::move(buffer)){
	ip_header = (struct ip *)ethernet_data;
	ip_data = (char*)ip_header + ip_header->ip_hl;
};

IPPacket::IPPacket(size_t buffer_size)
    : EthernetFrame(buffer_size), ip_header(nullptr), ip_data(nullptr){};

IPPacket::IPPacket(EthernetFrame &frame): EthernetFrame(std::move(frame)){
	ip_header = (struct ip *)ethernet_data;
	ip_data = (char*)ip_header + ip_header->ip_hl;
};

IPPacket::IPPacket(IPPacket &&other): EthernetFrame(std::move(other.internal_buffer)) {
	ip_header = (struct ip *)ethernet_data;
	ip_data = (char*)ip_header + ip_header->ip_hl;
};
