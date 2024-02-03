#include "capture.h"

#include <arpa/inet.h>
#include <netinet/tcp.h>

Capture::Capture(std::vector<char> &&buffer): internal_buffer(std::move(buffer)), data(internal_buffer.data()){};

Capture::Capture(size_t buffer_size) {
  internal_buffer = std::vector<char>(buffer_size);
  data = internal_buffer.data();
};

Capture::Capture(Capture &&other): internal_buffer(std::move(other.internal_buffer)), data(internal_buffer.data()){};

Capture::~Capture() {
  data = nullptr;
};

EthernetFrame::EthernetFrame(std::vector<char> &&buffer): Capture(std::move(buffer)) {
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

IPPacket::IPPacket(size_t buffer_size)
    : EthernetFrame(buffer_size), ip_header(nullptr), ip_data(nullptr){};

IPPacket::IPPacket(std::vector<char> &&buffer): EthernetFrame(std::move(buffer)){
  ip_header = (struct ip *)ethernet_data;
  ip_data = (char*)ip_header + (ip_header->ip_hl * 4); // ip_hl specifies the length of the header in 32 bit words
  char src_addr_str[INET_ADDRSTRLEN];
  char dst_addr_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip_header->ip_src.s_addr), src_addr_str, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip_header->ip_dst.s_addr), dst_addr_str, INET_ADDRSTRLEN);
  src_ip_str = std::string(src_addr_str);
  dst_ip_str = std::string(dst_addr_str);
};

IPPacket::IPPacket(EthernetFrame &frame): EthernetFrame(std::move(frame)) {
  ip_header = (struct ip *)ethernet_data;
  ip_data = (char*)ip_header + (ip_header->ip_hl * 4); // ip_hl specifies the length of the header in 32 bit words
  char src_addr_str[INET_ADDRSTRLEN];
  char dst_addr_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip_header->ip_src.s_addr), src_addr_str, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip_header->ip_dst.s_addr), dst_addr_str, INET_ADDRSTRLEN);
  src_ip_str = std::string(src_addr_str);
  dst_ip_str = std::string(dst_addr_str);
};

IPPacket::IPPacket(IPPacket &&other): EthernetFrame(std::move(other.internal_buffer)) {
  ip_header = (struct ip *)ethernet_data;
  ip_data = (char*)ip_header + (ip_header->ip_hl * 4); // ip_hl specifies the length of the header in 32 bit words
  src_ip_str = other.src_ip_str;
  dst_ip_str = other.dst_ip_str;
};

TCPFrame::TCPFrame(std::vector<char> &&buffer): IPPacket(std::move(buffer)) {
  tcp_header = (struct tcphdr*)ip_data;
  tcp_payload = (char*)tcp_header + tcp_header->th_off;
};

TCPFrame::TCPFrame(size_t buffer_size): IPPacket(buffer_size), tcp_header(nullptr), tcp_payload(nullptr){};

TCPFrame::TCPFrame(IPPacket &packet): IPPacket(std::move(packet)) {
  tcp_header = (struct tcphdr*)ip_data;
  tcp_sport = ntohs(tcp_header->th_sport);
  tcp_dport = ntohs(tcp_header->th_dport);
  tcp_payload = (char*)tcp_header + tcp_header->th_off;
};

TCPFrame::TCPFrame(TCPFrame &&other): IPPacket(std::move(other.internal_buffer)) {
  tcp_header = (struct tcphdr*)ip_data;
  tcp_sport = other.tcp_sport;
  tcp_dport = other.tcp_dport;
  tcp_payload = (char*)tcp_header + tcp_header->th_off;
};

UDPDatagram::UDPDatagram(std::vector<char> &&buffer): IPPacket(std::move(buffer)) {
  u_short* udp_header = (u_short*)ip_data;
  udp_sport = ntohs(udp_header[0]);
  udp_dport = ntohs(udp_header[1]);
  udp_length = ntohs(udp_header[2]);
  udp_payload = ip_data + 8;
};

UDPDatagram::UDPDatagram(size_t buffer_size): IPPacket(buffer_size), udp_sport(0), udp_dport(0), udp_length(0), udp_payload(nullptr) {};

UDPDatagram::UDPDatagram(IPPacket &packet): IPPacket(std::move(packet)) {
  u_short* udp_header = (u_short*)ip_data;
  udp_sport = ntohs(udp_header[0]);
  udp_dport = ntohs(udp_header[1]);
  udp_length = ntohs(udp_header[2]);
  udp_payload = ip_data + 8;
};

UDPDatagram::UDPDatagram(UDPDatagram &&other): IPPacket(std::move(other.internal_buffer)) {
  udp_sport = other.udp_sport;
  udp_dport = other.udp_dport;
  udp_length = other.udp_length;
  udp_payload = ip_data + 8;
};
