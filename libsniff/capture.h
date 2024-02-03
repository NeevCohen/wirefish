#include <memory>
#include <vector>
#include <string>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#pragma once

struct Capture {
protected:
  std::vector<char> internal_buffer;

public:
  const char *data;

public:
  Capture(std::vector<char> &&buffer);
  Capture(size_t buffer_size);
  Capture(Capture &&other);
  ~Capture();
};

struct EthernetFrame: public Capture {
public:
  const ether_header_t *ethernet_header;
  const char *ethernet_data;
  EthernetFrame(std::vector<char> &&buffer);
  EthernetFrame(size_t buffer_size);
  EthernetFrame(Capture &capture);
  EthernetFrame(EthernetFrame &&other);
};

struct IPPacket: public EthernetFrame {
public:
  const struct ip *ip_header;
  const char *ip_data;
  std::string src_ip_str;
  std::string dst_ip_str;
  IPPacket(std::vector<char> &&buffer);
  IPPacket(size_t buffer_size);
  IPPacket(EthernetFrame &frame);
  IPPacket(IPPacket &&other);
};

struct TCPFrame: public IPPacket {
  public:
  const struct tcphdr *tcp_header;
  u_short tcp_sport;
  u_short tcp_dport;
  const char *tcp_payload;
  TCPFrame(std::vector<char> &&buffer);
  TCPFrame(size_t buffer_size);
  TCPFrame(IPPacket &packet);
  TCPFrame(TCPFrame &&other);
};

struct UDPDatagram: public IPPacket {
  public:
  u_short udp_sport;
  u_short udp_dport;
  u_short udp_length;
  const char *udp_payload;
  UDPDatagram(std::vector<char> &&buffer);
  UDPDatagram(size_t buffer_size);
  UDPDatagram(IPPacket &packet);
  UDPDatagram(UDPDatagram &&other);
};
