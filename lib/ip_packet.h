#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <vector>

#include "capture.h"
#include "ethernet_frame.h"

#pragma once


enum class IPVersion {
  V4,
  V6
};


std::string parse_ip_address(const std::vector<uint8_t>& ip);


struct IPPacket {
private:
  const EthernetFrame& ethernet;
  struct ip *ip_header = nullptr;
  struct ip6_hdr *ip6_header = nullptr;
  static constexpr size_t ip6_header_len = 40;

private:
  void init_v4();
  void init_v6();

public:
  IPVersion version;
  char *ip_data = nullptr;
  std::vector<uint8_t> src_ip;
  std::vector<uint8_t> dst_ip;
  std::string src_ip_str;
  std::string dst_ip_str;
  TransportProtocol transport_protocol;

public:
  IPPacket(EthernetFrame& ethernet);
};
