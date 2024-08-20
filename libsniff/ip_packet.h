#include <netinet/ip.h>
#include <vector>

#include "capture.h"
#include "ethernet_frame.h"

#pragma once

std::string parse_ip_address(const std::vector<uint8_t>& ip);

struct IPPacket {
public:
  const EthernetFrame& ethernet;
  struct ip *ip_header;
  char *ip_data;
  std::vector<uint8_t> src_ip;
  std::vector<uint8_t> dst_ip;
  std::string src_ip_str;
  std::string dst_ip_str;
  TransportProtocol transport_protocol;

public:
  IPPacket(EthernetFrame& ethernet);
};
