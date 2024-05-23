#include <netinet/ip.h>

#include "capture.h"
#include "ethernet_frame.h"

#pragma once

struct IPPacket {
public:
  const EthernetFrame ethernet;
  struct ip *ip_header;
  char *ip_data;
  std::string src_ip_str;
  std::string dst_ip_str;
  TransportProtocol transport_protocol;

public:
  IPPacket(EthernetFrame& ethernet);
};
