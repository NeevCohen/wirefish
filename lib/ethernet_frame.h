#include <netinet/if_ether.h>

#include "capture.h"

#pragma once

constexpr size_t mac_address_length = 6;
std::string parse_mac_address(const std::vector<uint8_t>& mac); // mac should be in network order
std::string parse_mac_address(const u_char mac[ETHER_ADDR_LEN]);

struct EthernetFrame {
public:
  const Capture& capture;
  ether_header_t *ethernet_header;
  char *ethernet_data;
  NetworkProtocol network_protocol;

public:
  EthernetFrame(Capture& capture);
};
