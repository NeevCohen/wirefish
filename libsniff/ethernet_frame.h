#include <netinet/if_ether.h>

#include "capture.h"

#pragma once

struct EthernetFrame {
public:
  const Capture& capture;
  ether_header_t *ethernet_header;
  char *ethernet_data;
  NetworkProtocol network_protocol;

public:
  EthernetFrame(Capture& capture);
};
