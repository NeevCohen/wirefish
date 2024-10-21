#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <sys/types.h>

#include "capture.h"
#include "ethernet_frame.h"

#pragma once

enum class ArpOperation {
  Request,         /* request to resolve address */
  Reply,           /* response to previous request */
  ReverseRequest,  /* request protocol address given hardware */
  ReverseReply,    /* response giving protocol address */
  InverseRequest,  /* request to identify peer */
  InverseReply     /* response identifying peer */
};

struct ARPPacket {
private:
  static constexpr size_t sender_hardware_address_offset = 8;
public:
  const EthernetFrame& ethernet_frame;
  struct arphdr *arp_header;
  std::vector<uint8_t> sender_hardware_address;       /* sender hardware address */
  std::vector<uint8_t> sender_protocol_address;       /* sender protocol address */
  std::vector<uint8_t> target_hardware_address;       /* target hardware address */
  std::vector<uint8_t> target_protocol_address;       /* target protocol address */
  ArpOperation operation;

public:
  ARPPacket(EthernetFrame& ethernet_frame);
};

