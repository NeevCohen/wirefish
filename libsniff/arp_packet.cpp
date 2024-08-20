#include <arpa/inet.h>
#include <sstream>
#include <sys/types.h>
#include <iostream>

#include "capture.h"
#include "arp_packet.h"
#include "ethernet_frame.h"


ARPPacket::ARPPacket(EthernetFrame& ethernet_frame): ethernet_frame(ethernet_frame) {
  arp_header = (struct arphdr*)ethernet_frame.ethernet_data;

  uint8_t *sender_hardware_address_ptr = (uint8_t*)arp_header + sender_hardware_address_offset;
  uint8_t *sender_protocol_address_ptr = sender_hardware_address_ptr + arp_header->ar_hln;
  uint8_t *target_hardware_address_ptr = sender_protocol_address_ptr + arp_header->ar_pln;
  uint8_t *target_protocol_address_ptr = target_hardware_address_ptr + arp_header->ar_hln;

  sender_hardware_address.assign(sender_hardware_address_ptr, sender_hardware_address_ptr + arp_header->ar_hln);
  sender_protocol_address.assign(sender_protocol_address_ptr, sender_protocol_address_ptr + arp_header->ar_pln);
  target_hardware_address.assign(target_hardware_address_ptr, target_hardware_address_ptr + arp_header->ar_hln);
  target_protocol_address.assign(target_protocol_address_ptr, target_protocol_address_ptr + arp_header->ar_pln);

  uint16_t op = ntohs(arp_header->ar_op);
  if (op == ARPOP_REQUEST) {
    operation = ArpOperation::Request;
  } else if(op == ARPOP_REPLY) {
    operation = ArpOperation::Reply;
  } else if(op == ARPOP_REVREQUEST) {
    operation = ArpOperation::ReverseRequest;
  } else if(op == ARPOP_REVREPLY) {
    operation = ArpOperation::ReverseReply;
  } else if(op == ARPOP_INVREQUEST) {
    operation = ArpOperation::InverseRequest;
  } else if(op == ARPOP_INVREPLY) {
    operation = ArpOperation::InverseReply;
  }
}

