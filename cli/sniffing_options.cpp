#include "sniffing_options.h"

SniffingOptions::SniffingOptions(std::string&& interface_name,
                                 ssize_t packet_count,
                                 std::vector<NetworkProtocol>&& network_protocols,
                                 std::vector<TransportProtocol>&& transport_protocols):
                                  interface_name(std::move(interface_name)),
                                  packet_count(packet_count),
                                  network_protocols(std::move(network_protocols)),
                                  transport_protocols(std::move(transport_protocols)) {};
                                  
