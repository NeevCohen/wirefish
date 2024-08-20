#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <unistd.h>
#include <vector>

#include "arg_parse.h"
#include "capture.h"

std::vector<NetworkProtocol> parse_network_protocols(const char *args);
std::vector<TransportProtocol> parse_transport_protocols(const char *args);

SniffingOptions parse_args(int argc, char *const *argv) {
  std::string interface_name;
  ssize_t count = 0;
  std::vector<NetworkProtocol> network_protos;
  std::vector<TransportProtocol> transport_protos;

  int c;

  while ((c = getopt(argc, argv, "i:c:n:t:")) != -1) {
    switch (c) {
      case 'i':
        interface_name.assign(optarg);
        break;
      case 'c':
        if (sscanf(optarg, "%zu", &count) == 0) {
          throw std::invalid_argument("Option -c requires a valid positive number");
        }
        break;
      case 'n':
        network_protos = parse_network_protocols(optarg);
        break;
      case 't':
        transport_protos = parse_transport_protocols(optarg);
        break;
      case '?':
        if (optopt == 'n' || optopt == 't' || optopt == 'c' || optopt == 'i') {
          throw std::invalid_argument(std::string("Option -") + char(optopt) + " requires an argument");
        }
        else if (isprint (optopt)) {
          throw std::invalid_argument(std::string("Unknown option -") + char(optopt));
        }
        else {
          throw std::invalid_argument(std::string("Unknown option character ") + std::to_string(optopt));
        }
        break;
    }
  }

  if (interface_name.empty()) {
    throw std::invalid_argument("Must supply interface name");
  }

  return SniffingOptions (std::move(interface_name),
                          count, 
                          std::move(network_protos),
                          std::move(transport_protos));
}

std::vector<NetworkProtocol> parse_network_protocols(const char *arg) {
  std::string arg_str(arg);
  std::vector<NetworkProtocol> network_opts;
  size_t next = 0, last = 0;
  std::string delim = ",";
    

  while ((next = arg_str.find(delim, last)) != std::string::npos)  {
    std::string proto = arg_str.substr(last, next-last); 
    if (proto == "ipv4") {
      network_opts.push_back(NetworkProtocol::IPv4);
    } else if (proto == "ipv6") {
      network_opts.push_back(NetworkProtocol::IPv6);
    } else if (proto == "arp") {
      network_opts.push_back(NetworkProtocol::ARP);
    }
    last = next + 1;
  }

  return network_opts;
}

std::vector<TransportProtocol> parse_transport_protocols(const char *arg) {
  std::string arg_str(arg);
  std::vector<TransportProtocol> transport_protos;
  size_t next = 0, last = 0;
  char delim = ',';
    

  while ((next = arg_str.find(delim, last)) != std::string::npos)  {
    std::string proto = arg_str.substr(last, next-last); 
    if (proto == "tcp") {
      transport_protos.push_back(TransportProtocol::TCP);
    } else if (proto == "udp") {
      transport_protos.push_back(TransportProtocol::UDP);
    }   
    last = next + 1;
  }

  return transport_protos;
}
