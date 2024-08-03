#include "capture.h"
#include "libsniff.h"
#include <vector>

struct SniffingOptions {
public:
  std::string interface_name;
  ssize_t packet_count;
  std::vector<NetworkProtocol> network_protocols;
  std::vector<TransportProtocol> transport_protocols;

  SniffingOptions() = default;
  SniffingOptions(std::string&& interface_name, ssize_t packet_count, std::vector<NetworkProtocol>&& network_protocol, std::vector<TransportProtocol>&& transport_protocols);
};
