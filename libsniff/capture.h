#include <memory>
#include <vector>
#include <string>

#pragma once

enum class NetworkProtocol {
  IPv4,
  IPv6,
  ARP,
  UNKNOWN,
};

enum class TransportProtocol {
  TCP,
  UDP,
  UNKNOWN,
};

struct Capture {
public:
  const std::vector<char> buffer;

public:
  Capture(std::vector<char> &&buffer);
  Capture(size_t buffer_size);
};

