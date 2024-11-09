#include <memory>
#include <string>
#include <mutex>
#include <optional>
#include <chrono>

#include "capture.h"

#pragma once

struct SnifferOptions
{
  std::string bpf_device;
  std::string interface_name;
  u_int buffer_length;
};

struct Sniffer
{
private:
  SnifferOptions m_options;
  int m_bpf_fd;
  std::unique_ptr<char[]> m_read_buffer;
  size_t m_last_read_length;
  size_t m_read_bytes_consumed;
  std::mutex m_read_lock;

private:
  static int get_available_bpf_device();
  void fill_buffer(std::atomic_bool &timeout);
  static int set_non_blocking(int fd);

public:
  Sniffer(SnifferOptions options);
  std::optional<Capture> read_next_capture(std::atomic_bool &timeout);
  void attach_bpf();
  ~Sniffer();
};
