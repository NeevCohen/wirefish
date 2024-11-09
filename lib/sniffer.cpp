#include <fcntl.h>
#include <memory>
#include <net/bpf.h>
#include <net/if.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <thread>

#include "sniffer.h"

Sniffer::Sniffer(SnifferOptions options) : m_options(options), m_last_read_length(0), m_read_bytes_consumed(0)
{
  if (options.buffer_length > 0)
  {
    m_read_buffer = std::make_unique<char[]>(options.buffer_length);
  }
  else
  {
    m_read_buffer = nullptr;
  }
};

int Sniffer::get_available_bpf_device()
{
  u_int max_bpf_devices;
  size_t len = sizeof(max_bpf_devices);
  int fd;

  if (sysctlbyname("debug.bpf_maxdevices", &max_bpf_devices, &len, NULL, 0) < 0)
  {
    throw std::runtime_error("Failed to get maximum number of bpf devices");
  }

  std::unique_ptr<char[]> bpf_device_name = std::make_unique<char[]>(11);
  for (u_int i = 0; i < max_bpf_devices; ++i)
  {
    std::snprintf(bpf_device_name.get(), 11, "/dev/bpf%d", i);
    fd = open(bpf_device_name.get(), O_RDONLY);
    if (fd)
      return fd;
  }

  return -1;
}

int Sniffer::set_non_blocking(int fd)
{
  int flags = fcntl(fd, F_GETFL, 0);
  if (-1 == flags)
    return -1;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void Sniffer::attach_bpf()
{
  struct ifreq interface_request;
  std::strcpy((char *)&interface_request.ifr_name,
              m_options.interface_name.c_str());
  int immediate_mode = 1;

  // open bpf device
  if (m_options.bpf_device == "")
  {
    m_bpf_fd = Sniffer::get_available_bpf_device();
  }
  else
  {
    m_bpf_fd = open(m_options.bpf_device.c_str(), O_RDONLY);
  }

  if (m_bpf_fd < 0)
  {
    std::perror("open");
    throw std::runtime_error("Failed to open bpf device");
  }

  // set/get buffer length
  if (m_options.buffer_length)
  {
    if (ioctl(m_bpf_fd, BIOCSBLEN, &m_options.buffer_length) < 0)
    {
      std::perror("ioctl(BIOCGBLEN)");
      throw std::runtime_error("Failed to set bpf buffer length");
    }
  }
  else
  {
    if (ioctl(m_bpf_fd, BIOCGBLEN, &m_options.buffer_length) < 0)
    {
      std::perror("ioctl(BIOCGBLEN)");
      throw std::runtime_error("Failed to get bpf buffer length");
    }
  }

  if (m_read_buffer == nullptr)
  {
    m_read_buffer = std::make_unique<char[]>(m_options.buffer_length);
  }

  if (ioctl(m_bpf_fd, BIOCSETIF, &interface_request) < 0)
  {
    std::perror("ioctl(BIOCSETIF)");
    throw std::runtime_error("Failed to attach bpf to interface '" + m_options.interface_name + "'");
  }

  if (ioctl(m_bpf_fd, BIOCIMMEDIATE, &immediate_mode) < 0)
  {
    std::perror("ioctl(BIOCIMMEDIATE)");
    throw std::runtime_error("Failed to enable immediate mode");
  }

  if (ioctl(m_bpf_fd, BIOCPROMISC, nullptr) < 0)
  {
    std::perror("ioctl(BIOCPROMISC)");
    throw std::runtime_error("Failed to set interface to promiscuous mode");
  }

  if (Sniffer::set_non_blocking(m_bpf_fd))
  {
    std::perror("fcntl");
    throw std::runtime_error("Failed to set bpf device to non-blocking");
  }
}

void Sniffer::fill_buffer(std::atomic_bool &stop)
{
  m_read_bytes_consumed = 0;
  ssize_t bytes_read = 0;
  std::chrono::duration<float> elapsed{0};
  std::chrono::duration<float> sleep_time{std::chrono::milliseconds(5)};
  while (!stop)
  {
    bytes_read = read(m_bpf_fd, m_read_buffer.get(), m_options.buffer_length);
    if (bytes_read > 0)
    {
      m_last_read_length = (size_t)bytes_read;
      return;
    }
    std::this_thread::sleep_for(sleep_time);
    elapsed += sleep_time;
  }
}

std::optional<Capture> Sniffer::read_next_capture(std::atomic_bool &stop)
{
  std::lock_guard<std::mutex> lock_guard(m_read_lock);
  if (m_read_bytes_consumed >= m_last_read_length)
  {
    fill_buffer(stop);
  }
  struct bpf_hdr *bpf_header = (struct bpf_hdr *)(m_read_buffer.get() + m_read_bytes_consumed);
  char *bpf_capture = (char *)bpf_header + bpf_header->bh_hdrlen;

  std::vector<char> raw_cap(bpf_header->bh_caplen);
  std::copy(bpf_capture, bpf_capture + bpf_header->bh_caplen, raw_cap.begin());
  Capture capture(std::move(raw_cap));
  m_read_bytes_consumed += BPF_WORDALIGN(bpf_header->bh_caplen + bpf_header->bh_hdrlen);
  return capture;
};

Sniffer::~Sniffer()
{
  if (m_bpf_fd > 0)
  {
    close(m_bpf_fd);
  }
}
