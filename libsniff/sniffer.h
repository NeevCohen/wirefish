#include <memory>
#include <string>
#include <netinet/if_ether.h>

#pragma once

struct SnifferOptions {
	std::string bpf_device;
	std::string interface_name;
	u_int buffer_length;
};

struct Packet {
	std::unique_ptr<char[]> data;
};

struct Sniffer {

private:
	SnifferOptions options;
	int bpf_fd;
	std::unique_ptr<char[]> packet_buffer;

private:
	static int get_available_bpf_device();

public:
	Sniffer(SnifferOptions options);
	Packet read_next_packet();
	ether_header_t read_next_ethernet_frame();
	void attach_bpf();
	~Sniffer();
};


