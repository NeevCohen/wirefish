#include <memory>
#include <string>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#pragma once

struct SnifferOptions {
	std::string bpf_device;
	std::string interface_name;
	u_int buffer_length;
};

struct Packet {
	std::unique_ptr<char[]> data;
};

struct EthernetFrame {
	ether_header_t *header;
	char *data;
};

struct IPPacket {
	struct ip *header;
	char *data;
};

struct Sniffer {

private:
	SnifferOptions options;
	int bpf_fd;
	std::unique_ptr<char[]> read_buffer;
	size_t last_read_length;
	size_t read_bytes_consumed;

private:
	static int get_available_bpf_device();

public:
	Sniffer(SnifferOptions options);
	Packet read_next_packet();
	EthernetFrame read_next_ethernet_frame();
	IPPacket read_next_ip_packet();
	void attach_bpf();
	~Sniffer();
};


