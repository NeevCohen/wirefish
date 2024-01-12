#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <fcntl.h>


int main() {
  int bpf_fd;
  u_int buffer_length, immediate_mode = 1;
	struct ifreq interface_request = {
		.ifr_name = "en0"
	}, interface_response;
	char *pkt_buffer;
	struct bpf_hdr *bpf_header;
	struct ether_header *ethernet_header;

  if (getuid()) {
    std::cerr << "Please run as root user\n";
    goto out;
  }

  if ((bpf_fd = open("/dev/bpf0", O_RDONLY)) < 0) {
    std::perror("open");
    goto out;
  }

  if (ioctl(bpf_fd, BIOCGBLEN, &buffer_length) < 0) {
    std::perror("ioctl(BIOCGBLEN)");
		goto out_bpf;
  }

	if (ioctl(bpf_fd, BIOCSETIF, &interface_request) < 0) {
		std::perror("ioctl(BIOCSETIF)");
		goto out_bpf;
	}

	if (ioctl(bpf_fd, BIOCGETIF, &interface_response) < 0) {
		std::perror("ioctl(BIOCSETIF)");
		goto out_bpf;
	}

	if (ioctl(bpf_fd, BIOCIMMEDIATE, &immediate_mode) < 0) {
		std::perror("ioctl(BIOCIMMEDIATE)");
		goto out_bpf;
	}

	if (ioctl(bpf_fd, BIOCPROMISC, nullptr) < 0) {
		std::perror("ioctl(BIOCIMMEDIATE)");
		goto out_bpf;
	}

	std::printf("The buffer size is %u\n", buffer_length);
	std::printf("The connected interface is %s\n", interface_response.ifr_name);

	pkt_buffer = new char[buffer_length];

	while(true) {
		std::memset(pkt_buffer, 0, buffer_length);
		if (read(bpf_fd, pkt_buffer, buffer_length) < 0) {
			perror("read");
			goto out_pkt_buff;
		}
		bpf_header = (struct bpf_hdr *)pkt_buffer;
		ethernet_header = (struct ether_header *)(pkt_buffer + bpf_header->bh_hdrlen);
		std::printf("Ethernet source host %x:%x:%x:%x:%x:%x\n", 
					 ethernet_header->ether_shost[0], 
					 ethernet_header->ether_shost[1], 
					 ethernet_header->ether_shost[2], 
					 ethernet_header->ether_shost[3], 
					 ethernet_header->ether_shost[4], 
					 ethernet_header->ether_shost[5]
		);
		std::printf("Ethernet destination host %x:%x:%x:%x:%x:%x\n", 
					 ethernet_header->ether_dhost[0], 
					 ethernet_header->ether_dhost[1], 
					 ethernet_header->ether_dhost[2], 
					 ethernet_header->ether_dhost[3], 
					 ethernet_header->ether_dhost[4], 
					 ethernet_header->ether_dhost[5]
		);
	}

	return EXIT_SUCCESS;

out_pkt_buff:
	delete pkt_buffer;
out_bpf:
	close(bpf_fd);
out:
	return EXIT_FAILURE;
}
