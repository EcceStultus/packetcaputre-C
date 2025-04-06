#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

int linklayer_header_length = 0;
void packet_handler(u_char *arg, const struct pcap_pkthdr *packerthdr, const u_char *packetptr);

int main () {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *interfaces;
	char *chosen_int;
	pcap_t *handle;
	struct pcap_pkthdr header;
	const u_char *packet;
	pcap_dumper_t *pcap_dumper_handle;

	if (pcap_findalldevs(&interfaces, errbuf) == -1) {
	       printf("Error: %s\n", errbuf);
	       return 2;
	}

	printf("Available interfaces:\n");
	
	int index = 1;
	for (pcap_if_t *current_int = interfaces; current_int != NULL; current_int = current_int->next) {
		printf("%d.	%s\n", index,  current_int->name);
		++index;
	}
	
	int choice;

	printf("Select an interface to proceed\n");
	scanf("%d", &choice);
	
	if (choice < 1 || choice > index) {
		printf("Error: Device does not exist");
		pcap_freealldevs(interfaces);
	}

	index = 1;
	for (pcap_if_t *current_int = interfaces; current_int != NULL;current_int =  current_int->next) {
		if (index == choice) {
			chosen_int = current_int->name;
		}
			++index;
	}
	
	printf("Interface %s selected, proceeding with capture...\n", chosen_int);
	
	handle = pcap_open_live(chosen_int, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		printf("Error: %s\n", errbuf);
		return 2;
		pcap_freealldevs(interfaces);
		pcap_close(handle);
	}

	int linklayer_header_type = pcap_datalink(handle);
        switch (linklayer_header_type) {
                case DLT_NULL:
                        linklayer_header_length = 4;
                        break;
                case DLT_EN10MB:
                        linklayer_header_length = 14;
                        break;
                default:
                        linklayer_header_length = 0;

        }

	pcap_dumper_t *pcap_dump = pcap_dump_open(handle, "capture.pcap");
	if (pcap_dump == NULL) {
		printf("Error: %s", errbuf);
		pcap_freealldevs(interfaces);
		pcap_close(handle);
		return 2;
	}

	if (pcap_loop(handle, -1, packet_handler, (u_char *)pcap_dump) < 0) {
		printf("Error: loop failure\n");
		pcap_close(handle);
		pcap_freealldevs(interfaces);
		pcap_dump_close(pcap_dump);
		return 2;
	}
	
	pcap_freealldevs(interfaces);
	pcap_close(handle);
	
	
	return 0;

}

void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr) {
	pcap_dumper_t *pcap_dump_handle = (pcap_dumper_t *)user;
	packetptr += linklayer_header_length;
	struct ip *ip_hdr = (struct ip *) packetptr;
	char sourceip[INET_ADDRSTRLEN];
	char dstip[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &(ip_hdr->ip_src), sourceip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip_hdr->ip_dst), dstip, INET_ADDRSTRLEN);
	printf("| Src:%s | Dst:%s | Len:%d | Proto:%d |\n", sourceip, dstip, ntohs(ip_hdr->ip_len), ip_hdr->ip_p);
	pcap_dump((u_char *)pcap_dump_handle, packethdr, packetptr);
	pcap_dump_flush(pcap_dump_handle);
};	
