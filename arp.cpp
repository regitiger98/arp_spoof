#include "arp.h"

void get_my_mac(uint8_t *addr){
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { 
		printf("error\n");
		exit(0);
	}

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { 
		printf("error\n");
		exit(0);
	}

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) {
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { 
			printf("error\n");
		 }
    }
	
    if (success) memcpy(addr, ifr.ifr_hwaddr.sa_data, 6);	
}

void get_my_ip(uint8_t *addr, char *interface) {
	struct ifreq ifr;
	struct sockaddr_in * sin;
	uint32_t s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error0\n");
		close(s);
		exit(1);
  	} 
	else {
		sin = (struct sockaddr_in *)&ifr.ifr_addr;
    	memcpy(addr, (void*)&sin->sin_addr, sizeof(sin->sin_addr));
		close(s);
  	}
}

void make_arp(u_char *packet, uint8_t *src_mac, uint8_t *dst_mac, uint16_t op,
			  uint8_t *send_mac, uint8_t *send_ip, uint8_t *tar_mac, uint8_t *tar_ip) {
	struct ether_header ethhdr;
	struct arp_header arphdr;

	memcpy(ethhdr.dst_mac, dst_mac, 6);
	memcpy(ethhdr.src_mac, src_mac, 6);
	ethhdr.ether_type = htons(ETHERTYPE_ARP);

	arphdr.hw_type = htons(HWTYPE_ETHER);
	arphdr.proto_type = htons(PROTOTYPE_IP);
	arphdr.hw_addr_len = ADDR_LEN_MAC;
	arphdr.proto_addr_len = ADDR_LEN_IP;
	arphdr.op = htons(op);
	memcpy(arphdr.send_mac, send_mac, 6);
	memcpy(arphdr.send_ip, send_ip, 4);
	memcpy(arphdr.tar_mac, tar_mac, 6);
	memcpy(arphdr.tar_ip, tar_ip, 4);

	memcpy(packet, (u_char*)&ethhdr, sizeof(ethhdr));
	memcpy(packet + sizeof(ethhdr), (u_char*)&arphdr, sizeof(arphdr));
}

bool get_sender_mac(const u_char *packet, uint8_t *send_mac, uint8_t *send_ip) {
	struct ether_header *ethhdr = (ether_header*)packet;
	struct arp_header *arphdr = (arp_header*)(packet + sizeof(ether_header));

	if((ntohs(ethhdr->ether_type) == ETHERTYPE_ARP) && (ntohs(arphdr->op) == ARP_REPLY) && (!memcmp(arphdr->send_ip, send_ip, 4))) {
		memcpy(send_mac, arphdr->send_mac, 6);
		return true;
	}	
	return false;
}


