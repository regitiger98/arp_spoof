#pragma once

#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netdb.h>

#define ETHERTYPE_ARP	0x0806
#define HWTYPE_ETHER	0x0001
#define PROTOTYPE_IP	0x0800
#define ADDR_LEN_MAC	0x06
#define ADDR_LEN_IP		0x04
#define ARP_REQUEST		0x0001
#define ARP_REPLY		0x0002
#define PACKET_SIZE		42


struct ether_header {
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t ether_type;
};

struct arp_header {
	uint16_t hw_type;
	uint16_t proto_type;
	uint8_t hw_addr_len;
	uint8_t proto_addr_len;
	uint16_t op;
	uint8_t send_mac[6];
	uint8_t send_ip[4];
	uint8_t tar_mac[6];
	uint8_t tar_ip[4];
};

void get_my_mac(uint8_t *addr);

void get_my_ip(uint8_t *addr, char *interface);

void make_arp(u_char *packet, uint8_t *src_mac, uint8_t *dst_mac, uint16_t op,
			  uint8_t *send_mac, uint8_t *send_ip, uint8_t *tar_mac, uint8_t *tar_ip);

bool get_sender_mac(const u_char *packet, uint8_t *send_mac, uint8_t *send_ip);


