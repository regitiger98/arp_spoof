#pragma once

#include <netdb.h>
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <netinet/in.h>
#include <arpa/inet.h>

#include <vector>
#include <map>
using namespace std;

#define ETHERTYPE_ARP	0x0806
#define ETHERTYPE_IP	0x0800
#define HWTYPE_ETHER	0x0001
#define PROTOTYPE_IP	0x0800
#define ADDR_LEN_MAC	0x06
#define ADDR_LEN_IP	0x04
#define ARP_REQUEST	0x0001
#define ARP_REPLY	0x0002
#define ARP_PACKET_SIZE	42
#define DST_IP_POS	30

extern uint8_t my_mac[6], my_ip[4], mac_ff[6], mac_00[6];
extern map<uint32_t, uint8_t*> ip2mac;
extern pcap_t *handle;

struct ether_header 
{
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t ether_type;
};

struct arp_header 
{
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

struct ip_header 
{

};

struct session 
{
	uint32_t send_ip;
	uint32_t tar_ip;
};

void get_my_mac(uint8_t *addr);

void get_my_ip(uint8_t *addr, char *interface);

void make_arp(u_char *packet, uint8_t *src_mac, uint8_t *dst_mac, uint16_t op,
			  uint8_t *send_mac, uint8_t *send_ip, uint8_t *tar_mac, uint8_t *tar_ip);

void get_mac_addr(uint8_t *ip_addr);

void arp_infection(session s);

void pkt_relay(const u_char *pkt, uint32_t len, session s);
