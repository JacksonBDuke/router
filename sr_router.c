/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


/*--------------------------------------------------------------------
* Reply Definations
*----------------------------------------------------------------------*/

#define ICMP_IP_HDR_LEN_BYTE 20
#define ICMP_TYPE3_LEN 36

#define TTL 64
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
 *             unsigned int orig_len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
    unsigned int orig_len, struct sr_if *src_iface)
{
  /* Allocate space for packet */
  unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reply_pkt = (uint8_t *)malloc(reply_len);
  if (NULL == reply_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *orig_ethhdr = (sr_ethernet_hdr_t *)orig_pkt;
  sr_arp_hdr_t *orig_arphdr = 
      (sr_arp_hdr_t *)(orig_pkt + sizeof(sr_ethernet_hdr_t));

  sr_ethernet_hdr_t *reply_ethhdr = (sr_ethernet_hdr_t *)reply_pkt;
  sr_arp_hdr_t *reply_arphdr = 
      (sr_arp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memcpy(reply_ethhdr->ether_dhost, orig_ethhdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_ethhdr->ether_shost, src_iface->addr, ETHER_ADDR_LEN);
  reply_ethhdr->ether_type = orig_ethhdr->ether_type;

  /* Populate ARP header */
  memcpy(reply_arphdr, orig_arphdr, sizeof(sr_arp_hdr_t));
  reply_arphdr->ar_hrd = orig_arphdr->ar_hrd;
  reply_arphdr->ar_pro = orig_arphdr->ar_pro;
  reply_arphdr->ar_hln = orig_arphdr->ar_hln;
  reply_arphdr->ar_pln = orig_arphdr->ar_pln;
  reply_arphdr->ar_op = htons(arp_op_reply); 
  memcpy(reply_arphdr->ar_tha, orig_arphdr->ar_sha, ETHER_ADDR_LEN);
  reply_arphdr->ar_tip = orig_arphdr->ar_sip;
  memcpy(reply_arphdr->ar_sha, src_iface->addr, ETHER_ADDR_LEN);
  reply_arphdr->ar_sip = src_iface->ip;

  /* Send ARP reply */
  printf("Send ARP reply\n");
  print_hdrs(reply_pkt, reply_len);
  sr_send_packet(sr, reply_pkt, reply_len, src_iface->name);
  free(reply_pkt);
} /* -- sr_send_arpreply -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arprequest(struct sr_instance *sr, 
 *             struct sr_arpreq *req,i struct sr_if *out_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arprequest(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  /* Allocate space for ARP request packet */
  unsigned int reqst_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reqst_pkt = (uint8_t *)malloc(reqst_len);
  if (NULL == reqst_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *reqst_ethhdr = (sr_ethernet_hdr_t *)reqst_pkt;
  sr_arp_hdr_t *reqst_arphdr = 
      (sr_arp_hdr_t *)(reqst_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memset(reqst_ethhdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
  memcpy(reqst_ethhdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  reqst_ethhdr->ether_type = htons(ethertype_arp);

  /* Populate ARP header */
  reqst_arphdr->ar_hrd = htons(arp_hrd_ethernet);
  reqst_arphdr->ar_pro = htons(ethertype_ip);
  reqst_arphdr->ar_hln = ETHER_ADDR_LEN;
  reqst_arphdr->ar_pln = sizeof(uint32_t);
  reqst_arphdr->ar_op = htons(arp_op_request); 
  memcpy(reqst_arphdr->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
  reqst_arphdr->ar_sip = out_iface->ip;
  memset(reqst_arphdr->ar_tha, 0x00, ETHER_ADDR_LEN);
  reqst_arphdr->ar_tip = req->ip;

  /* Send ARP request */
  printf("Send ARP request\n");
  print_hdrs(reqst_pkt, reqst_len);
  sr_send_packet(sr, reqst_pkt, reqst_len, out_iface->name);
  free(reqst_pkt);
} /* -- sr_send_arprequest -- */

/*---------------------------------------------------------------------
* NEW CODE
-----------------------------------------------------------------------*/

void sr_add_ethernet_send(struct sr_instance *sr,
        uint8_t *packet,
        unsigned int len,
        uint32_t dip,
        enum sr_ethertype type) 
{
    struct sr_rt *lpmatch;
    struct sr_if *r_iface;
    struct sr_ethernet_hdr sr_ether_pkt;
    struct sr_arp_hdr * arp_pkt;
    uint8_t *send_packet;
    unsigned int eth_pkt_len;
    struct sr_arpentry *arp_entry;

    lpmatch = longest_prefix_matching(sr, dip);
    r_iface = sr_get_interface(sr, lpmatch->interface);

    if (type == ethertype_arp) { 
      arp_pkt = (struct sr_arp_hdr *)packet;

      /* Broadcast request */
      if (arp_pkt->ar_op == htons(arp_op_request)){
        memset(sr_ether_pkt.ether_dhost, 255, ETHER_ADDR_LEN);
      }
                   
      /* Build reply packet */
      else if (arp_pkt->ar_op == htons(arp_op_reply))
        memcpy(sr_ether_pkt.ether_dhost, arp_pkt->ar_tha, ETHER_ADDR_LEN);
        memcpy(sr_ether_pkt.ether_shost, r_iface->addr, ETHER_ADDR_LEN);
              sr_ether_pkt.ether_type = htons(type);

        /* Copy the packet into the sender buf */
        eth_pkt_len = sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr);
        send_packet = malloc(eth_pkt_len);
        memcpy(send_packet, &sr_ether_pkt, sizeof(struct sr_ethernet_hdr));
        memcpy(send_packet + sizeof(struct sr_ethernet_hdr), 
              packet, sizeof(struct sr_arp_hdr));

        /* Send the reply*/
        sr_send_packet(sr, send_packet, eth_pkt_len, r_iface->name);
        free(send_packet);

    } else {
        arp_entry = sr_arpcache_lookup(&sr->cache, dip);

        /* Set the ethernet header */
        memcpy(sr_ether_pkt.ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        memcpy(sr_ether_pkt.ether_shost, r_iface->addr, ETHER_ADDR_LEN);
              sr_ether_pkt.ether_type = htons(type);

        /* Copy the packet into the sender buf */
        eth_pkt_len = len + sizeof(struct sr_ethernet_hdr);
        send_packet = malloc(eth_pkt_len);
        memcpy(send_packet, &sr_ether_pkt, sizeof(struct sr_ethernet_hdr));
        memcpy(send_packet + sizeof(struct sr_ethernet_hdr), packet, len);

        /* Send the reply*/
        sr_send_packet(sr, send_packet, eth_pkt_len, r_iface->name);
        free(send_packet);
    }

}


struct sr_icmp_t3_hdr icmp_send_error_packet(struct sr_ip_hdr *ip_hdr, int code_num)
{

    struct sr_icmp_t3_hdr icmp_error_reply;
    
    icmp_error_reply.icmp_type = 3;
    memcpy(icmp_error_reply.data, ip_hdr, ICMP_DATA_SIZE);
    icmp_error_reply.icmp_code = code_num;    
    icmp_error_reply.next_mtu = htons(MTU);
    icmp_error_reply.icmp_sum = 0;
    icmp_error_reply.unused = 0;
    icmp_error_reply.icmp_sum = cksum(&(icmp_error_reply), ICMP_TYPE3_LEN);

    return icmp_error_reply;
}


struct sr_rt* longest_prefix_matching(struct sr_instance *sr, uint32_t ip_dest)
{
    /* Find longest prefix match in routing table. */
    struct sr_rt* ip_walker;
    struct sr_rt* lpmatch = 0;
    unsigned long lpmatch_len = 0;
    struct in_addr dst_ip;
        
    dst_ip.s_addr = ip_dest;  
    ip_walker = sr->routing_table;
        
    /* If there is a longer match ahead replace it */
    while(ip_walker != 0) {
      if (((ip_walker->dest.s_addr & ip_walker->mask.s_addr) == (dst_ip.s_addr & ip_walker->mask.s_addr)) && 
        (lpmatch_len <= ip_walker->mask.s_addr)) {          
          lpmatch_len = ip_walker->mask.s_addr;
          lpmatch = ip_walker;
      }
        ip_walker = ip_walker->next;
    }
    return lpmatch;
}


/*---------------------------------------------------------------------
* NEW CODE
-----------------------------------------------------------------------*/

/*---------------------------------------------------------------------
 * Method: sr_handle_arpreq(struct sr_instance *sr, 
 *             struct sr_arpreq *req, struct sr_if *out_iface)
 * Scope:  Global
 *
 * Perform processing for a pending ARP request: do nothing, timeout, or  
 * or generate an ARP request packet 
 *---------------------------------------------------------------------*/
void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  time_t now = time(NULL);
  if (difftime(now, req->sent) >= 1.0)
  {
    if (req->times_sent >= 5)
    {
      /*********************************************************************/
      /* TODO: send ICMP host uncreachable to the source address of all    */
      /* packets waiting on this request                                   */

	printf("** Host Unreachable\n");

	/* Send ICMP host unreachable*/
	struct sr_packet *ip_packet, *next;

	ip_packet = req->packets;

	if (ip_packet != 0)
	{
	next = ip_packet->next;
        }

	while (ip_packet != 0)
	{
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(ip_packet->buf);
	struct sr_if *s_interface = sr_get_interface(sr, ip_packet->iface);
	uint32_t dst;

	/* Send ICMP host unreachable */
	struct sr_ip_hdr send_ip_hdr;

	send_ip_hdr.ip_hl = 5;
	send_ip_hdr.ip_v = ip_hdr->ip_v;
	send_ip_hdr.ip_tos = 0;
	send_ip_hdr.ip_id = 0;
	send_ip_hdr.ip_off = htons(IP_DF);
	send_ip_hdr.ip_ttl = 100;
	send_ip_hdr.ip_p = ip_protocol_icmp;
	send_ip_hdr.ip_sum = 0;
	send_ip_hdr.ip_dst = ip_hdr->ip_src;
	send_ip_hdr.ip_src = s_interface->ip;
	dst = ip_hdr->ip_src;

	/* Copy the packet over */
	uint8_t *cache_packet;
	uint16_t total_len;
	uint16_t icmp_len;

          icmp_len = sizeof(struct sr_icmp_t3_hdr);
          total_len = ICMP_IP_HDR_LEN_BYTE + icmp_len;
          send_ip_hdr.ip_len = htons(total_len);
          send_ip_hdr.ip_sum = cksum(&send_ip_hdr, ICMP_IP_HDR_LEN_BYTE);

          cache_packet = malloc(total_len);
          struct sr_icmp_t3_hdr icmp_error_packet = icmp_send_error_packet(ip_hdr, code_host_unreach);

          memcpy(cache_packet, &(send_ip_hdr), ICMP_IP_HDR_LEN_BYTE);
          memcpy(cache_packet + ICMP_IP_HDR_LEN_BYTE, &(icmp_error_packet), 
                sizeof(struct sr_icmp_t3_hdr));

          print_hdr_ip(cache_packet);

          struct sr_arpreq *icmp_req;
          struct sr_arpentry *arp_entry;

          /* Check ARP cache  */
          arp_entry = sr_arpcache_lookup(&sr->cache, dst);

          if (arp_entry != 0){
                
            /* Entry exists, we can send it out right now */
            sr_add_ethernet_send(sr, cache_packet, total_len, dst, ethertype_ip);
          } else {

              /* Get the interface at which the original packet arrived */
              struct sr_rt *lpmatch;
              struct sr_if *r_iface;

              lpmatch = longest_prefix_matching(sr, dst);
              r_iface = sr_get_interface(sr, lpmatch->interface);           
              icmp_req = sr_arpcache_queuereq(&sr->cache, dst, 
                                        cache_packet, total_len, r_iface->name);
              sr_handle_arpreq(sr, icmp_req, out_iface);
            }
          ip_packet = next;
          if(ip_packet != 0){
            next = ip_packet->next;
          } else {
              sr_arpreq_destroy(&sr->cache, req);
          }
	} 

      /*********************************************************************/

      sr_arpreq_destroy(&(sr->cache), req);
    }
    else
    { 
      /* Send ARP request packet */
      sr_send_arprequest(sr, req, out_iface);
       
      /* Update ARP request entry to indicate ARP request packet was sent */ 
      req->sent = now;
      req->times_sent++;
    }
  }
} /* -- sr_handle_arpreq -- */

/*---------------------------------------------------------------------
 * Method: void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, uint32_t next_hop_ip, 
 *             struct sr_if *out_iface)
 * Scope:  Local
 *
 * Queue a packet to wait for an entry to be added to the ARP cache
 *---------------------------------------------------------------------*/
void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, uint32_t next_hop_ip, struct sr_if *out_iface)
{
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, 
            pkt, len, out_iface->name);
    sr_handle_arpreq(sr, req, out_iface);
} /* -- sr_waitforarp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Handle an ARP packet that was received by the router
 *---------------------------------------------------------------------*/
void sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, struct sr_if *src_iface)
{
  /* Drop packet if it is less than the size of Ethernet and ARP headers */
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)))
  {
    printf("Packet is too short => drop packet\n");
    return;
  }

  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  switch (ntohs(arphdr->ar_op))
  {
  case arp_op_request:
  {
    /* Check if request is for one of my interfaces */
    if (arphdr->ar_tip == src_iface->ip)
    {
		printf("Request is for me...");
		sr_send_arpreply(sr, pkt, len, src_iface); }
    break;
  }
  case arp_op_reply:
  {
    /* Check if reply is for one of my interfaces */
    if (arphdr->ar_tip != src_iface->ip)
    { break; }

    /* Update ARP cache with contents of ARP reply */
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha, 
        arphdr->ar_sip);

    /* Process pending ARP request entry, if there is one */
    if (req != NULL)
    {
      /*********************************************************************/
      /* TODO: send all packets on the req->packets linked list            */

		struct sr_packet *packet_walker = req->packets;
        while(packet_walker){
			printf("Sending all packets in linked list...");
            /*forward the packets*/
			/*
            uint8_t *fwd_packet = packet_walker->buf;
            struct sr_ethernet_hdr_t *fwd_eth_hdr = get_ethernet_hdr(fwd_packet, packet_walker->len);
			*/
            
            /*set destination mac address*/
            /*memcpy(fwd_eth_hdr->ether_dhost, arphdr->ar_sha, ETHER_ADDR_LEN);*/
            /*set out src_iface*/
            /*memcpy(fwd_eth_hdr->ether_dhost, src_iface->addr, ETHER_ADDR_LEN);*/
            
            /*re-calculate checksum*/
            /*
            struct sr_ip_hdr_t *fwd_ip_hdr = (sr_ip_hdr_t*)(fwd_packet + sizeof(sr_ethernet_hdr_t));
 
            fwd_ip_hdr->ip_sum = 0;
            fwd_ip_hdr->ip_sum = cksum(fwd_ip_hdr, sizeof(sr_ip_hdr_t));
            sr_send_packet(sr, fwd_packet, packet_walker->len, src_iface->name);
			*/
            sr_send_arprequest(sr, packet_walker, src_iface);
            packet_walker = packet_walker->next;
  
        }

      /*********************************************************************/
		printf("Destroying ARP request.");
      /* Release ARP request entry */
      sr_arpreq_destroy(&(sr->cache), req);
    }
    break;
  }    
  default:
    printf("Unknown ARP opcode => drop packet\n");
    return;
  }
} /* -- sr_handlepacket_arp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /*************************************************************************/
  /* TODO: Handle packets                                                  */

  uint16_t type = ethertype(packet);
  
  if (type == ethertype_arp) {
	  printf("Processing ARP packet.\n");

    sr_handlepacket_arp(sr, packet, len, interface);
  } else if (type == ethertype_ip) {
    /* STILL NEED TO ADD THIS*/
    /*handle_ip(sr, packet, len);*/
  } else {
    fprintf(stderr, "invalid packet type id in ethernet header\n");
  }

  /*************************************************************************/

}/* end sr_ForwardPacket */

struct sr_if *sr_packet_is_for_me(struct sr_instance *sr, uint32_t ip_dest) {
	struct sr_if *node = sr->if_list;
	while (node) {
		if (node->ip == ip_dest)return node;
		node = node->next;
	}
	return NULL;
}

void sr_handlepacket_ip(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {

	int min_length = sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t);
	if (len < min_length) {
		fprintf(stderr, "IP Packet too small - returning...\n");
		return;
	}

	sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	unsigned int ip_hdr_len = iphdr->ip_hl * 4;

	struct sr_if *my_node = sr_packet_is_for_me(sr, iphdr->ip_dst);
	if (my_node) {
		fprintf(stderr, "IP packet is for us\n");
		/*******************************************************/
		/*DONE*/
		sr_ip_packet_for_me(sr, iphdr);
		/*******************************************************/
		return;
	}

	uint8_t new_ttl = iphdr->ip_ttl - 1;
	if (new_ttl == 0) {
		fprintf(stderr, "TTL hit zero, sending an ICMP back....\n");
		uint8_t * buf = calloc(4 + ip_hdr_len + SNIPPIT, 1);
		memcpy(buf + 4, iphdr, ip_hdr_len + SNIPPIT);
		/*******************************************************/
		sr_send_icmp(sr, type_time_exceeded, code_ttl_expired, iphdr->ip_dst, iphdr->ip_src, buf, 4 + ip_hdr_len + SNIPPIT);
		/*******************************************************/
		free(buf);
		return;
	}

	iphdr->ip_ttl = new_ttl;

	iphdr->ip_sum = 0;
	iphdr->ip_sum = cksum(iphdr, ip_hdr_len);

	struct sr_rt *match = longest_prefix_matching(sr, iphdr->ip_dst);
	if (match) {

		uint8_t *temp = malloc(len);
		if (!temp)return;

		memcpy(temp, packet, len);

		sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)temp;

		struct sr_if * node = sr_get_interface(sr, match->interface);
		memcpy(eth_hdr->ether_shost, node->addr, ETHER_ADDR_LEN);

		/*******************************************************/
		/*sr_send_packet(sr, match, temp, len, match->interface);*/
		sr_send_packet(sr, temp, len, match->interface);
		/*sr_send_packet(sr, reply_pkt, reply_len, src_iface->name);*/
		/*******************************************************/
		free(temp);
	}
	else {
		fprintf(stderr, "No routing table match, send ICMP\n");
		struct sr_if *my_source = sr_get_interface(sr, interface);
		/*******************************************************/
		sr_send_icmp3(sr, type_dst_unreach, code_net_unreach, my_source->ip, iphdr->ip_src, (uint8_t*)iphdr, ip_hdr_len + SNIPPIT);
		/*******************************************************/
	}
}

/* Handles an IP packet that is meant for me
If it is ICMP echo, then we send reply, otherwise, if it is TCP or UDP,
we send an port unreachable back to sender
*/
void sr_ip_packet_for_me(struct sr_instance *sr, struct sr_ip_hdr *ip_hdr) {

	unsigned int ip_hdr_len = ip_hdr->ip_hl * 4;
	uint8_t *ip_payload = ((uint8_t *)ip_hdr) + ip_hdr_len;
	if (ip_hdr->ip_p == ip_protocol_icmp) {

		struct sr_icmp_hdr * icmp_hdr = (sr_icmp_hdr_t *)(ip_payload);
		unsigned int icmp_payload_len = ntohs(ip_hdr->ip_len) - ip_hdr_len - sizeof(sr_icmp_hdr_t);

		if (icmp_hdr->icmp_type == type_echo_request) {

			sr_send_icmp(sr, type_echo_reply, code_echo_reply, ip_hdr->ip_dst, ip_hdr->ip_src, (uint8_t *)(icmp_hdr + 1), icmp_payload_len);
		}

	}
	else {
		/*Assuming its TCP or UDP*/
		fprintf(stderr, "Its NOT an ICMP packet! Send Unreachable!!\n");
		sr_send_icmp3(sr, type_dst_unreach, code_port_unreach, ip_hdr->ip_dst, ip_hdr->ip_src, (uint8_t*)ip_hdr, ip_hdr_len + SNIPPIT);
	}
}

/* Checks to see if a given IP packet was meant for me */


void sr_send_icmp(struct sr_instance *sr, enum sr_icmp_type type, enum sr_icmp_code code, uint32_t ip_source, uint32_t ip_dest, uint8_t *buf, unsigned int len) {

	int icmp_len = sizeof(sr_icmp_hdr_t) + len;
	struct sr_icmp_hdr *icmp = calloc(icmp_len, 1);
	memcpy(icmp + 1, buf, len);
	icmp->icmp_type = type;
	icmp->icmp_code = code;
	icmp->icmp_sum = 0;
	icmp->icmp_sum = cksum(icmp, icmp_len);
	/*******************************************************/
	sr_send_ip(sr, ip_protocol_icmp, ip_source, ip_dest, (uint8_t *)icmp, icmp_len);
	/*******************************************************/
	free(icmp);
}

/* Sends an ICMP packet of type 3*/
void sr_send_icmp3(struct sr_instance *sr, enum sr_icmp_type type, enum sr_icmp_code code, uint32_t ip_source, uint32_t ip_dest, uint8_t *data, unsigned int len) {
	int icmp_len = sizeof(sr_icmp_t3_hdr_t);

	struct sr_icmp_t3_hdr *icmp = calloc(1, icmp_len);
	memcpy(icmp->data, data, len);
	icmp->icmp_type = type;
	icmp->icmp_code = code;
	icmp->icmp_sum = 0;
	icmp->icmp_sum = cksum(icmp, icmp_len);
	/*******************************************************/
	sr_send_ip(sr, ip_protocol_icmp, ip_source, ip_dest, (uint8_t *)icmp, icmp_len);
	/*******************************************************/
	free(icmp);
}

/* Sends an IP packet. Builds an IP and populates the fields accordingly */
void sr_send_ip(struct sr_instance *sr, enum sr_ip_protocol protocol, uint32_t source, uint32_t dest, uint8_t *buf, unsigned int len) {

	struct sr_rt * rt_node = longest_prefix_matching(sr, dest);

	if (!rt_node) {
		fprintf(stderr, "No match in routing table.....should return because otherwise would send message to self\n");
		return;
	}

	struct sr_if * if_node = sr_get_interface(sr, rt_node->interface);
	if (!if_node)return;

	int ip_len = sizeof(sr_ip_hdr_t);

	struct sr_ethernet_hdr *eth = calloc(sizeof(sr_ethernet_hdr_t) + ip_len + len, sizeof(uint8_t));
	struct sr_ip_hdr *ip = (sr_ip_hdr_t *)(eth + 1);
	memcpy(ip + 1, buf, len);

	ip->ip_v = ip_v;
	ip->ip_off = htons(IP_DF);
	ip->ip_hl = MIN_IP_HEADER_SIZE;
	ip->ip_p = protocol;
	ip->ip_src = source;
	ip->ip_dst = dest;
	ip->ip_len = htons(ip_len + len);
	ip->ip_ttl = TTL;
	ip->ip_sum = 0;
	ip->ip_sum = cksum(ip, ip_len);

	eth->ether_type = htons(ethertype_ip);
	memcpy(eth->ether_shost, if_node->addr, ETHER_ADDR_LEN);

	sr_send_packet(sr, rt_node, sizeof(sr_ethernet_hdr_t) + ip_len + len, if_node->name);
	/*sr_send_packet(sr, rt_node, sizeof(sr_ethernet_hdr_t) + ip_len + len, if_node->name);*/
	/*sr_send_ip(sr, ip_protocol_icmp, ip_source, ip_dest, (uint8_t *)icmp, icmp_len);*/
	/*sr_send_packet(sr, reply_pkt, reply_len, src_iface->name);*/

	free(eth);
}
