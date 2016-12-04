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
#include <stdbool.h>


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
#define DEFAULT_TTL 100


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
*
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
*
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
    { sr_send_arpreply(sr, pkt, len, src_iface); }
    break;
  }
  case arp_op_reply:
  {
    /* Check if reply is for one of my interfaces */
    if (arphdr->ar_tip != src_iface->ip)
    { break; }


    struct sr_if *s_interface;
    struct sr_packet *pkt_wait;
    struct sr_packet *temp;
    uint8_t *send_packet;
    unsigned int eth_pkt_len;


    /* Update ARP cache with contents of ARP reply */
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha, 
        arphdr->ar_sip);

    /* Process pending ARP request entry, if there is one */
    if (req != NULL)
    {
      /*********************************************************************/
      /* TODO: send all packets on the req->packets linked list            */

	printf("** ARP entry created\n");

	/* Check ARP request queue, if not empty send out packets on it*/
            if (req != 0)
            {
            pkt_wait = req->packets;

              while (pkt_wait != 0) {

                printf("** ARP resolved, sending queued packets\n");
                /* Send the packets out */
                s_interface = sr_get_interface(sr, pkt_wait->iface);
                struct sr_ethernet_hdr sr_ether_hdr;

                /* Construct the ethernet packet */
                sr_ether_hdr.ether_type = htons(ethertype_ip);
                memcpy(sr_ether_hdr.ether_shost, s_interface->addr, ETHER_ADDR_LEN);
                memcpy(sr_ether_hdr.ether_dhost, arphdr->ar_sha, ETHER_ADDR_LEN);

                /* Copy the packet into the sender buf */
                eth_pkt_len = pkt_wait->len + sizeof(struct sr_ethernet_hdr);
                send_packet = malloc(eth_pkt_len);
                memcpy(send_packet, &sr_ether_hdr, sizeof(struct sr_ethernet_hdr));
                memcpy(send_packet + sizeof(struct sr_ethernet_hdr), 
                      pkt_wait->buf, pkt_wait->len);

                sr_send_packet(sr, send_packet, eth_pkt_len, s_interface->name);

                temp = pkt_wait;
                pkt_wait = pkt_wait->next;
                free(temp);
              }

            printf("** All queued packets sent\n");
            }

      /*********************************************************************/

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
*
-----------------------------------------------------------------------*/

void sr_icmp_with_payload(struct sr_instance *sr,
        sr_ip_hdr_t *ip_hdr, char *interface,
        uint8_t icmp_type, uint8_t icmp_code) {

    struct sr_if *out_iface;
    struct sr_if *r_interface = sr_get_interface(sr, interface);
    struct sr_arpreq *req;
    struct sr_arpentry *arp_entry;
    uint8_t *cache_packet;
    uint16_t total_len;
    uint16_t icmp_len;
    uint32_t dst;


    /* Create a new IP packet for ICMP message */
    struct sr_ip_hdr send_ip_hdr;

    send_ip_hdr.ip_hl = 5;
    send_ip_hdr.ip_v = ip_hdr->ip_v;
    send_ip_hdr.ip_tos = 0;
    send_ip_hdr.ip_id = 0;
    send_ip_hdr.ip_off = htons(IP_DF);
    send_ip_hdr.ip_ttl = DEFAULT_TTL;
    send_ip_hdr.ip_p = ip_protocol_icmp;
    send_ip_hdr.ip_sum = 0;
    send_ip_hdr.ip_dst = ip_hdr->ip_src;

    if (icmp_type == 3 && icmp_code == 3){
      ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
      send_ip_hdr.ip_src = ip_hdr->ip_dst;
    } else {
        send_ip_hdr.ip_src = r_interface->ip;
    }
    dst = ip_hdr->ip_src;

    struct sr_icmp_t3_hdr error_packet;

    error_packet.icmp_type = icmp_type;
    error_packet.icmp_code = icmp_code;
    error_packet.icmp_sum = 0;
    error_packet.unused = 0;
    error_packet.next_mtu = htons(MTU);

    icmp_len = sizeof(struct sr_icmp_t3_hdr);
    total_len = ICMP_IP_HDR_LEN_BYTE + icmp_len;
    send_ip_hdr.ip_len = htons(total_len);
    send_ip_hdr.ip_sum = cksum(&send_ip_hdr, ICMP_IP_HDR_LEN_BYTE);

    cache_packet = malloc(total_len);

    memcpy(error_packet.data, ip_hdr, ICMP_DATA_SIZE);
    memcpy(cache_packet, &(send_ip_hdr), ICMP_IP_HDR_LEN_BYTE);
    memcpy(cache_packet + ICMP_IP_HDR_LEN_BYTE, &(error_packet), 
          sizeof(struct sr_icmp_t3_hdr));

    struct sr_icmp_hdr *icmp_hdr_ptr = icmp_header((struct sr_ip_hdr *)cache_packet);

    icmp_hdr_ptr->icmp_sum = cksum(icmp_hdr_ptr, icmp_len);

    /*Check if we should send immediately or wait */
    arp_entry = sr_arpcache_lookup(&sr->cache, dst);
    
    if (arp_entry != 0){

    /* Entry exists, we can send it out right now */
    sr_add_ethernet_send(sr, cache_packet, total_len, dst, ethertype_ip);
    } else {
        req = sr_arpcache_queuereq(&sr->cache, dst, 
                                  cache_packet, total_len, interface);
        sr_handle_arpreq(sr, req, out_iface);
      }  
}

void ip_forwardpacket(struct sr_instance *sr,
        sr_ip_hdr_t *ip_hdr,
        unsigned int len,
        char *interface) {

        printf("** FORWARDING\n");

        struct sr_if *out_iface;
        struct sr_arpreq *req;
        struct sr_arpentry *arp_entry;
        uint8_t icmp_type;
        uint8_t icmp_code;

        ip_hdr->ip_ttl --;
 	
        /* Update checksum */
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

        uint8_t *ip_pkt;

        ip_pkt = malloc(len);
        memcpy(ip_pkt, ip_hdr, len);

        /* Find longest prefix match in routing table */
        struct sr_rt* lpmatch = longest_prefix_matching(sr, ip_hdr->ip_dst);
        
        /* If cannot find destination IP in routing table, send ICMP net unreachable */
        /* OR TTL = 0 */
        if (lpmatch == 0) {
          icmp_type = 3;
          icmp_code = 0;
          sr_icmp_with_payload(sr, ip_hdr, interface, icmp_type, icmp_code);
          return;
        } else if (ip_hdr->ip_ttl == 0){
          icmp_type = 11;
          icmp_code = 0;
          sr_icmp_with_payload(sr, (sr_ip_hdr_t *)(ip_pkt), interface, icmp_type, icmp_code);
          return;
        }

        /* Ready to forward packet */  
        /* Get the corresponding interface of the destination IP. */
        struct sr_if* s_interface = sr_get_interface(sr, lpmatch->interface);
      
        /* Check ARP cache */
        arp_entry = sr_arpcache_lookup(&sr->cache, lpmatch->gw.s_addr);

        if (arp_entry == 0){

            /* If miss APR cache, add the packet to ARP request queue */
            req = sr_arpcache_queuereq(&sr->cache, lpmatch->gw.s_addr, ip_pkt, 
                                      len, s_interface->name);
            sr_handle_arpreq(sr, req, out_iface);
        } else {

            /* Hit ARP cache, send out the packet right away using next-hop */
            /* Encap the ARP request into ethernet frame and then send it */
            sr_ethernet_hdr_t sr_ether_pkt;

            memcpy(sr_ether_pkt.ether_dhost, arp_entry->mac, ETHER_ADDR_LEN); /* Address from routing table */
            memcpy(sr_ether_pkt.ether_shost, s_interface->addr, ETHER_ADDR_LEN); /* Hardware address of the outgoing interface */
            sr_ether_pkt.ether_type = htons(ethertype_ip);

            uint8_t *packet_rqt;
            unsigned int total_len = len + sizeof(struct sr_ethernet_hdr);
            packet_rqt = malloc(total_len);
            memcpy(packet_rqt, &(sr_ether_pkt), sizeof(sr_ether_pkt));
            memcpy(packet_rqt + sizeof(sr_ether_pkt), ip_pkt, len);

            /* Forward the IP packet*/
            sr_send_packet(sr, packet_rqt, total_len, s_interface->name);
            free(packet_rqt);
          }
}

int sr_packet_is_for_me(struct sr_instance* sr, uint32_t ip_dst)
{
    /* -- REQUIRES -- */

    struct sr_if* if_walker = sr->if_list;
    while(if_walker) {
      if(ip_dst == if_walker->ip){
        return 1;
      }
      if_walker = if_walker->next;
    }
    return 0;
}

int ip_validpacket(uint8_t *packet, unsigned int len){

    /* Initialization */
    struct sr_ip_hdr *ip_hdr = ip_header(packet);
    uint16_t c_cksum = 0;
    uint16_t r_cksum = ip_hdr->ip_sum;
    unsigned int hdr_len = ip_hdr->ip_hl * 4;

    /* Ensure the packet is long enough */
    if (len < sizeof(struct sr_ethernet_hdr) + hdr_len){
      return 0;
    }

    /* Check cksum */
    ip_hdr->ip_sum = 0;
    c_cksum = cksum(ip_hdr, hdr_len);
    if (c_cksum != r_cksum){
      return 0;
    }
    return 1;
}

void build_arp_reply(struct sr_instance *sr, struct sr_arp_hdr *arp_hdr, struct sr_if *r_iface)
{
    /* Initalize ARP header and input interface */
    struct sr_arp_hdr build_arp;

    /* Set value of arp packet  */
    build_arp.ar_hrd= htons(arp_hrd_ethernet);
    build_arp.ar_pro= htons(arp_pro_ip);
    build_arp.ar_hln= ETHER_ADDR_LEN;
    build_arp.ar_pln= ARP_PLEN;
    build_arp.ar_op = htons(arp_op_reply);
    build_arp.ar_sip= r_iface->ip;
    build_arp.ar_tip= arp_hdr->ar_sip;
    memcpy(build_arp.ar_sha, r_iface->addr, ETHER_ADDR_LEN); 
    memcpy(build_arp.ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);

    sr_add_ethernet_send(sr, (uint8_t *)&build_arp, 
                        sizeof(struct sr_arp_hdr), arp_hdr->ar_sip, ethertype_arp);
}

int arp_validpacket(uint8_t *packet, unsigned int len){

    /* Ensure the packet is long enough */
    if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr)){
      return 0;
    }

    struct sr_arp_hdr *arp_hdr = arp_header(packet);

    /* Ensure the ARP header setting is correct */
    if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet){
      return 0;
    }
    if (ntohs(arp_hdr->ar_pro) != arp_pro_ip){
      return 0;
    }
    return 1;
}

void arp_handlepacket(struct sr_instance *sr,
        uint8_t *packet,
        unsigned int len,
        char *interface) 
{
    printf("** Recieved ARP packet\n");

    /* Initalize ARP header from the Packet */
    struct sr_arp_hdr *arp_hdr = arp_header(packet);
    /* Interface the packet arrived in */
    struct sr_if *r_iface = sr_get_interface(sr,interface);

    /* Check if interface->ip = arp header->ip */
    if (r_iface->ip != arp_hdr->ar_tip){
      return;
    }

    /* validate ARP packet */
    if (!arp_validpacket(packet, len))
      return;

    if (ntohs(arp_hdr->ar_op) == arp_op_request){

      if(sr_arp_req_not_for_us(sr, packet, len, interface))
        return;

      printf("** ARP packet request to me \n");   
      
      /* Build and send ARP packet  */
      build_arp_reply(sr, arp_hdr, r_iface);
      
    } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
        printf("** ARP packet reply to me\n");

        struct sr_arpentry *arp_entry;
        struct sr_arpreq *arp_req;
        struct sr_if *s_interface;
        struct sr_packet *pkt_wait;
        struct sr_packet *temp;
        uint8_t *send_packet;
        unsigned int eth_pkt_len;

        /* Check ARP cache  */
        arp_entry = sr_arpcache_lookup(&sr->cache, arp_hdr->ar_sip);

        if (arp_entry != 0){
          free(arp_entry);
        } else {
            arp_req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

            printf("** ARP entry created\n");

            /* Check ARP request queue, if not empty send out packets on it*/
            if (arp_req != 0) {
              pkt_wait = arp_req->packets;

              while (pkt_wait != 0) {

                printf("** ARP resolved, sending queued packets\n");
                /* Send the packets out */
                s_interface = sr_get_interface(sr, pkt_wait->iface);
                struct sr_ethernet_hdr sr_ether_hdr;

                /* Construct the ethernet packet */
                sr_ether_hdr.ether_type = htons(ethertype_ip);
                memcpy(sr_ether_hdr.ether_shost, s_interface->addr, ETHER_ADDR_LEN);
                memcpy(sr_ether_hdr.ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);

                /* Copy the packet into the sender buf */
                eth_pkt_len = pkt_wait->len + sizeof(struct sr_ethernet_hdr);
                send_packet = malloc(eth_pkt_len);
                memcpy(send_packet, &sr_ether_hdr, sizeof(struct sr_ethernet_hdr));
                memcpy(send_packet + sizeof(struct sr_ethernet_hdr), 
                      pkt_wait->buf, pkt_wait->len);

                sr_send_packet(sr, send_packet, eth_pkt_len, s_interface->name);

                temp = pkt_wait;
                pkt_wait = pkt_wait->next;
                free(temp);
              }

	    printf("** All queued packets sent\n");

            } 
          }   
      }
}

void ip_handlepacket(struct sr_instance *sr,
        uint8_t *packet,
        unsigned int len,
        char *interface) {

    printf("** Recieved IP packet\n");

    struct sr_ip_hdr *ip_hdr = ip_header(packet);
    struct sr_if *r_interface = sr_get_interface(sr, interface);

    if (!ip_validpacket(packet, len))
      return;


      /* Check interface IP to determine whether this IP packet is for me */
      if (sr_packet_is_for_me(sr, ip_hdr->ip_dst)) {
        ip_handlepacketforme(sr, ip_hdr, interface);
      } else {

          /* Packet is not for me，forward it */
          ip_forwardpacket(sr, ip_hdr, len, interface);
        }  
}

void ip_handlepacketforme(struct sr_instance *sr,
        sr_ip_hdr_t *ip_hdr,
        char *interface) {
 
    struct sr_if *out_iface;
    struct sr_arpreq *req;
    struct sr_arpentry *arp_entry;
    uint8_t *cache_packet;
    uint16_t total_len;
    uint16_t icmp_len;
    uint32_t dst;
    uint8_t icmp_type;
    uint8_t icmp_code;

    /* Check whether ICMP echo request or TCP/UDP */
    if (ip_hdr->ip_p == ip_protocol_icmp){

      dst = ip_hdr->ip_src;
      ip_hdr->ip_src = ip_hdr->ip_dst;
      ip_hdr->ip_dst = dst;

      /* Modify the ICMP reply packet */
      sr_icmp_hdr_t *icmp_hdr_ptr = icmp_header(ip_hdr);

      icmp_hdr_ptr->icmp_sum = 0;
      icmp_hdr_ptr->icmp_type = type_echo_reply;
      icmp_hdr_ptr->icmp_code = code_echo_reply;
      icmp_len = ntohs(ip_hdr->ip_len)-ip_hdr->ip_hl * 4;
              
      /* Copy the packet over */
      total_len = ip_hdr->ip_len;
      cache_packet = malloc(total_len);
      memcpy(cache_packet, ip_hdr, total_len);

      icmp_hdr_ptr = icmp_header((struct sr_ip_hdr *)cache_packet);
      icmp_hdr_ptr->icmp_sum = cksum(icmp_hdr_ptr, icmp_len);

      struct sr_ip_hdr *ip_hdr_csum = (struct sr_ip_hdr *)cache_packet;
      ip_hdr_csum->ip_sum = cksum(ip_hdr_csum, sizeof(sr_ip_hdr_t));

      /* Check if we should send immediately or wait */
      arp_entry = sr_arpcache_lookup(&sr->cache, dst);

      if (arp_entry != 0){

        /* Entry Exists, we can send it out right now */
        sr_add_ethernet_send(sr, cache_packet, total_len, dst, ethertype_ip);

        printf("** ARP entry exists, Echo reply sent\n");

      } else {
          req = sr_arpcache_queuereq(&sr->cache, dst, cache_packet, 
                                    total_len, interface);

          printf("** ARP entry doesn't exist, Echo reply queued\n");

          sr_handle_arpreq(sr, req, out_iface);
        }
    } else if (ip_hdr->ip_p == ip_protocol_tcp||ip_hdr->ip_p == ip_protocol_udp) {

        /* Send ICMP port unreachable */            
        icmp_type = 3;
        icmp_code = 3;             
        sr_icmp_with_payload(sr, ip_hdr, interface, icmp_type, icmp_code);
      }
}

/*---------------------------------------------------------------------
*
-----------------------------------------------------------------------*/


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

    /* Ensure the packet is long enough */
    if (len < sizeof(struct sr_ethernet_hdr)){
      return;
    }

    if (ethertype(packet) == ethertype_arp){
      arp_handlepacket(sr, packet, len, interface);
    } else {
      ip_handlepacket(sr, packet, len, interface);
    }

  /*************************************************************************/

}/* end sr_ForwardPacket */
