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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define IP_HDR_LENGTH 20
#define ICMP_HDR_LENGTH 8
#define TCP_HDR_LENGTH 40
#define UDP_HDR_LENGTH 8

void sr_handle_ip_packet(struct sr_instance* sr, struct sr_ethernet_hdr* e_hdr_in, struct sr_if* iface, uint8_t* packet, unsigned int len) {
    struct sr_ip_hdr* ip_hdr_in;
    ip_hdr_in = (struct sr_ip_hdr*) packet;

    /* Sanity check the packet */
    uint16_t csum = cksum(ip_hdr_in, sizeof(struct sr_ip_hdr));
    unsigned int temp = len;
    len = ntohs(ip_hdr_in->ip_len) - ip_hdr_in->ip_hl;

    if (len < sizeof(struct sr_ip_hdr)) {
        fprintf(stderr, "** Error: IP packet too short: expecting at least %lu bytes and received %u bytes\n", sizeof(struct sr_ip_hdr), len);
        return;
    }
    if (csum != 0) {
        fprintf(stderr, "** Error: IP packet corrupt\n");
        return;
    }

    len = temp;
    /* End */

    /* Prepare needed structs and pre-populate common values */
    struct sr_ethernet_hdr e_hdr_out;
    struct sr_ip_hdr ip_hdr_out;
    struct sr_icmp_t3_hdr* icmp_hdr = malloc(sizeof(struct sr_icmp_t3_hdr));
    struct sr_icmp_hdr* icmp_hdr_in;
    uint8_t t3_buf[sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr)];
    uint8_t r_buf[sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + ICMP_HDR_LENGTH];
    int icmp_csum_len = ICMP_HDR_LENGTH + ICMP_DATA_SIZE;

    ip_hdr_out.ip_v = 4;
    ip_hdr_out.ip_hl = 5; /* Five 32-bit words */
    ip_hdr_out.ip_tos = ip_hdr_in->ip_tos;
    ip_hdr_out.ip_id = ip_hdr_in->ip_id;
    ip_hdr_out.ip_off = ip_hdr_in->ip_off;

    icmp_hdr->icmp_type = icmp_type_unreachable;
    icmp_hdr->unused = 0x00;
    memcpy(icmp_hdr->data, (uint8_t*) ip_hdr_in, ICMP_DATA_SIZE);
    /* End */

    /**********************************************************
        Packet is destined for router
    **********************************************************/
    if (htons(ip_hdr_in->ip_dst) == ntohs(iface->ip)) {
        ip_hdr_out.ip_src = iface->ip;
        ip_hdr_out.ip_dst = ip_hdr_in->ip_src;
        ip_hdr_out.ip_len = htons(IP_HDR_LENGTH + ICMP_HDR_LENGTH + ICMP_DATA_SIZE);
        ip_hdr_out.ip_ttl = INITIAL_TTL;
        ip_hdr_out.ip_p = ip_protocol_icmp;
        ip_hdr_out.ip_sum = 0;
        ip_hdr_out.ip_sum = cksum(&ip_hdr_out, IP_HDR_LENGTH);

        memcpy(e_hdr_out.ether_dhost, e_hdr_in->ether_shost, ETHER_ADDR_LEN);
        memcpy(e_hdr_out.ether_shost, (uint8_t*) iface->addr, ETHER_ADDR_LEN);
        e_hdr_out.ether_type = (uint16_t) htons(ethertype_ip);

        memcpy(t3_buf, (uint8_t*) &e_hdr_out, sizeof(e_hdr_out));
        memcpy(t3_buf + sizeof(e_hdr_out), (uint8_t*) &ip_hdr_out, sizeof(ip_hdr_out));

        switch (ip_hdr_in->ip_p) {
            case ip_protocol_icmp :
                icmp_hdr_in = (struct sr_icmp_hdr*) (packet + sizeof(struct sr_ip_hdr));
                
                if (icmp_hdr_in->icmp_type == icmp_type_ping) {
                    ip_hdr_out.ip_len = htons(IP_HDR_LENGTH + ICMP_HDR_LENGTH);
                    ip_hdr_out.ip_ttl = ip_hdr_in->ip_ttl;
                    ip_hdr_out.ip_sum = 0;
                    ip_hdr_out.ip_sum = cksum(&ip_hdr_out, IP_HDR_LENGTH);
                    icmp_hdr_in->icmp_type = icmp_type_ping_reply;
                    icmp_hdr_in->icmp_sum = 0;
                    icmp_hdr_in->icmp_sum = cksum(icmp_hdr_in, ICMP_HDR_LENGTH);
                    memcpy(r_buf, (uint8_t*) &e_hdr_out, sizeof(e_hdr_out));
                    memcpy(r_buf + sizeof(e_hdr_out), (uint8_t*) &ip_hdr_out, sizeof(ip_hdr_out));
                    memcpy(r_buf + sizeof(e_hdr_out) + sizeof(ip_hdr_out), (uint8_t*) icmp_hdr_in, sizeof(icmp_hdr_in));
                    sr_send_packet(sr, r_buf, sizeof(r_buf), (char*) iface->name);
                    return;
                }
                else {
                    icmp_hdr->icmp_code = net;
                }
            case ip_protocol_tcp :
                icmp_hdr->icmp_code = port;
                break;
            case ip_protocol_udp :
                if (ip_hdr_in->ip_ttl == 1) {
                    icmp_hdr->icmp_type = icmp_type_time_exceeded;
                    icmp_hdr->icmp_code = 0;
                }
                else {
                    icmp_hdr->icmp_code = net;
                }
                break;
        }

        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_csum_len);

        memcpy(t3_buf + sizeof(e_hdr_out) + sizeof(ip_hdr_out), (uint8_t*) icmp_hdr, sizeof(*icmp_hdr));

        sr_send_packet(sr, t3_buf, sizeof(t3_buf), (char*) iface->name);
    }
    /**********************************************************
        Packet is destined for upstream host
    **********************************************************/
    else {
        struct sr_rt* rt_entry = (struct sr_rt*) sr->routing_table;
        bool ip_unreachable = true;

        while (true) {
            if (rt_entry->dest.s_addr == ip_hdr_in->ip_dst) {
                ip_unreachable = false;
                break;
            }
            if (rt_entry->next != NULL) {
                rt_entry = rt_entry->next;
            }
            else {
                break;
            }
        }
        /* End */

        /* Prepare ICMP packet in case IP is unreachable or TTL=0 */
        ip_hdr_out.ip_src = iface->ip;
        ip_hdr_out.ip_dst = ip_hdr_in->ip_src;
        ip_hdr_out.ip_len = htons(IP_HDR_LENGTH + ICMP_HDR_LENGTH + ICMP_DATA_SIZE);
        ip_hdr_out.ip_ttl = INITIAL_TTL;
        ip_hdr_out.ip_p = ip_protocol_icmp;
        ip_hdr_out.ip_sum = 0;
        ip_hdr_out.ip_sum = cksum(&ip_hdr_out, IP_HDR_LENGTH);

        memcpy(e_hdr_out.ether_dhost, e_hdr_in->ether_shost, ETHER_ADDR_LEN);
        memcpy(e_hdr_out.ether_shost, (uint8_t*) iface->addr, ETHER_ADDR_LEN);
        e_hdr_out.ether_type = (uint16_t) htons(ethertype_ip);

        memcpy(t3_buf, (uint8_t*) &e_hdr_out, sizeof(e_hdr_out));
        memcpy(t3_buf + sizeof(e_hdr_out), (uint8_t*) &ip_hdr_out, sizeof(ip_hdr_out));
        /* End */

        if (ip_unreachable) {
            icmp_hdr->icmp_code = net;
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_csum_len);
        
            memcpy(t3_buf + sizeof(e_hdr_out) + sizeof(ip_hdr_out), (uint8_t*) icmp_hdr, sizeof(*icmp_hdr));

            sr_send_packet(sr, t3_buf, sizeof(t3_buf), (char*) iface->name);

            return;
        }

        ip_hdr_in->ip_ttl--;
        ip_hdr_in->ip_sum = 0;
        ip_hdr_in->ip_sum = cksum(ip_hdr_in, sizeof(struct sr_ip_hdr));

        if (ip_hdr_in->ip_ttl == 0) {
            icmp_hdr->icmp_type = icmp_type_time_exceeded;
            icmp_hdr->icmp_code = 0;
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_csum_len);

            memcpy(t3_buf + sizeof(e_hdr_out) + sizeof(ip_hdr_out), (uint8_t*) icmp_hdr, sizeof(*icmp_hdr));

            sr_send_packet(sr, t3_buf, sizeof(t3_buf), (char*) iface->name);

            return;
        }

        /* Packet can be forwarded, so check arp cache for destination MAC address */
        struct sr_if* send_addr = sr_get_interface(sr, rt_entry->interface);
        struct sr_arpentry* arp_entry;
        arp_entry = sr_arpcache_lookup(&sr->cache, ip_hdr_in->ip_dst);

        if (arp_entry != NULL) {
            /* Forward the packet */
            uint8_t buf[len + sizeof(struct sr_ethernet_hdr)];

            memcpy(e_hdr_in->ether_shost, send_addr->addr, ETHER_ADDR_LEN);
            memcpy(e_hdr_in->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
            memcpy(buf, (uint8_t*) e_hdr_in, sizeof(struct sr_ethernet_hdr));
            memcpy(buf + sizeof(struct sr_ethernet_hdr), packet, len);

            sr_send_packet(sr, buf, sizeof(buf), (char*) &rt_entry->interface[0]);
        }
        else {
            /* Create arp request */
            uint8_t buf[len + sizeof(struct sr_ethernet_hdr)];

            memcpy(e_hdr_in->ether_shost, send_addr->addr, ETHER_ADDR_LEN);
            memcpy(buf, (uint8_t*) e_hdr_in, sizeof(struct sr_ethernet_hdr));
            memcpy(buf + sizeof(struct sr_ethernet_hdr), packet, len);

            struct sr_arpreq* arp_req;
            arp_req = sr_arpcache_queuereq(&sr->cache, ip_hdr_in->ip_dst, buf, len + sizeof(struct sr_ethernet_hdr), rt_entry->interface);
            assert(arp_req);
        }
    }
}

void sr_handle_arp_packet(struct sr_instance* sr, struct sr_ethernet_hdr* e_hdr_in, struct sr_if* iface, uint8_t* packet, unsigned int len) {
    if(len < sizeof(struct sr_arp_hdr)) {
        fprintf(stderr , "** Error: ARP packet too short: expecting at least %lu bytes and received %u bytes\n", sizeof(struct sr_arp_hdr), len);
        return;
    }

    struct sr_arp_hdr* a_hdr_in;

    a_hdr_in = (struct sr_arp_hdr*) packet;

    /* Check if packet is request for router's MAC address */
    if(a_hdr_in->ar_op == htons(arp_op_request) && a_hdr_in->ar_tip == iface->ip) {
        uint8_t buf[sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr)];
        struct sr_ethernet_hdr e_hdr_out;
        struct sr_arp_hdr a_hdr_out;

        memcpy(e_hdr_out.ether_dhost, e_hdr_in->ether_shost, ETHER_ADDR_LEN);
        memcpy(e_hdr_out.ether_shost, (uint8_t*) iface->addr, ETHER_ADDR_LEN);
        e_hdr_out.ether_type = (uint16_t) htons(ethertype_arp);

        a_hdr_out.ar_hln = (unsigned char) ETHER_ADDR_LEN;
        a_hdr_out.ar_hrd = (unsigned short) htons(LINKTYPE_ETHERNET);
        a_hdr_out.ar_op = (unsigned short) htons(arp_op_reply);
        a_hdr_out.ar_pln = (unsigned char) sizeof(ethertype_ip);
        a_hdr_out.ar_pro = (unsigned short) htons(ethertype_ip);
        memcpy(a_hdr_out.ar_sha, iface->addr, ETHER_ADDR_LEN);
        a_hdr_out.ar_sip = iface->ip;
        memcpy(a_hdr_out.ar_tha, a_hdr_in->ar_sha, ETHER_ADDR_LEN);
        a_hdr_out.ar_tip = a_hdr_in->ar_sip;

        memcpy(buf,(uint8_t*) &e_hdr_out, sizeof(e_hdr_out));
        memcpy(buf + sizeof(e_hdr_out),(uint8_t*) &a_hdr_out, sizeof(a_hdr_out));

        /* Reply to this ARP request */
        sr_send_packet(sr, buf, sizeof(buf), (char*) iface->name);
    }
    /* Check if packet is reply to request sent by this router */
    else if(a_hdr_in->ar_op == htons(arp_op_reply) && a_hdr_in->ar_tip == iface->ip) {
        struct sr_arpreq* a_req;
        struct sr_packet* pkt;

        /* Insert IP to MAC mapping into ARP cache */
        a_req = sr_arpcache_insert(&(sr->cache), (unsigned char*) &(a_hdr_in->ar_sha), a_hdr_in->ar_sip);

        if(a_req == NULL) {
            return;
        }

        pkt = a_req->packets;

        /*sr_arpreq_destroy(&(sr->cache), a_req); */
        /* Remove this ARP request from ARP request queue */

        /* Send all packets that were waiting on this ARP request to be completed */
        while(pkt != NULL) {            
            struct sr_ethernet_hdr *e_hdr_out;
            struct sr_packet *tmp_pkt;
            
            /* Update destination hardware address using data from ARP reply */
            e_hdr_out = (struct sr_ethernet_hdr*) pkt->buf;
            memcpy(e_hdr_out->ether_dhost, a_hdr_in->ar_sha, ETHER_ADDR_LEN);
            pkt->buf = (uint8_t*) e_hdr_out;

            sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);

            tmp_pkt = pkt;
            pkt = pkt->next;
            
            /* Release memory allocated to packet */
            free(tmp_pkt);
        }
    }
}

/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req){
    if(difftime(time(NULL), req->sent) <= 1.0) {
        return;
    }

    uint8_t brdcast_addr[ETHER_ADDR_LEN];

    brdcast_addr[0] = 0xFF;
    brdcast_addr[1] = 0xFF;
    brdcast_addr[2] = 0xFF;
    brdcast_addr[3] = 0xFF;

    if(req->times_sent >= 5) {
       struct sr_packet* pkt;

        pkt = req->packets;

        /* Send icmp host unreachable to source addr of all pkts waiting on this request */
        while(pkt != NULL) {
            struct sr_ethernet_hdr e_hdr_out;
            struct sr_ip_hdr ip_hdr_out;
            struct sr_icmp_hdr icmp_hdr_out;
            struct sr_if* iface;
            unsigned short dgram_len, frame_len;

            dgram_len = sizeof(struct sr_icmp_hdr) + sizeof(struct sr_ip_hdr);
            frame_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr);

            uint8_t buf[frame_len];

            iface = sr_get_interface(sr, pkt->iface);

            memcpy(e_hdr_out.ether_dhost, &brdcast_addr, ETHER_ADDR_LEN);
            memcpy(e_hdr_out.ether_shost, (uint8_t*) iface->addr, ETHER_ADDR_LEN);
            e_hdr_out.ether_type = (uint16_t) htons(ethertype_arp);

            ip_hdr_out.ip_dst = req->ip;
            ip_hdr_out.ip_hl = 5;
            ip_hdr_out.ip_id = (uint16_t) htons(sr->ip_id);
            ip_hdr_out.ip_len = (uint16_t) htons(dgram_len);
            ip_hdr_out.ip_off = (uint16_t) 0;
            ip_hdr_out.ip_p = (uint8_t) ip_protocol_icmp;
            ip_hdr_out.ip_src = iface->ip;
            ip_hdr_out.ip_sum = (uint16_t) 0;
            ip_hdr_out.ip_tos = (uint8_t) 0;
            ip_hdr_out.ip_ttl = (uint8_t) INITIAL_TTL;

            ip_hdr_out.ip_sum = (uint16_t) htons(cksum(&ip_hdr_out, sizeof(struct sr_ip_hdr)));

            icmp_hdr_out.icmp_code = (uint8_t) 1;
            icmp_hdr_out.icmp_sum = (uint16_t) 0;
            icmp_hdr_out.icmp_type = (uint8_t) 3;

            icmp_hdr_out.icmp_sum = (uint16_t) htons(cksum(&icmp_hdr_out, sizeof(struct sr_icmp_hdr)));

            memcpy(buf,(uint8_t*) &e_hdr_out, sizeof(struct sr_ethernet_hdr));
            memcpy(buf + sizeof(struct sr_ethernet_hdr),(uint8_t*) &ip_hdr_out, sizeof(struct sr_ip_hdr));
            memcpy(buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), (uint8_t*) &icmp_hdr_out, sizeof(struct sr_icmp_hdr));

            sr_send_packet(sr, buf, frame_len, pkt->iface);

            sr->ip_id ++;
            pkt = pkt->next;
        }

        /* Remove ARP request from queue */
        sr_arpreq_destroy(&(sr->cache), req);
        return;
    }
    
    /* ARP request has not yet reached request limit so resend */

    struct sr_if* iface;

    iface = sr_get_ip_outgoing_iface(sr, req->ip);

    if(iface == NULL) {
        fprintf(stderr , "** Error: Cannot find network interface to send ARP request on.\n");
        return;
    }

    uint8_t buf[sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr)];
    struct sr_ethernet_hdr e_hdr_out;
    struct sr_arp_hdr a_hdr_out;

    memcpy(e_hdr_out.ether_dhost, &brdcast_addr, ETHER_ADDR_LEN);
    memcpy(e_hdr_out.ether_shost, (uint8_t*) iface->addr, ETHER_ADDR_LEN);
    e_hdr_out.ether_type = (uint16_t) htons(ethertype_arp);

    a_hdr_out.ar_hln = (unsigned char) ETHER_ADDR_LEN;
    a_hdr_out.ar_hrd = (unsigned short) htons(LINKTYPE_ETHERNET);
    a_hdr_out.ar_op = (unsigned short) htons(arp_op_request);
    a_hdr_out.ar_pln = (unsigned char) sizeof(ethertype_ip);
    a_hdr_out.ar_pro = (unsigned short) htons(ethertype_ip);
    memcpy(a_hdr_out.ar_sha, iface->addr, ETHER_ADDR_LEN);
    a_hdr_out.ar_sip = iface->ip;
    memcpy(a_hdr_out.ar_tha, (unsigned char*) &brdcast_addr, ETHER_ADDR_LEN);
    a_hdr_out.ar_tip = req->ip;

    memcpy(buf,(uint8_t*) &e_hdr_out, sizeof(e_hdr_out));
    memcpy(buf + sizeof(e_hdr_out),(uint8_t*) &a_hdr_out, sizeof(a_hdr_out));

    /* Resend ARP request */
    sr_send_packet(sr, buf, sizeof(buf), (char*) iface->name);

    req->sent = time(NULL);
    req->times_sent ++;
}

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

} /* -- sr_init -- */

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
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */) {

    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    /* See sr_arp_req_not_for_us() in sr_vns_comm.c */
    struct sr_if* iface = sr_get_interface(sr, interface);
    struct sr_ethernet_hdr* e_hdr = 0;

    e_hdr = (struct sr_ethernet_hdr*) packet;

    /* Packet contains IP message */
    if(ethertype((uint8_t*) e_hdr) == ethertype_ip) {
        sr_handle_ip_packet(sr, e_hdr, iface, packet + sizeof(struct sr_ethernet_hdr), len - sizeof(struct sr_ethernet_hdr));
    }
    /* Packet contains ARP message */
    else if(ethertype((uint8_t*) e_hdr) == ethertype_arp) {
        sr_handle_arp_packet(sr, e_hdr, iface, packet + sizeof(struct sr_ethernet_hdr), len - sizeof(struct sr_ethernet_hdr));
    }

}/* -- sr_handlepacket -- */

/* Gets router interface to forward on given destination IP address */
struct sr_if* sr_get_ip_outgoing_iface(struct sr_instance* sr, uint32_t dst_ip) {
    uint32_t longest_prefix;
    struct sr_rt* rt_entry;
    struct sr_if* iface;

    longest_prefix = 0;
    rt_entry = sr->routing_table;
    iface = NULL;

    while(rt_entry != NULL) {
        uint32_t prefix_len;
        uint32_t mask;
        uint32_t dest;

        mask = (uint32_t) ntohl(rt_entry->mask.s_addr);
        dest = (uint32_t) ntohl(rt_entry->dest.s_addr);

        if((prefix_len = sr_ip_prefix_match((mask & dest), (mask & ntohl(dst_ip)))) > longest_prefix) {
            longest_prefix = prefix_len;
            iface = sr_get_interface(sr, (char*) rt_entry->interface);
        }

        rt_entry = rt_entry->next;
    }
    
    return iface;
}

/* Calculate length of longest matching prefix for two IP addresses */
uint32_t sr_ip_prefix_match(uint32_t ip1, uint32_t ip2) {
    uint32_t bits_left, prefix_len, compare_bit;

    prefix_len = 0;
    bits_left = 32;
    compare_bit = 1 << (bits_left - 1);

    while(bits_left > 0) {
        if((compare_bit & ip1) != (compare_bit & ip2)) {
           break;
        }

        prefix_len ++;
        compare_bit = compare_bit >> 1;
        bits_left --;
    }

    return prefix_len;
}