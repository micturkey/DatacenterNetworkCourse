/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>  
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"
#include "parsing_helpers.h"


SEC("tc")
int droppacket(struct __sk_buff *skb){
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct hdr_cursor nh;
    struct ethhdr *eth;
    int eth_type;
    int ip_type;
    struct iphdr *iphdr;


    /* These keep track of the next header type and iterator pointer */
    nh.pos = data;
    /* Parse Ethernet */
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type != bpf_htons(ETH_P_IP)) return TC_ACT_OK;
        
    /* Parse IP/IPv6 headers */
    ip_type = parse_iphdr(&nh, data_end, &iphdr);
    if (ip_type == -1) return TC_ACT_OK;

    if (iphdr->saddr == 0x050505DF){ // 223.5.5.5's hex, Big-endian mode.
        // drop the packet
        return TC_ACT_SHOT;
        }
    return TC_ACT_OK; 
}
char _license[] SEC("license") = "GPL";