/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"
#include "parsing_helpers.h"


SEC("xdp_port")
int droppacket(struct xdp_md *ctx){
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
    int tcp_length;
	struct iphdr *iphdr;
    struct tcphdr *tcphdr;


	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;
    /* Parse Ethernet */
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type != bpf_htons(ETH_P_IP)) return XDP_PASS;
        
	/* Parse IP/IPv6 headers */
    ip_type = parse_iphdr(&nh, data_end, &iphdr);
    if (ip_type == -1)
    return XDP_PASS;

    if (ip_type == IPPROTO_TCP){ 
        tcp_length = parse_tcphdr(&nh, data_end, &tcphdr);
        if (tcp_length < 0) return XDP_PASS;
        if (tcphdr->dest == bpf_htons(22)){// Use bpf_ntohl() to convert 22 to hex, Big-endian mode.
            return XDP_DROP;
        }
        return XDP_PASS;
    }
}
char _license[] SEC("license") = "GPL";