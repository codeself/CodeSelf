/*
 * This is the 2017-09-02 write of URL filter, aiming for kernel 3.5.x.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include "uf_send_skb.h"

#define UF_SEND_SKB_OK		0
#define UF_SEND_SKB_ERR	1
#define UF_SEND_SKB_IGNORE	2

#define UF_SEND_SKB_TO_SENDER 0
#define UF_SEND_SKB_TO_RECEIVER 1

int uf_send_ipv4_resetskb(struct sk_buff *old_skb, int hook, int direct)
{
	struct sk_buff *new_skb;
	const struct tcphdr *old_tcphdr;
	struct tcphdr old_tcphdr_buff;
	struct tcphdr *new_tcphdr;
	const struct iphdr *old_iphdr;
	struct iphdr *new_iphdr;
	unsigned int addr_type = RTN_UNSPEC;

	if (ip_hdr(old_skb)->frag_off & htons(IP_OFFSET))
		return UF_SEND_SKB_ERR;

	if (ip_hdr(old_skb)->protocol != IPPROTO_TCP)
		return UF_SEND_SKB_IGNORE;

	old_tcphdr = skb_header_pointer(old_skb, ip_hdrlen(old_skb),
							sizeof(old_tcphdr_buff), (void*)(&old_tcphdr_buff));
	if (old_tcphdr == NULL)
		return UF_SEND_SKB_ERR;

	/* 如果已经是rst 的TCP包就不需要发送reset */
	if (old_tcphdr->rst)
		return UF_SEND_SKB_IGNORE;
	
	if (nf_ip_checksum(old_skb, hook, ip_hdrlen(old_skb), IPPROTO_TCP))
		return UF_SEND_SKB_ERR;

	old_iphdr = ip_hdr(old_skb);

	new_skb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) + LL_MAX_HEADER, GFP_ATOMIC);
	if (new_skb == NULL)
		return UF_SEND_SKB_ERR;
	
	/* 预留skb空间并复位 */	
	skb_reserve(new_skb, LL_MAX_HEADER);
	skb_reset_network_header(new_skb);
	
	/* 初始化新的skb ip header*/
	new_skb->vlan_tci = old_skb->vlan_tci;
	new_iphdr = (struct iphdr *)skb_put(new_skb, sizeof(struct iphdr));
	new_iphdr->version = 4;
	new_iphdr->ihl = sizeof(struct iphdr) / 4;
	new_iphdr->tos = 0;
	new_iphdr->id  = 0;
	new_iphdr->frag_off = htons(IP_DF);
	new_iphdr->protocol = IPPROTO_TCP;
	new_iphdr->check = 0;
	new_iphdr->saddr = (direct == UF_SEND_SKB_TO_SENDER) ? old_iphdr->daddr : old_iphdr->saddr;
	new_iphdr->daddr = (direct == UF_SEND_SKB_TO_SENDER) ? old_iphdr->saddr : old_iphdr->daddr;

	/*初始化新的skb tcp header*/
	new_tcphdr = (struct tcphdr *)skb_put(new_skb, sizeof(struct tcphdr));
	memset(new_tcphdr, 0, sizeof(*new_tcphdr));
	new_tcphdr->source = (direct == UF_SEND_SKB_TO_SENDER) ? old_tcphdr->dest : old_tcphdr->source;
	new_tcphdr->dest = (direct == UF_SEND_SKB_TO_SENDER) ? old_tcphdr->source : old_tcphdr->dest;
	new_tcphdr->doff = sizeof(struct tcphdr) / 4;
	new_tcphdr->window = 0;
	new_tcphdr->urg_ptr = 0;

	/* 清空4层以上数据，构造3/4层各字段值 */
	skb_trim(new_skb, new_iphdr->ihl * 4 + sizeof(struct tcphdr));
	new_iphdr->tot_len = htons(new_skb->len);

	if (old_tcphdr->ack) {
		new_tcphdr->seq = old_tcphdr->ack_seq;
	} else {
		new_tcphdr->ack_seq = htonl(ntohl(old_tcphdr->seq) 
									+ old_tcphdr->syn
									+ old_tcphdr->fin
									+ old_skb->len
									- ip_hdrlen(old_skb)
									- (old_tcphdr->doff << 2));
		new_tcphdr->ack = 1;
	}

	new_tcphdr->rst = 1;
	/* 计算TCP校验和 */
	new_tcphdr->check = tcp_v4_check(sizeof(struct tcphdr), new_iphdr->saddr, new_iphdr->daddr, 
													csum_partial(new_tcphdr,sizeof(struct tcphdr), 0));
	if (hook != NF_INET_FORWARD
		#ifdef CONFIG_BRIDGE_NETFILTER
			|| (new_skb->nf_bridge && new_skb->nf_bridge->mask & BRNF_BRIDGED)
		#endif
		) addr_type = RTN_LOCAL;

	skb_dst_set(new_skb, dst_clone(skb_dst(old_skb)));
	new_skb->protocol = htons(ETH_P_IP);
	if (ip_route_me_harder(new_skb, addr_type))
		goto free_new_skb;
	new_iphdr->ttl = dst_metric(skb_dst(new_skb), RTAX_HOPLIMIT);
	
	/* 由IP协议栈自己去计算校验和 */
	new_skb->ip_summed = CHECKSUM_NONE;
	
	if (new_skb->len > dst_mtu(skb_dst(new_skb)))
		goto free_new_skb;
	
	/* 2层数据在路由找到dev后自动加上 */	
	ip_local_out(new_skb);
	
	return UF_SEND_SKB_OK;	

free_new_skb:
	kfree_skb(new_skb);
	return UF_SEND_SKB_ERR;
}

int uf_send_ipv6_resetskb(struct sk_buff *old_skb, int hook, int direct)
{
	struct sk_buff *new_skb;
	u_int8_t nexthdr;
	__be16 frag_off;
	int tcphoff = 0, need_ack = 0;
	unsigned int old_tcp_len = 0, hh_len = 0;
	const struct ipv6hdr *old_ip6hdr = ipv6_hdr(old_skb);
	struct ipv6hdr *new_ip6hdr;
	const struct tcphdr old_tcphdr;
	struct tcphdr *new_tcphdr;
	struct flowi fl;
	struct dst_entry *dst = NULL;
	struct net *net = dev_net(old_skb->dev);

	if ((!(ipv6_addr_type(&old_ip6hdr->saddr) & IPV6_ADDR_UNICAST)) ||
		(!(ipv6_addr_type(&old_ip6hdr->daddr) & IPV6_ADDR_UNICAST)))
		return UF_SEND_SKB_IGNORE;

	nexthdr = old_ip6hdr->nexthdr;
	tcphoff = ipv6_skip_exthdr(old_skb, sizeof(sizeof(*old_ip6hdr)), &nexthdr, &frag_off);
	if ((tcphoff < 0) || (tcphoff > old_skb->len))
		return UF_SEND_SKB_ERR;

	old_tcp_len = old_skb->len - tcphoff;
	if (nexthdr != IPPROTO_TCP || old_tcp_len < sizeof(struct tcphdr))
		return UF_SEND_SKB_ERR;

	if (skb_copy_bits(old_skb, tcphoff, (void *)(&old_tcphdr), sizeof(struct tcphdr)))
		return UF_SEND_SKB_ERR;
	
	if (old_tcphdr.rst)
		return UF_SEND_SKB_IGNORE;

	/* 检查校验和 */
	if (csum_ipv6_magic(&old_ip6hdr->saddr, 
						&old_ip6hdr->daddr, 
						old_tcp_len,
						IPPROTO_TCP,
						skb_checksum(old_skb, tcphoff, old_tcp_len, 0)))
		return UF_SEND_SKB_ERR;

	memset(&fl, 0, sizeof(fl));
	fl.u.ip6.__fl_common.flowic_proto = IPPROTO_TCP;

	if (direct == UF_SEND_SKB_TO_SENDER) {
		memcpy(&fl.u.ip6.saddr, &old_ip6hdr->daddr, sizeof(old_ip6hdr->daddr));
		memcpy(&fl.u.ip6.daddr, &old_ip6hdr->saddr, sizeof(old_ip6hdr->saddr));
		fl.u.ip6.uli.ports.sport = old_tcphdr.dest;
		fl.u.ip6.uli.ports.dport = old_tcphdr.source;
	} else {
		memcpy(&fl.u.ip6.saddr, &old_ip6hdr->saddr, sizeof(old_ip6hdr->saddr));
		memcpy(&fl.u.ip6.daddr, &old_ip6hdr->daddr, sizeof(old_ip6hdr->daddr));
		fl.u.ip6.uli.ports.sport = old_tcphdr.source;
		fl.u.ip6.uli.ports.dport = old_tcphdr.dest;
	}
	
	dst = ip6_route_output(net, NULL, &(fl.u.ip6));

	if (dst == NULL || dst->error) {
		dst_release(dst);
		return UF_SEND_SKB_ERR;
	}

	if (xfrm_lookup(net, dst, &fl, NULL, 0))
		return UF_SEND_SKB_ERR;
	hh_len = (dst->dev->hard_header_len + 15)&~15;
	new_skb = alloc_skb(hh_len + 15 + dst->header_len 
						+ sizeof(struct ipv6hdr)
						+ sizeof(struct tcphdr)
						+ dst->trailer_len, GFP_ATOMIC);
	if (new_skb == NULL) {
		if (net_ratelimit())
			printk("Firewall: IPv6 send reset Cannot alloc skb\n");
		dst_release(dst);
		return UF_SEND_SKB_ERR;
	}

	skb_dst_set(new_skb, dst);
	skb_reserve(new_skb, hh_len + dst->header_len);

	skb_put(new_skb, sizeof(struct ipv6hdr));
	skb_reset_network_header(new_skb);
	new_skb->vlan_tci = old_skb->vlan_tci;
	new_ip6hdr = ipv6_hdr(new_skb);
	new_ip6hdr->version = 6;
	new_ip6hdr->hop_limit = dst_metric(dst, RTAX_HOPLIMIT);
	new_ip6hdr->nexthdr = IPPROTO_TCP;
	if (direct == UF_SEND_SKB_TO_SENDER) {
		memcpy(&new_ip6hdr->saddr, &old_ip6hdr->daddr, sizeof(old_ip6hdr->daddr));
		memcpy(&new_ip6hdr->daddr, &old_ip6hdr->saddr, sizeof(old_ip6hdr->saddr));
	} else {
		memcpy(&new_ip6hdr->saddr, &old_ip6hdr->saddr, sizeof(old_ip6hdr->saddr));
		memcpy(&new_ip6hdr->daddr, &old_ip6hdr->daddr, sizeof(old_ip6hdr->daddr));
	}

	new_ip6hdr->payload_len = htons(sizeof(struct tcphdr));
	new_tcphdr = (struct tcphdr *)skb_put(new_skb, sizeof(struct tcphdr));

	/* Truncate to length (no data) */
	new_tcphdr->doff = sizeof(struct tcphdr)/4;
	new_tcphdr->source = (direct == UF_SEND_SKB_TO_SENDER) ? old_tcphdr.dest : old_tcphdr.source;
	new_tcphdr->dest = (direct == UF_SEND_SKB_TO_SENDER) ? old_tcphdr.source : old_tcphdr.dest;
 
	if (old_tcphdr.ack) {
		need_ack = 0;
		new_tcphdr->seq = old_tcphdr.ack_seq;
		new_tcphdr->ack_seq = 0;
	} else {
		need_ack = 1;
		new_tcphdr->ack_seq = htonl(ntohl(old_tcphdr.seq) + old_tcphdr.syn
								+ old_tcphdr.fin + old_tcp_len - (old_tcphdr.doff<<2));
		new_tcphdr->seq = 0;
	}

	/* Reset flags */
	((u_int8_t *)new_tcphdr)[13] = 0;
	new_tcphdr->rst = 1;
	new_tcphdr->ack = need_ack;
	new_tcphdr->window = 0;
	new_tcphdr->urg_ptr = 0;
	new_tcphdr->check = 0;
                                                                               
	/* Adjust TCP checksum */
	new_tcphdr->check = csum_ipv6_magic(&ipv6_hdr(new_skb)->saddr,
									&ipv6_hdr(new_skb)->daddr,
									sizeof(struct tcphdr), IPPROTO_TCP,
									csum_partial(new_tcphdr, sizeof(struct tcphdr), 0));
	ip6_local_out(new_skb);	

	return UF_SEND_SKB_OK;
}

int uf_send_resetskb_to_sender(struct sk_buff *skb, int hook)
{
	int ret = 0;

	if (ntohs(skb->protocol) == ETH_P_IP)
		uf_send_ipv4_resetskb(skb, hook, UF_SEND_SKB_TO_SENDER);
	else if (ntohs(skb->protocol) == ETH_P_IPV6)
		uf_send_ipv6_resetskb(skb, hook, UF_SEND_SKB_TO_SENDER);

	return ret;
}

int uf_send_resetskb_to_receiver(struct sk_buff *skb, int hook)
{
	int ret = 0;

	if (ntohs(skb->protocol) == ETH_P_IP)
		uf_send_ipv4_resetskb(skb, hook, UF_SEND_SKB_TO_RECEIVER);
	else if (ntohs(skb->protocol) == ETH_P_IPV6)
		uf_send_ipv6_resetskb(skb, hook, UF_SEND_SKB_TO_RECEIVER);

	return ret;
}
