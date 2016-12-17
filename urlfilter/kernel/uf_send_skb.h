/*
 * This is the 2017-09-02 write of URL filter, aiming for kernel 3.5.x.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>

#include <net/ip.h>
#include <net/dst.h>
#include <net/tcp.h>
#include <net/flow.h>
#include <net/ip6_route.h>
//#include <include/net/netfilter/ipv4/nf_reject.h>
//#include <include/net/netfilter/ipv6/nf_reject.h>

int uf_send_ipv4_resetskb(struct sk_buff *old_skb, int hook, int direct);
int uf_send_ipv6_resetskb(struct sk_buff *old_skb, int hook, int direct);
int uf_send_resetskb_to_sender(struct sk_buff *skb, int hook);
int uf_send_resetskb_to_receiver(struct sk_buff *skb, int hook);
