/*
 * xfrm4_input.c
 *
 * Changes:
 *	YOSHIFUJI Hideaki @USAGI
 *		Split up af-specific portion
 *	Derek Atkins <derek@ihtfp.com>
 *		Add Encapsulation support
 *
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip.h>
#include <net/xfrm.h>

#include "ax8netfilter.h"

static inline int ax8netfilter_xfrm4_rcv_encap_finish(struct sk_buff *skb)
{
	if (skb->dst == NULL) {
		const struct iphdr *iph = ip_hdr(skb);

		if (ip_route_input(skb, iph->daddr, iph->saddr, iph->tos,
				   skb->dev))
			goto drop;
	}
	return dst_input(skb);
drop:
	ax8netfilter_kfree_skb(skb);
	return NET_RX_DROP;
}

int xfrm4_rcv_encap(struct sk_buff *skb, int nexthdr, __be32 spi,
		    int encap_type)
{
	XFRM_SPI_SKB_CB(skb)->family = AF_INET;
	XFRM_SPI_SKB_CB(skb)->daddroff = offsetof(struct iphdr, daddr);
	return xfrm_input(skb, nexthdr, spi, encap_type);
}


int ax8netfilter_xfrm4_transport_finish(struct sk_buff *skb, int async)
{
	struct iphdr *iph = ip_hdr(skb);

	iph->protocol = XFRM_MODE_SKB_CB(skb)->protocol;

#ifndef CONFIG_AX8_NETFILTER
	if (!async)
		return -iph->protocol;
#endif

	__skb_push(skb, skb->data - skb_network_header(skb));
	iph->tot_len = htons(skb->len);
	ip_send_check(iph);

	NF_HOOK(PF_INET, NF_INET_PRE_ROUTING, skb, skb->dev, NULL,
		ax8netfilter_xfrm4_rcv_encap_finish);
	return 0;
}


