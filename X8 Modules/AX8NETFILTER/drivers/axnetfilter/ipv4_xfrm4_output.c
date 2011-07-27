/*
 * xfrm4_output.c - Common IPsec encapsulation code for IPv4.
 * Copyright (c) 2004 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/if_ether.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>
#include <net/dst.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/icmp.h>

#include "ax8netfilter.h"


static int ax8netfilter_xfrm4_output_finish(struct sk_buff *skb)
{
#ifdef CONFIG_AX8_NETFILTER
	if (!skb->dst->xfrm) {
		IPCB(skb)->flags |= IPSKB_REROUTED;
		return dst_output(skb);
	}

	IPCB(skb)->flags |= IPSKB_XFRM_TRANSFORMED;
#endif

	skb->protocol = htons(ETH_P_IP);
	return ax8netfilter_xfrm_output(skb);
}

int ax8netfilter_xfrm4_output(struct sk_buff *skb)
{
	return NF_HOOK_COND(PF_INET, NF_INET_POST_ROUTING, skb,
			    NULL, skb->dst->dev, ax8netfilter_xfrm4_output_finish,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}
