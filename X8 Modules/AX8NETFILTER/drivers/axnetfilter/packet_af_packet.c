/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		PACKET - implements raw packet sockets.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *
 * Fixes:
 *		Alan Cox	:	verify_area() now used correctly
 *		Alan Cox	:	new skbuff lists, look ma no backlogs!
 *		Alan Cox	:	tidied skbuff lists.
 *		Alan Cox	:	Now uses generic datagram routines I
 *					added. Also fixed the peek/read crash
 *					from all old Linux datagram code.
 *		Alan Cox	:	Uses the improved datagram code.
 *		Alan Cox	:	Added NULL's for socket options.
 *		Alan Cox	:	Re-commented the code.
 *		Alan Cox	:	Use new kernel side addressing
 *		Rob Janssen	:	Correct MTU usage.
 *		Dave Platt	:	Counter leaks caused by incorrect
 *					interrupt locking and some slightly
 *					dubious gcc output. Can you read
 *					compiler: it said _VOLATILE_
 *	Richard Kooijman	:	Timestamp fixes.
 *		Alan Cox	:	New buffers. Use sk->mac.raw.
 *		Alan Cox	:	sendmsg/recvmsg support.
 *		Alan Cox	:	Protocol setting support
 *	Alexey Kuznetsov	:	Untied from IPv4 stack.
 *	Cyrus Durgin		:	Fixed kerneld for kmod.
 *	Michal Ostrowski        :       Module initialization cleanup.
 *         Ulises Alonso        :       Frame number limit removal and
 *                                      packet_set_ring memory leak.
 *		Eric Biederman	:	Allow for > 8 byte hardware addresses.
 *					The convention is that longer addresses
 *					will simply extend the hardware address
 *					byte arrays at the end of sockaddr_ll
 *					and packet_mreq.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 */ 

#include <linux/skbuff.h> 
#include <linux/netdevice.h>
#include <net/sock.h>

struct ax8netfilter_packet_skb_cb {
	unsigned int origlen;
	union {
		struct sockaddr_pkt pkt;
		struct sockaddr_ll ll;
	} sa;
};

#define PACKET_SKB_CB(__skb)	((struct ax8netfilter_packet_skb_cb *)((__skb)->cb)) 

int ax8netfilter_packet_rcv_spkt(struct sk_buff *skb, struct net_device *dev,  struct packet_type *pt, struct net_device *orig_dev)
{
	struct sock *sk;
	struct sockaddr_pkt *spkt;

	/*
	 *	When we registered the protocol we saved the socket in the data
	 *	field for just this event.
	 */

	sk = pt->af_packet_priv;

	/*
	 *	Yank back the headers [hope the device set this
	 *	right or kerboom...]
	 *
	 *	Incoming packets have ll header pulled,
	 *	push it back.
	 *
	 *	For outgoing ones skb->data == skb_mac_header(skb)
	 *	so that this procedure is noop.
	 */

	if (skb->pkt_type == PACKET_LOOPBACK)
		goto out;

	if (dev_net(dev) != sock_net(sk))
		goto out;

	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
		goto oom;

	/* drop any routing info */
	dst_release(skb->dst);
	skb->dst = NULL;

	/* drop conntrack reference */
	nf_reset(skb);

	spkt = &PACKET_SKB_CB(skb)->sa.pkt;

	skb_push(skb, skb->data - skb_mac_header(skb));

	/*
	 *	The SOCK_PACKET socket receives _all_ frames.
	 */

	spkt->spkt_family = dev->type;
	strlcpy(spkt->spkt_device, dev->name, sizeof(spkt->spkt_device));
	spkt->spkt_protocol = skb->protocol;

	/*
	 *	Charge the memory to the socket. This is done specifically
	 *	to prevent sockets using all the memory up.
	 */

	if (sock_queue_rcv_skb(sk,skb) == 0)
		return 0;

out:
	kfree_skb(skb);
oom:
	return 0;
} 
