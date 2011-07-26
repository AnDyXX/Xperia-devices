/*
 * Author: AnDyX <AnDyX at xda-developers>
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 *  This module contains code from kernel required to initialise netfilter.  
 */
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mroute.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/pkt_sched.h>
#include <linux/netfilter_arp.h>
#include <linux/icmp.h>
#include <linux/netfilter_bridge.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/ip.h>
#include <net/transp_v6.h>
#include <net/xfrm.h>
#include <net/dst.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/raw.h>


#define AX_MODULE_NAME 			"ax8netfilter"
#define AX_MODULE_VER			"v001a"

#define DEVICE_NAME			"X8"
#define OFS_KALLSYMS_LOOKUP_NAME	0xC00B0654			// kallsyms_lookup_name

// from ip_sockglue.c
#define IP_CMSG_PKTINFO		1
#define IP_CMSG_TTL		2
#define IP_CMSG_TOS		4
#define IP_CMSG_RECVOPTS	8
#define IP_CMSG_RETOPTS		16
#define IP_CMSG_PASSSEC		32
#define IP_CMSG_ORIGDSTADDR     64

struct ax8netfilter_net init_ax8netfilter_net;
EXPORT_SYMBOL(init_ax8netfilter_net);

// for get proc address
typedef unsigned long (*kallsyms_lookup_name_type)(const char *name);
static kallsyms_lookup_name_type kallsyms_lookup_name_ax;

//unresolved symbols

//defs
typedef int (*ip_mc_msfget_type)(struct sock *sk, struct ip_msfilter *msf,
		struct ip_msfilter __user *optval, int __user *optlen);
typedef int (*ip_mc_source_type)(int add, int omode, struct sock *sk,
		struct ip_mreq_source *mreqs, int ifindex);
typedef int (*ip_options_get_from_user_type)(struct net *net, struct ip_options **optp,
				    unsigned char __user *data, int optlen);
typedef void (*ip_options_undo_type)(struct ip_options * opt);
typedef int	(*ip_ra_control_type)(struct sock *sk, unsigned char on, void (*destructor)(struct sock *));
typedef int (*ip_mc_leave_group_type)(struct sock *sk, struct ip_mreqn *imr);
typedef int (*ip_mc_gsfget_type)(struct sock *sk, struct group_filter *gsf,
		struct group_filter __user *optval, int __user *optlen);
typedef int (*ip_mc_msfilter_type)(struct sock *sk, struct ip_msfilter *msf,int ifindex);
typedef int (*ip_finish_output2_type)(struct sk_buff *skb);

typedef int (*ip_cmsg_send_type)(struct net *net, struct msghdr *msg, struct ipcm_cookie *ipc);
typedef void (*icmp_out_count_type)(struct net *net, unsigned char type);

typedef int (*ip_append_data_type)(struct sock *sk,
		   int getfrag(void *from, char *to, int offset, int len,
			       int odd, struct sk_buff *skb),
		   void *from, int length, int transhdrlen,
		   struct ipcm_cookie *ipc, struct rtable **rtp,
		   unsigned int flags); 
typedef void (*xfrm_replay_notify_type)(struct xfrm_state *x, int event);
typedef void (*ip_local_error_type)(struct sock *sk, int err, __be32 daddr, __be16 port, u32 info) ;
typedef void (*ip_flush_pending_frames_type)(struct sock *sk);
typedef void (*ip_forward_options_type)(struct sk_buff *skb);
typedef int (*ip_push_pending_frames_type)(struct sock *sk);
typedef int (*ip_call_ra_chain_type)(struct sk_buff *skb);
typedef int (*raw_local_deliver_type)(struct sk_buff *skb, int protocol);
typedef void (*ip_rt_send_redirect_type)(struct sk_buff *skb);

//declared types
static ip_mc_msfget_type ax8netfilter_ip_mc_msfget;
static ip_mc_source_type ax8netfilter_ip_mc_source;
static ip_options_get_from_user_type ax8netfilter_ip_options_get_from_user;
static ip_options_undo_type ax8netfilter_ip_options_undo;
static ip_ra_control_type ax8netfilter_ip_ra_control;
static ip_mc_leave_group_type ax8netfilter_ip_mc_leave_group;
static ip_mc_gsfget_type ax8netfilter_ip_mc_gsfget;
static ip_mc_msfilter_type ax8netfilter_ip_mc_msfilter;
static ip_finish_output2_type ax8netfilter_ip_finish_output2;

static ip_cmsg_send_type ax8netfilter_ip_cmsg_send;
static icmp_out_count_type ax8netfilter_icmp_out_count;
static ip_append_data_type ax8netfilter_ip_append_data;
static xfrm_replay_notify_type ax8netfilter_xfrm_replay_notify;
static ip_local_error_type ax8netfilter_ip_local_error;
static ip_flush_pending_frames_type ax8netfilter_ip_flush_pending_frames;
static ip_forward_options_type ax8netfilter_ip_forward_options;
static ip_push_pending_frames_type ax8netfilter_ip_push_pending_frames;
static ip_call_ra_chain_type ax8netfilter_ip_call_ra_chain;
static raw_local_deliver_type ax8netfilter_raw_local_deliver;
static ip_rt_send_redirect_type ax8netfilter_ip_rt_send_redirect;

static int *ax8netfilter_sysctl_igmp_max_msf;
static int *ax8netfilter_sysctl_ip_default_ttl;

//static struct net_protocol * ax8netfilter_inet_protos[MAX_INET_PROTOS] ____cacheline_aligned_in_smp;

static struct net_protocol ** ax8netfilter_inet_protos ____cacheline_aligned_in_smp;  

static void patch(unsigned int addr, unsigned int value) {
	*(unsigned int*)addr = value;
}

// patch to an jump obcode
static void patch_to_jmp(unsigned int addr, void * func) {
	int write_value;
	// calculate the offset
	write_value = ((((unsigned int)func - 8 - addr) >> 2) & 0x00FFFFFF);
	// add the unconditional jump opcode
	write_value |= 0xEA000000;
	// and patch it
	patch(addr, write_value);
}



/*********** HIJACKED METHODS ***************/
//from ip_options.c
/*
 *	Options "fragmenting", just fill options not
 *	allowed in fragments with NOOPs.
 *	Simple and stupid 8), but the most efficient way.
 */

void ax8netfilter_ip_options_fragment(struct sk_buff * skb)
{
	unsigned char *optptr = skb_network_header(skb) + sizeof(struct iphdr);
	struct ip_options * opt = &(IPCB(skb)->opt);
	int  l = opt->optlen;
	int  optlen;

	while (l > 0) {
		switch (*optptr) {
		case IPOPT_END:
			return;
		case IPOPT_NOOP:
			l--;
			optptr++;
			continue;
		}
		optlen = optptr[1];
		if (optlen<2 || optlen>l)
		  return;
		if (!IPOPT_COPIED(*optptr))
			memset(optptr, IPOPT_NOOP, optlen);
		l -= optlen;
		optptr += optlen;
	}
	opt->ts = 0;
	opt->rr = 0;
	opt->rr_needaddr = 0;
	opt->ts_needaddr = 0;
	opt->ts_needtime = 0;
	return;
}

//from ip_output.c
static inline int ax8netfilter_ip_skb_dst_mtu(struct sk_buff *skb)
{
	struct inet_sock *inet = skb->sk ? inet_sk(skb->sk) : NULL;

	return (inet && inet->pmtudisc == IP_PMTUDISC_PROBE) ?
	       skb->dst->dev->mtu : dst_mtu(skb->dst);
}

static void ax8netfilter_ip_copy_metadata(struct sk_buff *to, struct sk_buff *from)
{
	to->pkt_type = from->pkt_type;
	to->priority = from->priority;
	to->protocol = from->protocol;
	dst_release(to->dst);
	to->dst = dst_clone(from->dst);
	to->dev = from->dev;
	to->mark = from->mark;

	/* Copy the flags to each fragment. */
	IPCB(to)->flags = IPCB(from)->flags;

#ifdef CONFIG_NET_SCHED
	to->tc_index = from->tc_index;
#endif
	nf_copy(to, from);
#if defined(CONFIG_NETFILTER_XT_TARGET_TRACE) || \
    defined(CONFIG_NETFILTER_XT_TARGET_TRACE_MODULE)
	to->nf_trace = from->nf_trace;
#endif
#if defined(CONFIG_IP_VS) || defined(CONFIG_IP_VS_MODULE)
	to->ipvs_property = from->ipvs_property;
#endif
	skb_copy_secmark(to, from);
}

/*
 *	This IP datagram is too large to be sent in one piece.  Break it up into
 *	smaller pieces (each of size equal to IP header plus
 *	a block of the data of the original IP data part) that will yet fit in a
 *	single device frame, and queue such a frame for sending.
 */

int ax8netfilter_ip_fragment(struct sk_buff *skb, int (*output)(struct sk_buff *))
{
	struct iphdr *iph;
	int raw = 0;
	int ptr;
	struct net_device *dev;
	struct sk_buff *skb2;
	unsigned int mtu, hlen, left, len, ll_rs, pad;
	int offset;
	__be16 not_last_frag;
	struct rtable *rt = skb->rtable;
	int err = 0;

	dev = rt->u.dst.dev;

	/*
	 *	Point into the IP datagram header.
	 */

	iph = ip_hdr(skb);

	if (unlikely((iph->frag_off & htons(IP_DF)) && !skb->local_df)) {
		IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGFAILS);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(ax8netfilter_ip_skb_dst_mtu(skb)));
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	/*
	 *	Setup starting values.
	 */

	hlen = iph->ihl * 4;
	mtu = dst_mtu(&rt->u.dst) - hlen;	/* Size of data space */
	IPCB(skb)->flags |= IPSKB_FRAG_COMPLETE;

	/* When frag_list is given, use it. First, check its validity:
	 * some transformers could create wrong frag_list or break existing
	 * one, it is not prohibited. In this case fall back to copying.
	 *
	 * LATER: this step can be merged to real generation of fragments,
	 * we can switch to copy when see the first bad fragment.
	 */
	if (skb_shinfo(skb)->frag_list) {
		struct sk_buff *frag;
		int first_len = skb_pagelen(skb);
		int truesizes = 0;

		if (first_len - hlen > mtu ||
		    ((first_len - hlen) & 7) ||
		    (iph->frag_off & htons(IP_MF|IP_OFFSET)) ||
		    skb_cloned(skb))
			goto slow_path;

		for (frag = skb_shinfo(skb)->frag_list; frag; frag = frag->next) {
			/* Correct geometry. */
			if (frag->len > mtu ||
			    ((frag->len & 7) && frag->next) ||
			    skb_headroom(frag) < hlen)
			    goto slow_path;

			/* Partially cloned skb? */
			if (skb_shared(frag))
				goto slow_path;

			BUG_ON(frag->sk);
			if (skb->sk) {
				sock_hold(skb->sk);
				frag->sk = skb->sk;
				frag->destructor = sock_wfree;
				truesizes += frag->truesize;
			}
		}

		/* Everything is OK. Generate! */

		err = 0;
		offset = 0;
		frag = skb_shinfo(skb)->frag_list;
		skb_shinfo(skb)->frag_list = NULL;
		skb->data_len = first_len - skb_headlen(skb);
		skb->truesize -= truesizes;
		skb->len = first_len;
		iph->tot_len = htons(first_len);
		iph->frag_off = htons(IP_MF);
		ip_send_check(iph);

		for (;;) {
			/* Prepare header of the next frame,
			 * before previous one went down. */
			if (frag) {
				frag->ip_summed = CHECKSUM_NONE;
				skb_reset_transport_header(frag);
				__skb_push(frag, hlen);
				skb_reset_network_header(frag);
				memcpy(skb_network_header(frag), iph, hlen);
				iph = ip_hdr(frag);
				iph->tot_len = htons(frag->len);
				ax8netfilter_ip_copy_metadata(frag, skb);
				if (offset == 0)
					ax8netfilter_ip_options_fragment(frag);
				offset += skb->len - hlen;
				iph->frag_off = htons(offset>>3);
				if (frag->next != NULL)
					iph->frag_off |= htons(IP_MF);
				/* Ready, complete checksum */
				ip_send_check(iph);
			}

			err = output(skb);

			if (!err)
				IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGCREATES);
			if (err || !frag)
				break;

			skb = frag;
			frag = skb->next;
			skb->next = NULL;
		}

		if (err == 0) {
			IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGOKS);
			return 0;
		}

		while (frag) {
			skb = frag->next;
			kfree_skb(frag);
			frag = skb;
		}
		IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGFAILS);
		return err;
	}

slow_path:
	left = skb->len - hlen;		/* Space per frame */
	ptr = raw + hlen;		/* Where to start from */

	/* for bridged IP traffic encapsulated inside f.e. a vlan header,
	 * we need to make room for the encapsulating header
	 */
	pad = nf_bridge_pad(skb);
	ll_rs = LL_RESERVED_SPACE_EXTRA(rt->u.dst.dev, pad);
	mtu -= pad;

	/*
	 *	Fragment the datagram.
	 */

	offset = (ntohs(iph->frag_off) & IP_OFFSET) << 3;
	not_last_frag = iph->frag_off & htons(IP_MF);

	/*
	 *	Keep copying data until we run out.
	 */

	while (left > 0) {
		len = left;
		/* IF: it doesn't fit, use 'mtu' - the data space left */
		if (len > mtu)
			len = mtu;
		/* IF: we are not sending upto and including the packet end
		   then align the next start on an eight byte boundary */
		if (len < left)	{
			len &= ~7;
		}
		/*
		 *	Allocate buffer.
		 */

		if ((skb2 = alloc_skb(len+hlen+ll_rs, GFP_ATOMIC)) == NULL) {
			NETDEBUG(KERN_INFO "IP: frag: no memory for new fragment!\n");
			err = -ENOMEM;
			goto fail;
		}

		/*
		 *	Set up data on packet
		 */

		ax8netfilter_ip_copy_metadata(skb2, skb);
		skb_reserve(skb2, ll_rs);
		skb_put(skb2, len + hlen);
		skb_reset_network_header(skb2);
		skb2->transport_header = skb2->network_header + hlen;

		/*
		 *	Charge the memory for the fragment to any owner
		 *	it might possess
		 */

		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);

		/*
		 *	Copy the packet header into the new buffer.
		 */

		skb_copy_from_linear_data(skb, skb_network_header(skb2), hlen);

		/*
		 *	Copy a block of the IP datagram.
		 */
		if (skb_copy_bits(skb, ptr, skb_transport_header(skb2), len))
			BUG();
		left -= len;

		/*
		 *	Fill in the new header fields.
		 */
		iph = ip_hdr(skb2);
		iph->frag_off = htons((offset >> 3));

		/* ANK: dirty, but effective trick. Upgrade options only if
		 * the segment to be fragmented was THE FIRST (otherwise,
		 * options are already fixed) and make it ONCE
		 * on the initial skb, so that all the following fragments
		 * will inherit fixed options.
		 */
		if (offset == 0)
			ax8netfilter_ip_options_fragment(skb);

		/*
		 *	Added AC : If we are fragmenting a fragment that's not the
		 *		   last fragment then keep MF on each bit
		 */
		if (left > 0 || not_last_frag)
			iph->frag_off |= htons(IP_MF);
		ptr += len;
		offset += len;

		/*
		 *	Put this fragment into the sending queue.
		 */
		iph->tot_len = htons(len + hlen);

		ip_send_check(iph);

		err = output(skb2);
		if (err)
			goto fail;

		IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGCREATES);
	}
	kfree_skb(skb);
	IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGOKS);
	return err;

fail:
	kfree_skb(skb);
	IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGFAILS);
	return err;
}


//from skbuff.c
static void ax8_netfilter___copy_skb_header(struct sk_buff *new, const struct sk_buff *old)
{
	new->tstamp		= old->tstamp;
	new->dev		= old->dev;
	new->transport_header	= old->transport_header;
	new->network_header	= old->network_header;
	new->mac_header		= old->mac_header;
	new->dst		= dst_clone(old->dst);
#ifdef CONFIG_XFRM
	new->sp			= secpath_get(old->sp);
#endif
	memcpy(new->cb, old->cb, sizeof(old->cb));
	new->csum_start		= old->csum_start;
	new->csum_offset	= old->csum_offset;
	new->local_df		= old->local_df;
	new->pkt_type		= old->pkt_type;
	new->ip_summed		= old->ip_summed;
	skb_copy_queue_mapping(new, old);
	new->priority		= old->priority;
#if defined(CONFIG_IP_VS) || defined(CONFIG_IP_VS_MODULE)
	new->ipvs_property	= old->ipvs_property;
#endif
	new->protocol		= old->protocol;
	new->mark		= old->mark;
	__nf_copy(new, old);
#if defined(CONFIG_NETFILTER_XT_TARGET_TRACE) || \
    defined(CONFIG_NETFILTER_XT_TARGET_TRACE_MODULE)
	new->nf_trace		= old->nf_trace;
#endif
#ifdef CONFIG_NET_SCHED
	new->tc_index		= old->tc_index;
#ifdef CONFIG_NET_CLS_ACT
	new->tc_verd		= old->tc_verd;
#endif
#endif
	new->vlan_tci		= old->vlan_tci;

	skb_copy_secmark(new, old);
}
// from xfrm_output.c
int ax8netfilter_xfrm_output_resume(struct sk_buff *skb, int err);
static int ax8netfilter_xfrm_output2(struct sk_buff *skb)
{
	return ax8netfilter_xfrm_output_resume(skb, 1);
} 

static int ax8netfilter_xfrm_state_check_space(struct xfrm_state *x, struct sk_buff *skb)
{
	struct dst_entry *dst = skb->dst;
	int nhead = dst->header_len + LL_RESERVED_SPACE(dst->dev)
		- skb_headroom(skb);
	int ntail = dst->dev->needed_tailroom - skb_tailroom(skb);

	if (nhead <= 0) {
		if (ntail <= 0)
			return 0;
		nhead = 0;
	} else if (ntail < 0)
		ntail = 0;

	return pskb_expand_head(skb, nhead, ntail, GFP_ATOMIC);
} 

static int ax8netfilter_xfrm_output_one(struct sk_buff *skb, int err)
{
	struct dst_entry *dst = skb->dst;
	struct xfrm_state *x = dst->xfrm;
	struct net *net = xs_net(x);

	if (err <= 0)
		goto resume;

	do {
		err = ax8netfilter_xfrm_state_check_space(x, skb);
		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
			goto error_nolock;
		}

		err = x->outer_mode->output(x, skb);
		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEMODEERROR);
			goto error_nolock;
		}

		spin_lock_bh(&x->lock);
		err = xfrm_state_check_expire(x);
		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEEXPIRED);
			goto error;
		}

		if (x->type->flags & XFRM_TYPE_REPLAY_PROT) {
			XFRM_SKB_CB(skb)->seq.output = ++x->replay.oseq;
			if (unlikely(x->replay.oseq == 0)) {
				XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATESEQERROR);
				x->replay.oseq--;
				xfrm_audit_state_replay_overflow(x, skb);
				err = -EOVERFLOW;
				goto error;
			}
			if (xfrm_aevent_is_on(net))
				ax8netfilter_xfrm_replay_notify(x, XFRM_REPLAY_UPDATE);
		}

		x->curlft.bytes += skb->len;
		x->curlft.packets++;

		spin_unlock_bh(&x->lock);

		err = x->type->output(x, skb);
		if (err == -EINPROGRESS)
			goto out_exit;

resume:
		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEPROTOERROR);
			goto error_nolock;
		}

		if (!(skb->dst = dst_pop(dst))) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
			err = -EHOSTUNREACH;
			goto error_nolock;
		}
		dst = skb->dst;
		x = dst->xfrm;
	} while (x && !(x->outer_mode->flags & XFRM_MODE_FLAG_TUNNEL));

	err = 0;

out_exit:
	return err;
error:
	spin_unlock_bh(&x->lock);
error_nolock:
	kfree_skb(skb);
	goto out_exit;
} 

int ax8netfilter_xfrm_output_resume(struct sk_buff *skb, int err)
{
	while (likely((err = ax8netfilter_xfrm_output_one(skb, err)) == 0)) {
		nf_reset(skb);

		err = skb->dst->ops->local_out(skb);
		if (unlikely(err != 1))
			goto out;

		if (!skb->dst->xfrm)
			return dst_output(skb);

		err = nf_hook(skb->dst->ops->family,
			      NF_INET_POST_ROUTING, skb,
			      NULL, skb->dst->dev, ax8netfilter_xfrm_output2);
		if (unlikely(err != 1))
			goto out;
	}

	if (err == -EINPROGRESS)
		err = 0;

out:
	return err;
} 

// from raw.c
static int ax8netfilter_raw_send_hdrinc(struct sock *sk, void *from, size_t length,
			struct rtable *rt,
			unsigned int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct iphdr *iph;
	struct sk_buff *skb;
	unsigned int iphlen;
	int err;

	if (length > rt->u.dst.dev->mtu) {
		ax8netfilter_ip_local_error(sk, EMSGSIZE, rt->rt_dst, inet->dport,
			       rt->u.dst.dev->mtu);
		return -EMSGSIZE;
	}
	if (flags&MSG_PROBE)
		goto out;

	skb = sock_alloc_send_skb(sk,
				  length + LL_ALLOCATED_SPACE(rt->u.dst.dev) + 15,
				  flags & MSG_DONTWAIT, &err);
	if (skb == NULL)
		goto error;
	skb_reserve(skb, LL_RESERVED_SPACE(rt->u.dst.dev));

	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;
	skb->dst = dst_clone(&rt->u.dst);

	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	skb_put(skb, length);

	skb->ip_summed = CHECKSUM_NONE;

	skb->transport_header = skb->network_header;
	err = memcpy_fromiovecend((void *)iph, from, 0, length);
	if (err)
		goto error_fault;

	/* We don't modify invalid header */
	iphlen = iph->ihl * 4;
	if (iphlen >= sizeof(*iph) && iphlen <= length) {
		if (!iph->saddr)
			iph->saddr = rt->rt_src;
		iph->check   = 0;
		iph->tot_len = htons(length);
		if (!iph->id)
			ip_select_ident(iph, &rt->u.dst, NULL);

		iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
	}
	if (iph->protocol == IPPROTO_ICMP)
		ax8netfilter_icmp_out_count(net, ((struct icmphdr *)
			skb_transport_header(skb))->type);

	err = NF_HOOK(PF_INET, NF_INET_LOCAL_OUT, skb, NULL, rt->u.dst.dev,
		      dst_output);
	if (err > 0)
		err = inet->recverr ? net_xmit_errno(err) : 0;
	if (err)
		goto error;
out:
	return 0;

error_fault:
	err = -EFAULT;
	kfree_skb(skb);
error:
	IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
	return err;
} 

static int ax8netfilter_raw_probe_proto_opt(struct flowi *fl, struct msghdr *msg)
{
	struct iovec *iov;
	u8 __user *type = NULL;
	u8 __user *code = NULL;
	int probed = 0;
	unsigned int i;

	if (!msg->msg_iov)
		return 0;

	for (i = 0; i < msg->msg_iovlen; i++) {
		iov = &msg->msg_iov[i];
		if (!iov)
			continue;

		switch (fl->proto) {
		case IPPROTO_ICMP:
			/* check if one-byte field is readable or not. */
			if (iov->iov_base && iov->iov_len < 1)
				break;

			if (!type) {
				type = iov->iov_base;
				/* check if code field is readable or not. */
				if (iov->iov_len > 1)
					code = type + 1;
			} else if (!code)
				code = iov->iov_base;

			if (type && code) {
				if (get_user(fl->fl_icmp_type, type) ||
				    get_user(fl->fl_icmp_code, code))
					return -EFAULT;
				probed = 1;
			}
			break;
		default:
			probed = 1;
			break;
		}
		if (probed)
			break;
	}
	return 0;
} 

static int ax8netfilter_raw_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		       size_t len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	int free = 0;
	__be32 daddr;
	__be32 saddr;
	u8  tos;
	int err;

	err = -EMSGSIZE;
	if (len > 0xFFFF)
		goto out;

	/*
	 *	Check the flags.
	 */

	err = -EOPNOTSUPP;
	if (msg->msg_flags & MSG_OOB)	/* Mirror BSD error message */
		goto out;               /* compatibility */

	/*
	 *	Get and verify the address.
	 */

	if (msg->msg_namelen) {
		struct sockaddr_in *usin = (struct sockaddr_in *)msg->msg_name;
		err = -EINVAL;
		if (msg->msg_namelen < sizeof(*usin))
			goto out;
		if (usin->sin_family != AF_INET) {
			static int complained;
			if (!complained++)
				printk(KERN_INFO "%s forgot to set AF_INET in "
						 "raw sendmsg. Fix it!\n",
						 current->comm);
			err = -EAFNOSUPPORT;
			if (usin->sin_family)
				goto out;
		}
		daddr = usin->sin_addr.s_addr;
		/* ANK: I did not forget to get protocol from port field.
		 * I just do not know, who uses this weirdness.
		 * IP_HDRINCL is much more convenient.
		 */
	} else {
		err = -EDESTADDRREQ;
		if (sk->sk_state != TCP_ESTABLISHED)
			goto out;
		daddr = inet->daddr;
	}

	ipc.addr = inet->saddr;
	ipc.opt = NULL;
	ipc.oif = sk->sk_bound_dev_if;

	if (msg->msg_controllen) {
		err = ax8netfilter_ip_cmsg_send(sock_net(sk), msg, &ipc);
		if (err)
			goto out;
		if (ipc.opt)
			free = 1;
	}

	saddr = ipc.addr;
	ipc.addr = daddr;

	if (!ipc.opt)
		ipc.opt = inet->opt;

	if (ipc.opt) {
		err = -EINVAL;
		/* Linux does not mangle headers on raw sockets,
		 * so that IP options + IP_HDRINCL is non-sense.
		 */
		if (inet->hdrincl)
			goto done;
		if (ipc.opt->srr) {
			if (!daddr)
				goto done;
			daddr = ipc.opt->faddr;
		}
	}
	tos = RT_CONN_FLAGS(sk);
	if (msg->msg_flags & MSG_DONTROUTE)
		tos |= RTO_ONLINK;

	if (ipv4_is_multicast(daddr)) {
		if (!ipc.oif)
			ipc.oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
	}

	{
		struct flowi fl = { .oif = ipc.oif,
				    .mark = sk->sk_mark,
				    .nl_u = { .ip4_u =
					      { .daddr = daddr,
						.saddr = saddr,
						.tos = tos } },
				    .proto = inet->hdrincl ? IPPROTO_RAW :
							     sk->sk_protocol,
				  };
		if (!inet->hdrincl) {
			err = ax8netfilter_raw_probe_proto_opt(&fl, msg);
			if (err)
				goto done;
		}

		security_sk_classify_flow(sk, &fl);
		err = ip_route_output_flow(sock_net(sk), &rt, &fl, sk, 1);
	}
	if (err)
		goto done;

	err = -EACCES;
	if (rt->rt_flags & RTCF_BROADCAST && !sock_flag(sk, SOCK_BROADCAST))
		goto done;

	if (msg->msg_flags & MSG_CONFIRM)
		goto do_confirm;
back_from_confirm:

	if (inet->hdrincl)
		err = ax8netfilter_raw_send_hdrinc(sk, msg->msg_iov, len,
					rt, msg->msg_flags);

	 else {
		if (!ipc.addr)
			ipc.addr = rt->rt_dst;
		lock_sock(sk);
		err = ax8netfilter_ip_append_data(sk, ip_generic_getfrag, msg->msg_iov, len, 0,
					&ipc, &rt, msg->msg_flags);
		if (err)
			ax8netfilter_ip_flush_pending_frames(sk);
		else if (!(msg->msg_flags & MSG_MORE))
			err = ax8netfilter_ip_push_pending_frames(sk);
		release_sock(sk);
	}
done:
	if (free)
		kfree(ipc.opt);
	ip_rt_put(rt);

out:
	if (err < 0)
		return err;
	return len;

do_confirm:
	dst_confirm(&rt->u.dst);
	if (!(msg->msg_flags & MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto done;
} 

//from ip_output.c
/* dev_loopback_xmit for use with netfilter. */
static int ax8netfilter_ip_dev_loopback_xmit(struct sk_buff *newskb)
{
	skb_reset_mac_header(newskb);
	__skb_pull(newskb, skb_network_offset(newskb));
	newskb->pkt_type = PACKET_LOOPBACK;
	newskb->ip_summed = CHECKSUM_UNNECESSARY;
	WARN_ON(!newskb->dst);
	netif_rx(newskb);
	return 0;
} 

static int ax8netfilter_ip_finish_output(struct sk_buff *skb);
int ax8netfilter_ip_mc_output(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct rtable *rt = skb->rtable;
	struct net_device *dev = rt->u.dst.dev;

	/*
	 *	If the indicated interface is up and running, send the packet.
	 */
	IP_INC_STATS(dev_net(dev), IPSTATS_MIB_OUTREQUESTS);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	/*
	 *	Multicasts are looped back for other local users
	 */

	if (rt->rt_flags&RTCF_MULTICAST) {
		if ((!sk || inet_sk(sk)->mc_loop)
#ifdef CONFIG_IP_MROUTE
		/* Small optimization: do not loopback not local frames,
		   which returned after forwarding; they will be  dropped
		   by ip_mr_input in any case.
		   Note, that local frames are looped back to be delivered
		   to local recipients.

		   This check is duplicated in ip_mr_input at the moment.
		 */
		    && ((rt->rt_flags&RTCF_LOCAL) || !(IPCB(skb)->flags&IPSKB_FORWARDED))
#endif
		) {
			struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
			if (newskb)
				NF_HOOK(PF_INET, NF_INET_POST_ROUTING, newskb,
					NULL, newskb->dev,
					ax8netfilter_ip_dev_loopback_xmit);
		}

		/* Multicasts with ttl 0 must not go beyond the host */

		if (ip_hdr(skb)->ttl == 0) {
			kfree_skb(skb);
			return 0;
		}
	}

	if (rt->rt_flags&RTCF_BROADCAST) {
		struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
		if (newskb)
			NF_HOOK(PF_INET, NF_INET_POST_ROUTING, newskb, NULL,
				newskb->dev, ax8netfilter_ip_dev_loopback_xmit);
	}

	return NF_HOOK_COND(PF_INET, NF_INET_POST_ROUTING, skb, NULL, skb->dev,
			    ax8netfilter_ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}

int ax8netfilter_ip_output(struct sk_buff *skb)
{
	struct net_device *dev = skb->dst->dev;

	IP_INC_STATS(dev_net(dev), IPSTATS_MIB_OUTREQUESTS);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	return NF_HOOK_COND(PF_INET, NF_INET_POST_ROUTING, skb, NULL, dev,
			    ax8netfilter_ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
} 

/* Generate a checksum for an outgoing IP datagram. */
__inline__ void ax8netfilter_ip_send_check(struct iphdr *iph)
{
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

int ax8netfilter___ip_local_out(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	iph->tot_len = htons(skb->len);
	ax8netfilter_ip_send_check(iph);
	return nf_hook(PF_INET, NF_INET_LOCAL_OUT, skb, NULL, skb->dst->dev,
		       dst_output);
}

int ax8netfilter_ip_local_out(struct sk_buff *skb)
{
	int err;

	err = ax8netfilter___ip_local_out(skb);
	if (likely(err == 1))
		err = dst_output(skb);

	return err;
} 

//from ip_input.c
static int ax8netfilter_ip_local_deliver_finish(struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);

	__skb_pull(skb, ip_hdrlen(skb));

	/* Point into the IP datagram, just past the header. */
	skb_reset_transport_header(skb);

	rcu_read_lock();
	{
		int protocol = ip_hdr(skb)->protocol;
		int hash, raw;
		struct net_protocol *ipprot;

	resubmit:
		raw = ax8netfilter_raw_local_deliver(skb, protocol);

		hash = protocol & (MAX_INET_PROTOS - 1);
		ipprot = rcu_dereference(ax8netfilter_inet_protos[hash]);
		if (ipprot != NULL) {
			int ret;

			if (!net_eq(net, &init_net) && !ipprot->netns_ok) {
				if (net_ratelimit())
					printk("%s: proto %d isn't netns-ready\n",
						__func__, protocol);
				kfree_skb(skb);
				goto out;
			}

			if (!ipprot->no_policy) {
				if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					kfree_skb(skb);
					goto out;
				}
				nf_reset(skb);
			}
			ret = ipprot->handler(skb);
			if (ret < 0) {
				protocol = -ret;
				goto resubmit;
			}
			IP_INC_STATS_BH(net, IPSTATS_MIB_INDELIVERS);
		} else {
			if (!raw) {
				if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					IP_INC_STATS_BH(net, IPSTATS_MIB_INUNKNOWNPROTOS);
					icmp_send(skb, ICMP_DEST_UNREACH,
						  ICMP_PROT_UNREACH, 0);
				}
			} else
				IP_INC_STATS_BH(net, IPSTATS_MIB_INDELIVERS);
			kfree_skb(skb);
		}
	}
 out:
	rcu_read_unlock();

	return 0;
} 

/*
 * 	Deliver IP Packets to the higher protocol layers.
 */
int ax8netfilter_ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */

	if (ip_hdr(skb)->frag_off & htons(IP_MF | IP_OFFSET)) {
		if (ip_defrag(skb, IP_DEFRAG_LOCAL_DELIVER))
			return 0;
	}

	return NF_HOOK(PF_INET, NF_INET_LOCAL_IN, skb, skb->dev, NULL,
		       ax8netfilter_ip_local_deliver_finish);
} 



//from ip_forward.c
static int ax8netfilter_ip_forward_finish(struct sk_buff *skb)
{
	struct ip_options * opt	= &(IPCB(skb)->opt);

	IP_INC_STATS_BH(dev_net(skb->dst->dev), IPSTATS_MIB_OUTFORWDATAGRAMS);

	if (unlikely(opt->optlen))
		ax8netfilter_ip_forward_options(skb);

	return dst_output(skb);
} 

int ax8netfilter_ip_forward(struct sk_buff *skb)
{
	struct iphdr *iph;	/* Our header */
	struct rtable *rt;	/* Route we use */
	struct ip_options * opt	= &(IPCB(skb)->opt);

	if (skb_warn_if_lro(skb))
		goto drop;

	if (!xfrm4_policy_check(NULL, XFRM_POLICY_FWD, skb))
		goto drop;

	if (IPCB(skb)->opt.router_alert && ax8netfilter_ip_call_ra_chain(skb))
		return NET_RX_SUCCESS;

	if (skb->pkt_type != PACKET_HOST)
		goto drop;

	skb_forward_csum(skb);

	/*
	 *	According to the RFC, we must first decrease the TTL field. If
	 *	that reaches zero, we must reply an ICMP control message telling
	 *	that the packet's lifetime expired.
	 */
	if (ip_hdr(skb)->ttl <= 1)
		goto too_many_hops;

	if (!xfrm4_route_forward(skb))
		goto drop;

	rt = skb->rtable;

	if (opt->is_strictroute && rt->rt_dst != rt->rt_gateway)
		goto sr_failed;

	if (unlikely(skb->len > dst_mtu(&rt->u.dst) && !skb_is_gso(skb) &&
		     (ip_hdr(skb)->frag_off & htons(IP_DF))) && !skb->local_df) {
		IP_INC_STATS(dev_net(rt->u.dst.dev), IPSTATS_MIB_FRAGFAILS);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(dst_mtu(&rt->u.dst)));
		goto drop;
	}

	/* We are about to mangle packet. Copy it! */
	if (skb_cow(skb, LL_RESERVED_SPACE(rt->u.dst.dev)+rt->u.dst.header_len))
		goto drop;
	iph = ip_hdr(skb);

	/* Decrease ttl after skb cow done */
	ip_decrease_ttl(iph);

	/*
	 *	We now generate an ICMP HOST REDIRECT giving the route
	 *	we calculated.
	 */
	if (rt->rt_flags&RTCF_DOREDIRECT && !opt->srr && !skb_sec_path(skb))
		ax8netfilter_ip_rt_send_redirect(skb);

	skb->priority = rt_tos2priority(iph->tos);

	return NF_HOOK(PF_INET, NF_INET_FORWARD, skb, skb->dev, rt->u.dst.dev,
		       ax8netfilter_ip_forward_finish);

sr_failed:
	/*
	 *	Strict routing permits no gatewaying
	 */
	 icmp_send(skb, ICMP_DEST_UNREACH, ICMP_SR_FAILED, 0);
	 goto drop;

too_many_hops:
	/* Tell the sender its packet died... */
	IP_INC_STATS_BH(dev_net(skb->dst->dev), IPSTATS_MIB_INHDRERRORS);
	icmp_send(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
} 


// from arp.c

/*
 *	Send an arp packet.
 */
void ax8netfilter_arp_xmit(struct sk_buff *skb)
{
	/* Send it off, maybe filter it using firewalling first.  */
	NF_HOOK(NFPROTO_ARP, NF_ARP_OUT, skb, NULL, skb->dev, dev_queue_xmit);
} 


// from route.c --------------------------
#define ECN_OR_COST(class)	TC_PRIO_##class

const __u8 ip_tos2prio[16] = {
	TC_PRIO_BESTEFFORT,
	ECN_OR_COST(FILLER),
	TC_PRIO_BESTEFFORT,
	ECN_OR_COST(BESTEFFORT),
	TC_PRIO_BULK,
	ECN_OR_COST(BULK),
	TC_PRIO_BULK,
	ECN_OR_COST(BULK),
	TC_PRIO_INTERACTIVE,
	ECN_OR_COST(INTERACTIVE),
	TC_PRIO_INTERACTIVE,
	ECN_OR_COST(INTERACTIVE),
	TC_PRIO_INTERACTIVE_BULK,
	ECN_OR_COST(INTERACTIVE_BULK),
	TC_PRIO_INTERACTIVE_BULK,
	ECN_OR_COST(INTERACTIVE_BULK)
};

static char ax8netfilter_rt_tos2priority(u8 tos)
{
	return ip_tos2prio[IPTOS_TOS(tos)>>1];
}

//---------------------------------------

static int ax8netfilter_xfrm4_rcv_encap_finish(struct sk_buff *skb)
{
	if (skb->dst == NULL) {
		const struct iphdr *iph = ip_hdr(skb);

		if (ip_route_input(skb, iph->daddr, iph->saddr, iph->tos,
				   skb->dev))
			goto drop;
	}
	return dst_input(skb);
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

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
	return xfrm_output(skb);
}

int ax8netfilter_xfrm4_output(struct sk_buff *skb)
{
	return NF_HOOK_COND(PF_INET, NF_INET_POST_ROUTING, skb,
			    NULL, skb->dst->dev, ax8netfilter_xfrm4_output_finish,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
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

static int ax8netfilter_ip_finish_output(struct sk_buff *skb)
{
#if defined(CONFIG_AX8_NETFILTER) && defined(CONFIG_XFRM)
	/* Policy lookup after SNAT yielded a new policy */
	if (skb->dst->xfrm != NULL) {
		IPCB(skb)->flags |= IPSKB_REROUTED;
		return dst_output(skb);
	}
#endif
	if (skb->len > ax8netfilter_ip_skb_dst_mtu(skb) && !skb_is_gso(skb))
		return ip_fragment(skb, ax8netfilter_ip_finish_output2);
	else
		return ax8netfilter_ip_finish_output2(skb);
}


/*
 *	Socket option code for IP. This is the end of the line after any TCP,UDP etc options on
 *	an IP socket.
 */


static int ax8netfilter_do_ip_setsockopt(struct sock *sk, int level,
			    int optname, char __user *optval, int optlen)
{
	struct inet_sock *inet = inet_sk(sk);
	int val = 0, err;

	if (((1<<optname) & ((1<<IP_PKTINFO) | (1<<IP_RECVTTL) |
			     (1<<IP_RECVOPTS) | (1<<IP_RECVTOS) |
			     (1<<IP_RETOPTS) | (1<<IP_TOS) |
			     (1<<IP_TTL) | (1<<IP_HDRINCL) |
			     (1<<IP_MTU_DISCOVER) | (1<<IP_RECVERR) |
			     (1<<IP_ROUTER_ALERT) | (1<<IP_FREEBIND) |
			     (1<<IP_PASSSEC) | (1<<IP_TRANSPARENT))) ||
	    optname == IP_MULTICAST_TTL ||
	    optname == IP_MULTICAST_LOOP ||
	    optname == IP_RECVORIGDSTADDR) {
		if (optlen >= sizeof(int)) {
			if (get_user(val, (int __user *) optval))
				return -EFAULT;
		} else if (optlen >= sizeof(char)) {
			unsigned char ucval;

			if (get_user(ucval, (unsigned char __user *) optval))
				return -EFAULT;
			val = (int) ucval;
		}
	}

	/* If optlen==0, it is equivalent to val == 0 */

	if (ip_mroute_opt(optname))
		return ip_mroute_setsockopt(sk, optname, optval, optlen);

	err = 0;
	lock_sock(sk);

	switch (optname) {
	case IP_OPTIONS:
	{
		struct ip_options * opt = NULL;
		if (optlen > 40 || optlen < 0)
			goto e_inval;
		err = ax8netfilter_ip_options_get_from_user(sock_net(sk), &opt,
					       optval, optlen);
		if (err)
			break;
		if (inet->is_icsk) {
			struct inet_connection_sock *icsk = inet_csk(sk);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
			if (sk->sk_family == PF_INET ||
			    (!((1 << sk->sk_state) &
			       (TCPF_LISTEN | TCPF_CLOSE)) &&
			     inet->daddr != LOOPBACK4_IPV6)) {
#endif
				if (inet->opt)
					icsk->icsk_ext_hdr_len -= inet->opt->optlen;
				if (opt)
					icsk->icsk_ext_hdr_len += opt->optlen;
				icsk->icsk_sync_mss(sk, icsk->icsk_pmtu_cookie);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
			}
#endif
		}
		opt = xchg(&inet->opt, opt);
		kfree(opt);
		break;
	}
	case IP_PKTINFO:
		if (val)
			inet->cmsg_flags |= IP_CMSG_PKTINFO;
		else
			inet->cmsg_flags &= ~IP_CMSG_PKTINFO;
		break;
	case IP_RECVTTL:
		if (val)
			inet->cmsg_flags |=  IP_CMSG_TTL;
		else
			inet->cmsg_flags &= ~IP_CMSG_TTL;
		break;
	case IP_RECVTOS:
		if (val)
			inet->cmsg_flags |=  IP_CMSG_TOS;
		else
			inet->cmsg_flags &= ~IP_CMSG_TOS;
		break;
	case IP_RECVOPTS:
		if (val)
			inet->cmsg_flags |=  IP_CMSG_RECVOPTS;
		else
			inet->cmsg_flags &= ~IP_CMSG_RECVOPTS;
		break;
	case IP_RETOPTS:
		if (val)
			inet->cmsg_flags |= IP_CMSG_RETOPTS;
		else
			inet->cmsg_flags &= ~IP_CMSG_RETOPTS;
		break;
	case IP_PASSSEC:
		if (val)
			inet->cmsg_flags |= IP_CMSG_PASSSEC;
		else
			inet->cmsg_flags &= ~IP_CMSG_PASSSEC;
		break;
	case IP_RECVORIGDSTADDR:
		if (val)
			inet->cmsg_flags |= IP_CMSG_ORIGDSTADDR;
		else
			inet->cmsg_flags &= ~IP_CMSG_ORIGDSTADDR;
		break;
	case IP_TOS:	/* This sets both TOS and Precedence */
		if (sk->sk_type == SOCK_STREAM) {
			val &= ~3;
			val |= inet->tos & 3;
		}
		if (inet->tos != val) {
			inet->tos = val;
			sk->sk_priority = ax8netfilter_rt_tos2priority(val);
			sk_dst_reset(sk);
		}
		break;
	case IP_TTL:
		if (optlen<1)
			goto e_inval;
		if (val != -1 && (val < 1 || val>255))
			goto e_inval;
		inet->uc_ttl = val;
		break;
	case IP_HDRINCL:
		if (sk->sk_type != SOCK_RAW) {
			err = -ENOPROTOOPT;
			break;
		}
		inet->hdrincl = val ? 1 : 0;
		break;
	case IP_MTU_DISCOVER:
		if (val<0 || val>3)
			goto e_inval;
		inet->pmtudisc = val;
		break;
	case IP_RECVERR:
		inet->recverr = !!val;
		if (!val)
			skb_queue_purge(&sk->sk_error_queue);
		break;
	case IP_MULTICAST_TTL:
		if (sk->sk_type == SOCK_STREAM)
			goto e_inval;
		if (optlen<1)
			goto e_inval;
		if (val == -1)
			val = 1;
		if (val < 0 || val > 255)
			goto e_inval;
		inet->mc_ttl = val;
		break;
	case IP_MULTICAST_LOOP:
		if (optlen<1)
			goto e_inval;
		inet->mc_loop = !!val;
		break;
	case IP_MULTICAST_IF:
	{
		struct ip_mreqn mreq;
		struct net_device *dev = NULL;

		if (sk->sk_type == SOCK_STREAM)
			goto e_inval;
		/*
		 *	Check the arguments are allowable
		 */

		err = -EFAULT;
		if (optlen >= sizeof(struct ip_mreqn)) {
			if (copy_from_user(&mreq, optval, sizeof(mreq)))
				break;
		} else {
			memset(&mreq, 0, sizeof(mreq));
			if (optlen >= sizeof(struct in_addr) &&
			    copy_from_user(&mreq.imr_address, optval, sizeof(struct in_addr)))
				break;
		}

		if (!mreq.imr_ifindex) {
			if (mreq.imr_address.s_addr == htonl(INADDR_ANY)) {
				inet->mc_index = 0;
				inet->mc_addr  = 0;
				err = 0;
				break;
			}
			dev = ip_dev_find(sock_net(sk), mreq.imr_address.s_addr);
			if (dev) {
				mreq.imr_ifindex = dev->ifindex;
				dev_put(dev);
			}
		} else
			dev = __dev_get_by_index(sock_net(sk), mreq.imr_ifindex);


		err = -EADDRNOTAVAIL;
		if (!dev)
			break;

		err = -EINVAL;
		if (sk->sk_bound_dev_if &&
		    mreq.imr_ifindex != sk->sk_bound_dev_if)
			break;

		inet->mc_index = mreq.imr_ifindex;
		inet->mc_addr  = mreq.imr_address.s_addr;
		err = 0;
		break;
	}

	case IP_ADD_MEMBERSHIP:
	case IP_DROP_MEMBERSHIP:
	{
		struct ip_mreqn mreq;

		err = -EPROTO;
		if (inet_sk(sk)->is_icsk)
			break;

		if (optlen < sizeof(struct ip_mreq))
			goto e_inval;
		err = -EFAULT;
		if (optlen >= sizeof(struct ip_mreqn)) {
			if (copy_from_user(&mreq, optval, sizeof(mreq)))
				break;
		} else {
			memset(&mreq, 0, sizeof(mreq));
			if (copy_from_user(&mreq, optval, sizeof(struct ip_mreq)))
				break;
		}

		if (optname == IP_ADD_MEMBERSHIP)
			err = ip_mc_join_group(sk, &mreq);
		else
			err = ax8netfilter_ip_mc_leave_group(sk, &mreq);
		break;
	}
	case IP_MSFILTER:
	{
		//extern int sysctl_igmp_max_msf;
		struct ip_msfilter *msf;

		if (optlen < IP_MSFILTER_SIZE(0))
			goto e_inval;
		if (optlen > sysctl_optmem_max) {
			err = -ENOBUFS;
			break;
		}
		msf = kmalloc(optlen, GFP_KERNEL);
		if (!msf) {
			err = -ENOBUFS;
			break;
		}
		err = -EFAULT;
		if (copy_from_user(msf, optval, optlen)) {
			kfree(msf);
			break;
		}
		/* numsrc >= (1G-4) overflow in 32 bits */
		if (msf->imsf_numsrc >= 0x3ffffffcU ||
		    msf->imsf_numsrc > (*ax8netfilter_sysctl_igmp_max_msf)) {
			kfree(msf);
			err = -ENOBUFS;
			break;
		}
		if (IP_MSFILTER_SIZE(msf->imsf_numsrc) > optlen) {
			kfree(msf);
			err = -EINVAL;
			break;
		}
		err = ax8netfilter_ip_mc_msfilter(sk, msf, 0);
		kfree(msf);
		break;
	}
	case IP_BLOCK_SOURCE:
	case IP_UNBLOCK_SOURCE:
	case IP_ADD_SOURCE_MEMBERSHIP:
	case IP_DROP_SOURCE_MEMBERSHIP:
	{
		struct ip_mreq_source mreqs;
		int omode, add;

		if (optlen != sizeof(struct ip_mreq_source))
			goto e_inval;
		if (copy_from_user(&mreqs, optval, sizeof(mreqs))) {
			err = -EFAULT;
			break;
		}
		if (optname == IP_BLOCK_SOURCE) {
			omode = MCAST_EXCLUDE;
			add = 1;
		} else if (optname == IP_UNBLOCK_SOURCE) {
			omode = MCAST_EXCLUDE;
			add = 0;
		} else if (optname == IP_ADD_SOURCE_MEMBERSHIP) {
			struct ip_mreqn mreq;

			mreq.imr_multiaddr.s_addr = mreqs.imr_multiaddr;
			mreq.imr_address.s_addr = mreqs.imr_interface;
			mreq.imr_ifindex = 0;
			err = ip_mc_join_group(sk, &mreq);
			if (err && err != -EADDRINUSE)
				break;
			omode = MCAST_INCLUDE;
			add = 1;
		} else /* IP_DROP_SOURCE_MEMBERSHIP */ {
			omode = MCAST_INCLUDE;
			add = 0;
		}
		err = ax8netfilter_ip_mc_source(add, omode, sk, &mreqs, 0);
		break;
	}
	case MCAST_JOIN_GROUP:
	case MCAST_LEAVE_GROUP:
	{
		struct group_req greq;
		struct sockaddr_in *psin;
		struct ip_mreqn mreq;

		if (optlen < sizeof(struct group_req))
			goto e_inval;
		err = -EFAULT;
		if (copy_from_user(&greq, optval, sizeof(greq)))
			break;
		psin = (struct sockaddr_in *)&greq.gr_group;
		if (psin->sin_family != AF_INET)
			goto e_inval;
		memset(&mreq, 0, sizeof(mreq));
		mreq.imr_multiaddr = psin->sin_addr;
		mreq.imr_ifindex = greq.gr_interface;

		if (optname == MCAST_JOIN_GROUP)
			err = ip_mc_join_group(sk, &mreq);
		else
			err = ax8netfilter_ip_mc_leave_group(sk, &mreq);
		break;
	}
	case MCAST_JOIN_SOURCE_GROUP:
	case MCAST_LEAVE_SOURCE_GROUP:
	case MCAST_BLOCK_SOURCE:
	case MCAST_UNBLOCK_SOURCE:
	{
		struct group_source_req greqs;
		struct ip_mreq_source mreqs;
		struct sockaddr_in *psin;
		int omode, add;

		if (optlen != sizeof(struct group_source_req))
			goto e_inval;
		if (copy_from_user(&greqs, optval, sizeof(greqs))) {
			err = -EFAULT;
			break;
		}
		if (greqs.gsr_group.ss_family != AF_INET ||
		    greqs.gsr_source.ss_family != AF_INET) {
			err = -EADDRNOTAVAIL;
			break;
		}
		psin = (struct sockaddr_in *)&greqs.gsr_group;
		mreqs.imr_multiaddr = psin->sin_addr.s_addr;
		psin = (struct sockaddr_in *)&greqs.gsr_source;
		mreqs.imr_sourceaddr = psin->sin_addr.s_addr;
		mreqs.imr_interface = 0; /* use index for mc_source */

		if (optname == MCAST_BLOCK_SOURCE) {
			omode = MCAST_EXCLUDE;
			add = 1;
		} else if (optname == MCAST_UNBLOCK_SOURCE) {
			omode = MCAST_EXCLUDE;
			add = 0;
		} else if (optname == MCAST_JOIN_SOURCE_GROUP) {
			struct ip_mreqn mreq;

			psin = (struct sockaddr_in *)&greqs.gsr_group;
			mreq.imr_multiaddr = psin->sin_addr;
			mreq.imr_address.s_addr = 0;
			mreq.imr_ifindex = greqs.gsr_interface;
			err = ip_mc_join_group(sk, &mreq);
			if (err && err != -EADDRINUSE)
				break;
			greqs.gsr_interface = mreq.imr_ifindex;
			omode = MCAST_INCLUDE;
			add = 1;
		} else /* MCAST_LEAVE_SOURCE_GROUP */ {
			omode = MCAST_INCLUDE;
			add = 0;
		}
		err = ax8netfilter_ip_mc_source(add, omode, sk, &mreqs,
				   greqs.gsr_interface);
		break;
	}
	case MCAST_MSFILTER:
	{
		//extern int sysctl_igmp_max_msf;
		struct sockaddr_in *psin;
		struct ip_msfilter *msf = NULL;
		struct group_filter *gsf = NULL;
		int msize, i, ifindex;

		if (optlen < GROUP_FILTER_SIZE(0))
			goto e_inval;
		if (optlen > sysctl_optmem_max) {
			err = -ENOBUFS;
			break;
		}
		gsf = kmalloc(optlen, GFP_KERNEL);
		if (!gsf) {
			err = -ENOBUFS;
			break;
		}
		err = -EFAULT;
		if (copy_from_user(gsf, optval, optlen)) {
			goto mc_msf_out;
		}
		/* numsrc >= (4G-140)/128 overflow in 32 bits */
		if (gsf->gf_numsrc >= 0x1ffffff ||
		    gsf->gf_numsrc > (*ax8netfilter_sysctl_igmp_max_msf)) {
			err = -ENOBUFS;
			goto mc_msf_out;
		}
		if (GROUP_FILTER_SIZE(gsf->gf_numsrc) > optlen) {
			err = -EINVAL;
			goto mc_msf_out;
		}
		msize = IP_MSFILTER_SIZE(gsf->gf_numsrc);
		msf = kmalloc(msize, GFP_KERNEL);
		if (!msf) {
			err = -ENOBUFS;
			goto mc_msf_out;
		}
		ifindex = gsf->gf_interface;
		psin = (struct sockaddr_in *)&gsf->gf_group;
		if (psin->sin_family != AF_INET) {
			err = -EADDRNOTAVAIL;
			goto mc_msf_out;
		}
		msf->imsf_multiaddr = psin->sin_addr.s_addr;
		msf->imsf_interface = 0;
		msf->imsf_fmode = gsf->gf_fmode;
		msf->imsf_numsrc = gsf->gf_numsrc;
		err = -EADDRNOTAVAIL;
		for (i=0; i<gsf->gf_numsrc; ++i) {
			psin = (struct sockaddr_in *)&gsf->gf_slist[i];

			if (psin->sin_family != AF_INET)
				goto mc_msf_out;
			msf->imsf_slist[i] = psin->sin_addr.s_addr;
		}
		kfree(gsf);
		gsf = NULL;

		err = ax8netfilter_ip_mc_msfilter(sk, msf, ifindex);
	mc_msf_out:
		kfree(msf);
		kfree(gsf);
		break;
	}
	case IP_ROUTER_ALERT:
		err = ax8netfilter_ip_ra_control(sk, val ? 1 : 0, NULL);
		break;

	case IP_FREEBIND:
		if (optlen<1)
			goto e_inval;
		inet->freebind = !!val;
		break;

	case IP_IPSEC_POLICY:
	case IP_XFRM_POLICY:
		err = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			break;
		err = xfrm_user_policy(sk, optname, optval, optlen);
		break;

	case IP_TRANSPARENT:
		if (!capable(CAP_NET_ADMIN)) {
			err = -EPERM;
			break;
		}
		if (optlen < 1)
			goto e_inval;
		inet->transparent = !!val;
		break;

	default:
		err = -ENOPROTOOPT;
		break;
	}
	release_sock(sk);
	return err;

e_inval:
	release_sock(sk);
	return -EINVAL;
}

int ax8netfilter_ip_setsockopt(struct sock *sk, int level,
		int optname, char __user *optval, int optlen)
{
	int err;

	if (level != SOL_IP)
		return -ENOPROTOOPT;

	err = ax8netfilter_do_ip_setsockopt(sk, level, optname, optval, optlen);
#ifdef CONFIG_AX8_NETFILTER
	/* we need to exclude all possible ENOPROTOOPTs except default case */
	if (err == -ENOPROTOOPT && optname != IP_HDRINCL &&
			optname != IP_IPSEC_POLICY &&
			optname != IP_XFRM_POLICY &&
			!ip_mroute_opt(optname)) {
		lock_sock(sk);
		err = nf_setsockopt(sk, PF_INET, optname, optval, optlen);
		release_sock(sk);
	}
#endif
	return err;
}

/*
 *	Get the options. Note for future reference. The GET of IP options gets the
 *	_received_ ones. The set sets the _sent_ ones.
 */

static int ax8netfilter_do_ip_getsockopt(struct sock *sk, int level, int optname,
			    char __user *optval, int __user *optlen)
{
	struct inet_sock *inet = inet_sk(sk);
	int val;
	int len;

	if (level != SOL_IP)
		return -EOPNOTSUPP;

	if (ip_mroute_opt(optname))
		return ip_mroute_getsockopt(sk, optname, optval, optlen);

	if (get_user(len, optlen))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	lock_sock(sk);

	switch (optname) {
	case IP_OPTIONS:
	{
		unsigned char optbuf[sizeof(struct ip_options)+40];
		struct ip_options * opt = (struct ip_options *)optbuf;
		opt->optlen = 0;
		if (inet->opt)
			memcpy(optbuf, inet->opt,
			       sizeof(struct ip_options)+
			       inet->opt->optlen);
		release_sock(sk);

		if (opt->optlen == 0)
			return put_user(0, optlen);

		ax8netfilter_ip_options_undo(opt);

		len = min_t(unsigned int, len, opt->optlen);
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, opt->__data, len))
			return -EFAULT;
		return 0;
	}
	case IP_PKTINFO:
		val = (inet->cmsg_flags & IP_CMSG_PKTINFO) != 0;
		break;
	case IP_RECVTTL:
		val = (inet->cmsg_flags & IP_CMSG_TTL) != 0;
		break;
	case IP_RECVTOS:
		val = (inet->cmsg_flags & IP_CMSG_TOS) != 0;
		break;
	case IP_RECVOPTS:
		val = (inet->cmsg_flags & IP_CMSG_RECVOPTS) != 0;
		break;
	case IP_RETOPTS:
		val = (inet->cmsg_flags & IP_CMSG_RETOPTS) != 0;
		break;
	case IP_PASSSEC:
		val = (inet->cmsg_flags & IP_CMSG_PASSSEC) != 0;
		break;
	case IP_RECVORIGDSTADDR:
		val = (inet->cmsg_flags & IP_CMSG_ORIGDSTADDR) != 0;
		break;
	case IP_TOS:
		val = inet->tos;
		break;
	case IP_TTL:
		val = (inet->uc_ttl == -1 ?
		       (*ax8netfilter_sysctl_ip_default_ttl) :
		       inet->uc_ttl);
		break;
	case IP_HDRINCL:
		val = inet->hdrincl;
		break;
	case IP_MTU_DISCOVER:
		val = inet->pmtudisc;
		break;
	case IP_MTU:
	{
		struct dst_entry *dst;
		val = 0;
		dst = sk_dst_get(sk);
		if (dst) {
			val = dst_mtu(dst);
			dst_release(dst);
		}
		if (!val) {
			release_sock(sk);
			return -ENOTCONN;
		}
		break;
	}
	case IP_RECVERR:
		val = inet->recverr;
		break;
	case IP_MULTICAST_TTL:
		val = inet->mc_ttl;
		break;
	case IP_MULTICAST_LOOP:
		val = inet->mc_loop;
		break;
	case IP_MULTICAST_IF:
	{
		struct in_addr addr;
		len = min_t(unsigned int, len, sizeof(struct in_addr));
		addr.s_addr = inet->mc_addr;
		release_sock(sk);

		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, &addr, len))
			return -EFAULT;
		return 0;
	}
	case IP_MSFILTER:
	{
		struct ip_msfilter msf;
		int err;

		if (len < IP_MSFILTER_SIZE(0)) {
			release_sock(sk);
			return -EINVAL;
		}
		if (copy_from_user(&msf, optval, IP_MSFILTER_SIZE(0))) {
			release_sock(sk);
			return -EFAULT;
		}
		err = ax8netfilter_ip_mc_msfget(sk, &msf,
				   (struct ip_msfilter __user *)optval, optlen);
		release_sock(sk);
		return err;
	}
	case MCAST_MSFILTER:
	{
		struct group_filter gsf;
		int err;

		if (len < GROUP_FILTER_SIZE(0)) {
			release_sock(sk);
			return -EINVAL;
		}
		if (copy_from_user(&gsf, optval, GROUP_FILTER_SIZE(0))) {
			release_sock(sk);
			return -EFAULT;
		}
		err = ax8netfilter_ip_mc_gsfget(sk, &gsf,
				   (struct group_filter __user *)optval, optlen);
		release_sock(sk);
		return err;
	}
	case IP_PKTOPTIONS:
	{
		struct msghdr msg;

		release_sock(sk);

		if (sk->sk_type != SOCK_STREAM)
			return -ENOPROTOOPT;

		msg.msg_control = optval;
		msg.msg_controllen = len;
		msg.msg_flags = 0;

		if (inet->cmsg_flags & IP_CMSG_PKTINFO) {
			struct in_pktinfo info;

			info.ipi_addr.s_addr = inet->rcv_saddr;
			info.ipi_spec_dst.s_addr = inet->rcv_saddr;
			info.ipi_ifindex = inet->mc_index;
			put_cmsg(&msg, SOL_IP, IP_PKTINFO, sizeof(info), &info);
		}
		if (inet->cmsg_flags & IP_CMSG_TTL) {
			int hlim = inet->mc_ttl;
			put_cmsg(&msg, SOL_IP, IP_TTL, sizeof(hlim), &hlim);
		}
		len -= msg.msg_controllen;
		return put_user(len, optlen);
	}
	case IP_FREEBIND:
		val = inet->freebind;
		break;
	case IP_TRANSPARENT:
		val = inet->transparent;
		break;
	default:
		release_sock(sk);
		return -ENOPROTOOPT;
	}
	release_sock(sk);

	if (len < sizeof(int) && len > 0 && val>=0 && val<=255) {
		unsigned char ucval = (unsigned char)val;
		len = 1;
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, &ucval, 1))
			return -EFAULT;
	} else {
		len = min_t(unsigned int, sizeof(int), len);
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, &val, len))
			return -EFAULT;
	}
	return 0;
}


int ax8netfilter_ip_getsockopt(struct sock *sk, int level,
		  int optname, char __user *optval, int __user *optlen)
{
	int err;

	err = ax8netfilter_do_ip_getsockopt(sk, level, optname, optval, optlen);
#ifdef CONFIG_AX8_NETFILTER
	/* we need to exclude all possible ENOPROTOOPTs except default case */
	if (err == -ENOPROTOOPT && optname != IP_PKTOPTIONS &&
			!ip_mroute_opt(optname)) {
		int len;

		if (get_user(len, optlen))
			return -EFAULT;

		lock_sock(sk);
		err = nf_getsockopt(sk, PF_INET, optname, optval,
				&len);
		release_sock(sk);
		if (err >= 0)
			err = put_user(len, optlen);
		return err;
	}
#endif
	return err;
}

/***************************************/

struct cfg_value_map {
	const char* name;
	void * new_func;
};

static const struct cfg_value_map func_mapping_table[] = {
	{"ip_getsockopt", 		&ax8netfilter_ip_getsockopt },
	{"ip_setsockopt", 		&ax8netfilter_ip_setsockopt },
	{"xfrm4_output", 		&ax8netfilter_xfrm4_output },
	{"ip_finish_output", 		&ax8netfilter_ip_finish_output },
	{"xfrm4_transport_finish", 	&ax8netfilter_xfrm4_transport_finish},
	{"arp_xmit", 			&ax8netfilter_arp_xmit },
	{"ip_forward", 			&ax8netfilter_ip_forward },
	{"ip_local_deliver", 		&ax8netfilter_ip_local_deliver },
	{"ip_local_out", 		&ax8netfilter_ip_local_out },
	{"ip_output", 			&ax8netfilter_ip_output },
	{"ip_mc_output", 		&ax8netfilter_ip_mc_output },
	{"raw_sendmsg", 		&ax8netfilter_raw_sendmsg },
	{"xfrm_output_resume", 		&ax8netfilter_xfrm_output_resume },
	{"__copy_skb_header",		&ax8_netfilter___copy_skb_header},
	{"ip_options_fragment",		&ax8netfilter_ip_options_fragment},
	{NULL, 0},
};

static int hijack_functions(int check_only)
{	
	const struct cfg_value_map * t = func_mapping_table;
	int func;
	int ret = 1;

	while (t->name) {
		func = kallsyms_lookup_name_ax(t->name);
		if(check_only)
		{
			if(!func)
			{
				printk(KERN_ERR AX_MODULE_NAME ": Pointer to %s not found!!!\n", t->name);	
				ret = 0;
			}
		}
		else
			if(func)
			{
				patch_to_jmp(func, t->new_func);
				printk(KERN_ERR AX_MODULE_NAME ": Function %s hijacked\n", t->name);	
			}
			else
				ret = 0;
		t++;
	}

	return ret;
}

/* inits of netfilters */
int ipv4_netfilter_init(void);
int ipv6_netfilter_init(void);
void netfilter_init(void);

/********* Module methods *************/
// init module
static int __init ax8netfilter_init(void)
{
	int ret = -1;
	struct sk_buff aaa;
	long a;


	a = ((long)&aaa.nfct) - ((long)&aaa.cb);

	printk(KERN_INFO AX_MODULE_NAME ": module " AX_MODULE_VER " loaded\n");

	printk(KERN_INFO AX_MODULE_NAME ": struct tcp_skb_cb size %d!!!\n", sizeof(struct tcp_skb_cb));
	printk(KERN_INFO AX_MODULE_NAME ": struct udp_skb_cb size %d!!!\n", sizeof(struct udp_skb_cb));
	printk(KERN_INFO AX_MODULE_NAME ": struct xfrm_skb_cb size %d!!!\n", sizeof(struct xfrm_skb_cb));
	printk(KERN_INFO AX_MODULE_NAME ": sizeof(void *) size %d!!!\n", sizeof(void *));
	printk(KERN_INFO AX_MODULE_NAME ": place of nfct %d!!!\n", (int)a);

	if(sizeof(struct tcp_skb_cb) > 4)
	{
	//	goto eof;
	}

	// our 'GetProcAddress' :D
	kallsyms_lookup_name_ax = (void*) OFS_KALLSYMS_LOOKUP_NAME;

	if(!hijack_functions(1))
	{
		goto eof;
	}

	ax8netfilter_ip_mc_msfget = (void*) kallsyms_lookup_name_ax("ip_mc_msfget");
	if(!ax8netfilter_ip_mc_msfget)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_mc_msfget func missing!!!\n");
		goto eof;
	}
		
	ax8netfilter_ip_mc_source = (void*) kallsyms_lookup_name_ax("ip_mc_source");
	if(!ax8netfilter_ip_mc_source)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_mc_source func missing!!!\n");
		goto eof;
	}

	ax8netfilter_sysctl_igmp_max_msf = (void*) kallsyms_lookup_name_ax("sysctl_igmp_max_msf");
	if(!ax8netfilter_sysctl_igmp_max_msf)
	{
		printk(KERN_INFO AX_MODULE_NAME ": sysctl_igmp_max_msf func missing!!!\n");
		goto eof;
	}

	ax8netfilter_sysctl_ip_default_ttl = (void*) kallsyms_lookup_name_ax("sysctl_ip_default_ttl");
	if(!ax8netfilter_sysctl_ip_default_ttl)
	{
		printk(KERN_INFO AX_MODULE_NAME ": sysctl_ip_default_ttlfunc missing!!!\n");
		goto eof;
	}

	ax8netfilter_ip_options_get_from_user = (void*) kallsyms_lookup_name_ax("ip_options_get_from_user");
	if(!ax8netfilter_ip_options_get_from_user)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_options_get_from_user func missing!!!\n");
		goto eof;
	}

	ax8netfilter_ip_options_undo = (void*) kallsyms_lookup_name_ax("ip_options_undo");
	if(!ax8netfilter_ip_options_undo)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_options_undo func missing!!!\n");
		goto eof;
	}

	ax8netfilter_ip_ra_control = (void*) kallsyms_lookup_name_ax("ip_ra_control");
	if(!ax8netfilter_ip_ra_control)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_ra_control func missing!!!\n");
		goto eof;
	}

	ax8netfilter_ip_mc_leave_group= (void*) kallsyms_lookup_name_ax("ip_mc_leave_group");
	if(!ax8netfilter_ip_mc_leave_group)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_mc_leave_group func missing!!!\n");
		goto eof;
	}

	ax8netfilter_ip_mc_gsfget= (void*) kallsyms_lookup_name_ax("ip_mc_gsfget");
	if(!ax8netfilter_ip_mc_gsfget)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_mc_gsfget func missing!!!\n");
		goto eof;
	}

	ax8netfilter_ip_mc_msfilter= (void*) kallsyms_lookup_name_ax("ip_mc_msfilter");
	if(!ax8netfilter_ip_mc_msfilter)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_mc_msfilter func missing!!!\n");
		goto eof;
	}

	ax8netfilter_ip_cmsg_send= (void*) kallsyms_lookup_name_ax("ip_cmsg_send");
	if(!ax8netfilter_ip_cmsg_send)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_cmsg_send func missing!!!\n");
		goto eof;
	}

	ax8netfilter_ip_finish_output2= (void*) kallsyms_lookup_name_ax("ip_finish_output2");
	if(!ax8netfilter_ip_finish_output2)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_finish_output2 func missing!!!\n");
		goto eof;
	}

	ax8netfilter_icmp_out_count= (void*) kallsyms_lookup_name_ax("icmp_out_count");
	if(!ax8netfilter_icmp_out_count)
	{
		printk(KERN_INFO AX_MODULE_NAME ": icmp_out_count func missing!!!\n");
		goto eof;
	}

	ax8netfilter_inet_protos= (struct net_protocol **) kallsyms_lookup_name_ax("inet_protos");
	if(!ax8netfilter_inet_protos)
	{
		printk(KERN_INFO AX_MODULE_NAME ": inet_protos func missing!!!\n");
		goto eof;
	}

	ax8netfilter_ip_append_data= (void*) kallsyms_lookup_name_ax("ip_append_data");
	if(!ax8netfilter_ip_append_data)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_append_data func missing!!!\n");
		goto eof;
	}

	ax8netfilter_xfrm_replay_notify= (void*) kallsyms_lookup_name_ax("xfrm_replay_notify");
	if(!ax8netfilter_xfrm_replay_notify)
	{
		printk(KERN_INFO AX_MODULE_NAME ": xfrm_replay_notify func missing!!!\n");
		goto eof;
	}

	ax8netfilter_ip_local_error= (void*) kallsyms_lookup_name_ax("ip_local_error");
	if(!ax8netfilter_ip_local_error)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_local_error func missing!!!\n");
		goto eof;
	}

	ax8netfilter_ip_flush_pending_frames= (void*) kallsyms_lookup_name_ax("ip_flush_pending_frames");
	if(!ax8netfilter_ip_flush_pending_frames)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_flush_pending_frames func missing!!!\n");
		goto eof;
	}

	ax8netfilter_ip_forward_options= (void*) kallsyms_lookup_name_ax("ip_forward_options");
	if(!ax8netfilter_ip_forward_options)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_forward_options func missing!!!\n");
		goto eof;
	}

	ax8netfilter_ip_push_pending_frames= (void*) kallsyms_lookup_name_ax("ip_push_pending_frames");
	if(!ax8netfilter_ip_push_pending_frames)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_push_pending_frames func missing!!!\n");
		goto eof;
	}

	ax8netfilter_ip_call_ra_chain= (void*) kallsyms_lookup_name_ax("ip_call_ra_chain");
	if(!ax8netfilter_ip_call_ra_chain)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_call_ra_chain func missing!!!\n");
		goto eof;
	}

	ax8netfilter_raw_local_deliver= (void*) kallsyms_lookup_name_ax("raw_local_deliver");
	if(!ax8netfilter_raw_local_deliver)
	{
		printk(KERN_INFO AX_MODULE_NAME ": raw_local_deliver func missing!!!\n");
		goto eof;
	}

	ax8netfilter_ip_rt_send_redirect= (void*) kallsyms_lookup_name_ax("ip_rt_send_redirect");
	if(!ax8netfilter_ip_rt_send_redirect)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_rt_send_redirect func missing!!!\n");
		goto eof;
	}

	netfilter_init();

	ret = ipv4_netfilter_init();

	if( ret < 0 )
	{
		printk(KERN_INFO AX_MODULE_NAME ": ipv4_netfilter_init() failed\n");
		goto eof;
	}

	ret = ipv6_netfilter_init();

	if( ret < 0 )
	{
		printk(KERN_INFO AX_MODULE_NAME ": ipv6_netfilter_init() failed\n");
		goto eof;
	}

	hijack_functions(0);

	eof:
	return ret;
}

module_init(ax8netfilter_init);

MODULE_AUTHOR("AnDyX@xda-developers.com");
MODULE_DESCRIPTION("Netfilter module for X8");
MODULE_LICENSE("GPL");
