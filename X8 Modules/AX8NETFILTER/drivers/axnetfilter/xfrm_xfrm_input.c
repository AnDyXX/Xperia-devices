/*
 * xfrm_input.c
 *
 * Changes:
 * 	YOSHIFUJI Hideaki @USAGI
 * 		Split up af-specific portion
 *
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/dst.h>
#include <net/ip.h>
#include <net/xfrm.h>
 

#include "ax8netfilter.h"

int ax8netfilter_xfrm_input(struct sk_buff *skb, int nexthdr, __be32 spi, int encap_type)
{
	struct net *net = dev_net(skb->dev);
	int err;
	__be32 seq;
	struct xfrm_state *x;
	xfrm_address_t *daddr;
	struct xfrm_mode *inner_mode;
	unsigned int family;
	int decaps = 0;
	int async = 0;

	/* A negative encap_type indicates async resumption. */
	if (encap_type < 0) {
		async = 1;
		x = xfrm_input_state(skb);
		seq = XFRM_SKB_CB(skb)->seq.input;
		goto resume;
	}

	/* Allocate new secpath or COW existing one. */
	if (!skb->sp || atomic_read(&skb->sp->refcnt) != 1) {
		struct sec_path *sp;

		sp = secpath_dup(skb->sp);
		if (!sp) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINERROR);
			goto drop;
		}
		if (skb->sp)
			secpath_put(skb->sp);
		skb->sp = sp;
	}

	daddr = (xfrm_address_t *)(skb_network_header(skb) +
				   XFRM_SPI_SKB_CB(skb)->daddroff);
	family = XFRM_SPI_SKB_CB(skb)->family;

	seq = 0;
	if (!spi && (err = ax8netfilter_xfrm_parse_spi(skb, nexthdr, &spi, &seq)) != 0) {
		XFRM_INC_STATS(net, LINUX_MIB_XFRMINHDRERROR);
		goto drop;
	}

	do {
		if (skb->sp->len == XFRM_MAX_DEPTH) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINBUFFERERROR);
			goto drop;
		}

		x = xfrm_state_lookup(net, daddr, spi, nexthdr, family);
		if (x == NULL) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINNOSTATES);
			xfrm_audit_state_notfound(skb, family, spi, seq);
			goto drop;
		}

		skb->sp->xvec[skb->sp->len++] = x;

		spin_lock(&x->lock);
		if (unlikely(x->km.state != XFRM_STATE_VALID)) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINSTATEINVALID);
			goto drop_unlock;
		}

		if ((x->encap ? x->encap->encap_type : 0) != encap_type) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINSTATEMISMATCH);
			goto drop_unlock;
		}

		if (x->props.replay_window && ax8netfilter_xfrm_replay_check(x, skb, seq)) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINSTATESEQERROR);
			goto drop_unlock;
		}

		if (xfrm_state_check_expire(x)) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINSTATEEXPIRED);
			goto drop_unlock;
		}

		spin_unlock(&x->lock);

		XFRM_SKB_CB(skb)->seq.input = seq;

		nexthdr = x->type->input(x, skb);

		if (nexthdr == -EINPROGRESS)
			return 0;

resume:
		spin_lock(&x->lock);
		if (nexthdr <= 0) {
			if (nexthdr == -EBADMSG) {
				xfrm_audit_state_icvfail(x, skb,
							 x->type->proto);
				x->stats.integrity_failed++;
			}
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINSTATEPROTOERROR);
			goto drop_unlock;
		}

		/* only the first xfrm gets the encap type */
		encap_type = 0;

		if (x->props.replay_window)
			ax8netfilter_xfrm_replay_advance(x, seq);

		x->curlft.bytes += skb->len;
		x->curlft.packets++;

		spin_unlock(&x->lock);

		XFRM_MODE_SKB_CB(skb)->protocol = nexthdr;

		inner_mode = x->inner_mode;

		if (x->sel.family == AF_UNSPEC) {
			inner_mode = xfrm_ip2inner_mode(x, XFRM_MODE_SKB_CB(skb)->protocol);
			if (inner_mode == NULL)
				goto drop;
		}

		if (inner_mode->input(x, skb)) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINSTATEMODEERROR);
			goto drop;
		}

		if (x->outer_mode->flags & XFRM_MODE_FLAG_TUNNEL) {
			decaps = 1;
			break;
		}

		/*
		 * We need the inner address.  However, we only get here for
		 * transport mode so the outer address is identical.
		 */
		daddr = &x->id.daddr;
		family = x->outer_mode->afinfo->family;

		err = ax8netfilter_xfrm_parse_spi(skb, nexthdr, &spi, &seq);
		if (err < 0) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMINHDRERROR);
			goto drop;
		}
	} while (!err);

	nf_reset(skb);

	if (decaps) {
		dst_release(skb->dst);
		skb->dst = NULL;
		netif_rx(skb);
		return 0;
	} else {
		return x->inner_mode->afinfo->transport_finish(skb, async);
	}

drop_unlock:
	spin_unlock(&x->lock);
drop:
	kfree_skb(skb);
	return 0;
} 
