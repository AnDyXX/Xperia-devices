/*
 *	Linux NET3:	Internet Group Management Protocol  [IGMP]
 *
 *	This code implements the IGMP protocol as defined in RFC1112. There has
 *	been a further revision of this protocol since which is now supported.
 *
 *	If you have trouble with this module be careful what gcc you have used,
 *	the older version didn't come out right using gcc 2.5.8, the newer one
 *	seems to fall out with gcc 2.6.2.
 *
 *	Authors:
 *		Alan Cox <alan@lxorguk.ukuu.org.uk>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 *	Fixes:
 *
 *		Alan Cox	:	Added lots of __inline__ to optimise
 *					the memory usage of all the tiny little
 *					functions.
 *		Alan Cox	:	Dumped the header building experiment.
 *		Alan Cox	:	Minor tweaks ready for multicast routing
 *					and extended IGMP protocol.
 *		Alan Cox	:	Removed a load of inline directives. Gcc 2.5.8
 *					writes utterly bogus code otherwise (sigh)
 *					fixed IGMP loopback to behave in the manner
 *					desired by mrouted, fixed the fact it has been
 *					broken since 1.3.6 and cleaned up a few minor
 *					points.
 *
 *		Chih-Jen Chang	:	Tried to revise IGMP to Version 2
 *		Tsu-Sheng Tsao		E-mail: chihjenc@scf.usc.edu and tsusheng@scf.usc.edu
 *					The enhancements are mainly based on Steve Deering's
 * 					ipmulti-3.5 source code.
 *		Chih-Jen Chang	:	Added the igmp_get_mrouter_info and
 *		Tsu-Sheng Tsao		igmp_set_mrouter_info to keep track of
 *					the mrouted version on that device.
 *		Chih-Jen Chang	:	Added the max_resp_time parameter to
 *		Tsu-Sheng Tsao		igmp_heard_query(). Using this parameter
 *					to identify the multicast router version
 *					and do what the IGMP version 2 specified.
 *		Chih-Jen Chang	:	Added a timer to revert to IGMP V2 router
 *		Tsu-Sheng Tsao		if the specified time expired.
 *		Alan Cox	:	Stop IGMP from 0.0.0.0 being accepted.
 *		Alan Cox	:	Use GFP_ATOMIC in the right places.
 *		Christian Daudt :	igmp timer wasn't set for local group
 *					memberships but was being deleted,
 *					which caused a "del_timer() called
 *					from %p with timer not initialized\n"
 *					message (960131).
 *		Christian Daudt :	removed del_timer from
 *					igmp_timer_expire function (960205).
 *             Christian Daudt :       igmp_heard_report now only calls
 *                                     igmp_timer_expire if tm->running is
 *                                     true (960216).
 *		Malcolm Beattie :	ttl comparison wrong in igmp_rcv made
 *					igmp_heard_query never trigger. Expiry
 *					miscalculation fixed in igmp_heard_query
 *					and random() made to return unsigned to
 *					prevent negative expiry times.
 *		Alexey Kuznetsov:	Wrong group leaving behaviour, backport
 *					fix from pending 2.1.x patches.
 *		Alan Cox:		Forget to enable FDDI support earlier.
 *		Alexey Kuznetsov:	Fixed leaving groups on device down.
 *		Alexey Kuznetsov:	Accordance to igmp-v2-06 draft.
 *		David L Stevens:	IGMPv3 support, with help from
 *					Vinay Kulkarni
 */

#include <linux/module.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/times.h>

#include <net/net_namespace.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/sock.h>
#include <net/checksum.h>
#include <linux/netfilter_ipv4.h>
#ifdef CONFIG_IP_MROUTE
#include <linux/mroute.h>
#endif
#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#endif


#include "ax8netfilter.h"

#define IP_MAX_MEMBERSHIPS	20
#define IP_MAX_MSF		10


/*
 *	Add a filter to a device
 */

static void ax8netfilter_ip_mc_filter_add(struct in_device *in_dev, __be32 addr)
{
	char buf[MAX_ADDR_LEN];
	struct net_device *dev = in_dev->dev;

	/* Checking for IFF_MULTICAST here is WRONG-WRONG-WRONG.
	   We will get multicast token leakage, when IFF_MULTICAST
	   is changed. This check should be done in dev->set_multicast_list
	   routine. Something sort of:
	   if (dev->mc_list && dev->flags&IFF_MULTICAST) { do it; }
	   --ANK
	   */
	if (arp_mc_map(addr, buf, dev, 0) == 0)
		dev_mc_add(dev, buf, dev->addr_len, 0);
}

/*
 *	Remove a filter from a device
 */

static void ax8netfilter_ip_mc_filter_del(struct in_device *in_dev, __be32 addr)
{
	char buf[MAX_ADDR_LEN];
	struct net_device *dev = in_dev->dev;

	if (arp_mc_map(addr, buf, dev, 0) == 0)
		dev_mc_delete(dev, buf, dev->addr_len, 0);
}


static void ax8netfilter_igmp_group_dropped(struct ip_mc_list *im)
{
	struct in_device *in_dev = im->interface;

	if (im->loaded) {
		im->loaded = 0;
		ax8netfilter_ip_mc_filter_del(in_dev, im->multiaddr);
	}

	ip_mc_clear_src(im);
}

static void ax8netfilter_igmp_group_added(struct ip_mc_list *im)
{
	struct in_device *in_dev = im->interface;

	if (im->loaded == 0) {
		im->loaded = 1;
		ax8netfilter_ip_mc_filter_add(in_dev, im->multiaddr);
	}

}


/*
 *	Multicast list managers
 */


/*
 *	A socket has joined a multicast group on device dev.
 */

void ax8netfilter_ip_mc_inc_group(struct in_device *in_dev, __be32 addr)
{
	struct ip_mc_list *im;

	ASSERT_RTNL();

	for (im=in_dev->mc_list; im; im=im->next) {
		if (im->multiaddr == addr) {
			im->users++;
			ip_mc_add_src(in_dev, &addr, MCAST_EXCLUDE, 0, NULL, 0);
			goto out;
		}
	}

	im = kmalloc(sizeof(*im), GFP_KERNEL);
	if (!im)
		goto out;

	im->users = 1;
	im->interface = in_dev;
	in_dev_hold(in_dev);
	im->multiaddr = addr;
	/* initial mode is (EX, empty) */
	im->sfmode = MCAST_EXCLUDE;
	im->sfcount[MCAST_INCLUDE] = 0;
	im->sfcount[MCAST_EXCLUDE] = 1;
	im->sources = NULL;
	im->tomb = NULL;
	im->crcount = 0;
	atomic_set(&im->refcnt, 1);
	spin_lock_init(&im->lock);
	im->loaded = 0;
	write_lock_bh(&in_dev->mc_list_lock);
	im->next = in_dev->mc_list;
	in_dev->mc_list = im;
	in_dev->mc_count++;
	write_unlock_bh(&in_dev->mc_list_lock);
	ax8netfilter_igmp_group_added(im);
	if (!in_dev->dead)
		ip_rt_multicast_event(in_dev);
out:
	return;
}

/*
 *	A socket has left a multicast group on device dev
 */

void ax8netfilter_ip_mc_dec_group(struct in_device *in_dev, __be32 addr)
{
	struct ip_mc_list *i, **ip;

	ASSERT_RTNL();

	for (ip=&in_dev->mc_list; (i=*ip)!=NULL; ip=&i->next) {
		if (i->multiaddr == addr) {
			if (--i->users == 0) {
				write_lock_bh(&in_dev->mc_list_lock);
				*ip = i->next;
				in_dev->mc_count--;
				write_unlock_bh(&in_dev->mc_list_lock);
				ax8netfilter_igmp_group_dropped(i);

				if (!in_dev->dead)
					ip_rt_multicast_event(in_dev);

				ip_ma_put(i);
				return;
			}
			break;
		}
	}
}



static int ax8netfilter_ip_mc_del1_src(struct ip_mc_list *pmc, int sfmode,
	__be32 *psfsrc)
{
	struct ip_sf_list *psf, *psf_prev;
	int rv = 0;

	psf_prev = NULL;
	for (psf=pmc->sources; psf; psf=psf->sf_next) {
		if (psf->sf_inaddr == *psfsrc)
			break;
		psf_prev = psf;
	}
	if (!psf || psf->sf_count[sfmode] == 0) {
		/* source filter not found, or count wrong =>  bug */
		return -ESRCH;
	}
	psf->sf_count[sfmode]--;
	if (psf->sf_count[sfmode] == 0) {
		ip_rt_multicast_event(pmc->interface);
	}
	if (!psf->sf_count[MCAST_INCLUDE] && !psf->sf_count[MCAST_EXCLUDE]) {


		/* no more filters for this source */
		if (psf_prev)
			psf_prev->sf_next = psf->sf_next;
		else
			pmc->sources = psf->sf_next;

			kfree(psf);
	}
	return rv;
}

#ifndef CONFIG_IP_MULTICAST
#define igmp_ifc_event(x)	do { } while (0)
#endif

static int ip_mc_del_src(struct in_device *in_dev, __be32 *pmca, int sfmode,
			 int sfcount, __be32 *psfsrc, int delta)
{
	struct ip_mc_list *pmc;
	int	changerec = 0;
	int	i, err;

	if (!in_dev)
		return -ENODEV;
	read_lock(&in_dev->mc_list_lock);
	for (pmc=in_dev->mc_list; pmc; pmc=pmc->next) {
		if (*pmca == pmc->multiaddr)
			break;
	}
	if (!pmc) {
		/* MCA not found?? bug */
		read_unlock(&in_dev->mc_list_lock);
		return -ESRCH;
	}
	spin_lock_bh(&pmc->lock);
	read_unlock(&in_dev->mc_list_lock);

	if (!delta) {
		err = -EINVAL;
		if (!pmc->sfcount[sfmode])
			goto out_unlock;
		pmc->sfcount[sfmode]--;
	}
	err = 0;
	for (i=0; i<sfcount; i++) {
		int rv = ax8netfilter_ip_mc_del1_src(pmc, sfmode, &psfsrc[i]);

		changerec |= rv > 0;
		if (!err && rv < 0)
			err = rv;
	}
	if (pmc->sfmode == MCAST_EXCLUDE &&
	    pmc->sfcount[MCAST_EXCLUDE] == 0 &&
	    pmc->sfcount[MCAST_INCLUDE]) {


		/* filter mode change */
		pmc->sfmode = MCAST_INCLUDE;

	}
out_unlock:
	spin_unlock_bh(&pmc->lock);
	return err;
}

/*
 * Add multicast single-source filter to the interface list
 */
static int ip_mc_add1_src(struct ip_mc_list *pmc, int sfmode,
	__be32 *psfsrc, int delta)
{
	struct ip_sf_list *psf, *psf_prev;

	psf_prev = NULL;
	for (psf=pmc->sources; psf; psf=psf->sf_next) {
		if (psf->sf_inaddr == *psfsrc)
			break;
		psf_prev = psf;
	}
	if (!psf) {
		psf = kzalloc(sizeof(*psf), GFP_ATOMIC);
		if (!psf)
			return -ENOBUFS;
		psf->sf_inaddr = *psfsrc;
		if (psf_prev) {
			psf_prev->sf_next = psf;
		} else
			pmc->sources = psf;
	}
	psf->sf_count[sfmode]++;
	if (psf->sf_count[sfmode] == 1) {
		ip_rt_multicast_event(pmc->interface);
	}
	return 0;
}


/*
 * Add multicast source filter list to the interface list
 */
static int ip_mc_add_src(struct in_device *in_dev, __be32 *pmca, int sfmode,
			 int sfcount, __be32 *psfsrc, int delta)
{
	struct ip_mc_list *pmc;
	int	isexclude;
	int	i, err;

	if (!in_dev)
		return -ENODEV;
	read_lock(&in_dev->mc_list_lock);
	for (pmc=in_dev->mc_list; pmc; pmc=pmc->next) {
		if (*pmca == pmc->multiaddr)
			break;
	}
	if (!pmc) {
		/* MCA not found?? bug */
		read_unlock(&in_dev->mc_list_lock);
		return -ESRCH;
	}
	spin_lock_bh(&pmc->lock);
	read_unlock(&in_dev->mc_list_lock);

	isexclude = pmc->sfmode == MCAST_EXCLUDE;
	if (!delta)
		pmc->sfcount[sfmode]++;
	err = 0;
	for (i=0; i<sfcount; i++) {
		err = ip_mc_add1_src(pmc, sfmode, &psfsrc[i], delta);
		if (err)
			break;
	}
	if (err) {
		int j;

		pmc->sfcount[sfmode]--;
		for (j=0; j<i; j++)
			(void) ip_mc_del1_src(pmc, sfmode, &psfsrc[i]);
	} else if (isexclude != (pmc->sfcount[MCAST_EXCLUDE] != 0)) {

		/* filter mode change */
		if (pmc->sfcount[MCAST_EXCLUDE])
			pmc->sfmode = MCAST_EXCLUDE;
		else if (pmc->sfcount[MCAST_INCLUDE])
			pmc->sfmode = MCAST_INCLUDE;
	}
	spin_unlock_bh(&pmc->lock);
	return err;
}

static void ip_mc_clear_src(struct ip_mc_list *pmc)
{
	struct ip_sf_list *psf, *nextpsf;

	for (psf=pmc->tomb; psf; psf=nextpsf) {
		nextpsf = psf->sf_next;
		kfree(psf);
	}
	pmc->tomb = NULL;
	for (psf=pmc->sources; psf; psf=nextpsf) {
		nextpsf = psf->sf_next;
		kfree(psf);
	}
	pmc->sources = NULL;
	pmc->sfmode = MCAST_EXCLUDE;
	pmc->sfcount[MCAST_INCLUDE] = 0;
	pmc->sfcount[MCAST_EXCLUDE] = 1;
}


/*
 * Join a multicast group
 */
int ip_mc_join_group(struct sock *sk , struct ip_mreqn *imr)
{
	int err;
	__be32 addr = imr->imr_multiaddr.s_addr;
	struct ip_mc_socklist *iml = NULL, *i;
	struct in_device *in_dev;
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	int ifindex;
	int count = 0;

	if (!ipv4_is_multicast(addr))
		return -EINVAL;

	rtnl_lock();

	in_dev = ip_mc_find_dev(net, imr);

	if (!in_dev) {
		iml = NULL;
		err = -ENODEV;
		goto done;
	}

	err = -EADDRINUSE;
	ifindex = imr->imr_ifindex;
	for (i = inet->mc_list; i; i = i->next) {
		if (i->multi.imr_multiaddr.s_addr == addr &&
		    i->multi.imr_ifindex == ifindex)
			goto done;
		count++;
	}
	err = -ENOBUFS;
	if (count >= sysctl_igmp_max_memberships)
		goto done;
	iml = sock_kmalloc(sk, sizeof(*iml), GFP_KERNEL);
	if (iml == NULL)
		goto done;

	memcpy(&iml->multi, imr, sizeof(*imr));
	iml->next = inet->mc_list;
	iml->sflist = NULL;
	iml->sfmode = MCAST_EXCLUDE;
	inet->mc_list = iml;
	ax8netfilter_ip_mc_inc_group(in_dev, addr);
	err = 0;
done:
	rtnl_unlock();
	return err;
}

static int ip_mc_leave_src(struct sock *sk, struct ip_mc_socklist *iml,
			   struct in_device *in_dev)
{
	int err;

	if (iml->sflist == NULL) {
		/* any-source empty exclude case */
		return ip_mc_del_src(in_dev, &iml->multi.imr_multiaddr.s_addr,
			iml->sfmode, 0, NULL, 0);
	}
	err = ip_mc_del_src(in_dev, &iml->multi.imr_multiaddr.s_addr,
			iml->sfmode, iml->sflist->sl_count,
			iml->sflist->sl_addr, 0);
	sock_kfree_s(sk, iml->sflist, IP_SFLSIZE(iml->sflist->sl_max));
	iml->sflist = NULL;
	return err;
}

/*
 *	Ask a socket to leave a group.
 */

int ip_mc_leave_group(struct sock *sk, struct ip_mreqn *imr)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ip_mc_socklist *iml, **imlp;
	struct in_device *in_dev;
	struct net *net = sock_net(sk);
	__be32 group = imr->imr_multiaddr.s_addr;
	u32 ifindex;
	int ret = -EADDRNOTAVAIL;

	rtnl_lock();
	in_dev = ip_mc_find_dev(net, imr);
	ifindex = imr->imr_ifindex;
	for (imlp = &inet->mc_list; (iml = *imlp) != NULL; imlp = &iml->next) {
		if (iml->multi.imr_multiaddr.s_addr != group)
			continue;
		if (ifindex) {
			if (iml->multi.imr_ifindex != ifindex)
				continue;
		} else if (imr->imr_address.s_addr && imr->imr_address.s_addr !=
				iml->multi.imr_address.s_addr)
			continue;

		(void) ip_mc_leave_src(sk, iml, in_dev);

		*imlp = iml->next;

		if (in_dev)
			ax8netfilter_ip_mc_dec_group(in_dev, group);
		rtnl_unlock();
		sock_kfree_s(sk, iml, sizeof(*iml));
		return 0;
	}
	if (!in_dev)
		ret = -ENODEV;
	rtnl_unlock();
	return ret;
}

int ip_mc_source(int add, int omode, struct sock *sk, struct
	ip_mreq_source *mreqs, int ifindex)
{
	int err;
	struct ip_mreqn imr;
	__be32 addr = mreqs->imr_multiaddr;
	struct ip_mc_socklist *pmc;
	struct in_device *in_dev = NULL;
	struct inet_sock *inet = inet_sk(sk);
	struct ip_sf_socklist *psl;
	struct net *net = sock_net(sk);
	int leavegroup = 0;
	int i, j, rv;

	if (!ipv4_is_multicast(addr))
		return -EINVAL;

	rtnl_lock();

	imr.imr_multiaddr.s_addr = mreqs->imr_multiaddr;
	imr.imr_address.s_addr = mreqs->imr_interface;
	imr.imr_ifindex = ifindex;
	in_dev = ip_mc_find_dev(net, &imr);

	if (!in_dev) {
		err = -ENODEV;
		goto done;
	}
	err = -EADDRNOTAVAIL;

	for (pmc=inet->mc_list; pmc; pmc=pmc->next) {
		if (pmc->multi.imr_multiaddr.s_addr == imr.imr_multiaddr.s_addr
		    && pmc->multi.imr_ifindex == imr.imr_ifindex)
			break;
	}
	if (!pmc) {		/* must have a prior join */
		err = -EINVAL;
		goto done;
	}
	/* if a source filter was set, must be the same mode as before */
	if (pmc->sflist) {
		if (pmc->sfmode != omode) {
			err = -EINVAL;
			goto done;
		}
	} else if (pmc->sfmode != omode) {
		/* allow mode switches for empty-set filters */
		ip_mc_add_src(in_dev, &mreqs->imr_multiaddr, omode, 0, NULL, 0);
		ip_mc_del_src(in_dev, &mreqs->imr_multiaddr, pmc->sfmode, 0,
			NULL, 0);
		pmc->sfmode = omode;
	}

	psl = pmc->sflist;
	if (!add) {
		if (!psl)
			goto done;	/* err = -EADDRNOTAVAIL */
		rv = !0;
		for (i=0; i<psl->sl_count; i++) {
			rv = memcmp(&psl->sl_addr[i], &mreqs->imr_sourceaddr,
				sizeof(__be32));
			if (rv == 0)
				break;
		}
		if (rv)		/* source not found */
			goto done;	/* err = -EADDRNOTAVAIL */

		/* special case - (INCLUDE, empty) == LEAVE_GROUP */
		if (psl->sl_count == 1 && omode == MCAST_INCLUDE) {
			leavegroup = 1;
			goto done;
		}

		/* update the interface filter */
		ip_mc_del_src(in_dev, &mreqs->imr_multiaddr, omode, 1,
			&mreqs->imr_sourceaddr, 1);

		for (j=i+1; j<psl->sl_count; j++)
			psl->sl_addr[j-1] = psl->sl_addr[j];
		psl->sl_count--;
		err = 0;
		goto done;
	}
	/* else, add a new source to the filter */

	if (psl && psl->sl_count >= sysctl_igmp_max_msf) {
		err = -ENOBUFS;
		goto done;
	}
	if (!psl || psl->sl_count == psl->sl_max) {
		struct ip_sf_socklist *newpsl;
		int count = IP_SFBLOCK;

		if (psl)
			count += psl->sl_max;
		newpsl = sock_kmalloc(sk, IP_SFLSIZE(count), GFP_KERNEL);
		if (!newpsl) {
			err = -ENOBUFS;
			goto done;
		}
		newpsl->sl_max = count;
		newpsl->sl_count = count - IP_SFBLOCK;
		if (psl) {
			for (i=0; i<psl->sl_count; i++)
				newpsl->sl_addr[i] = psl->sl_addr[i];
			sock_kfree_s(sk, psl, IP_SFLSIZE(psl->sl_max));
		}
		pmc->sflist = psl = newpsl;
	}
	rv = 1;	/* > 0 for insert logic below if sl_count is 0 */
	for (i=0; i<psl->sl_count; i++) {
		rv = memcmp(&psl->sl_addr[i], &mreqs->imr_sourceaddr,
			sizeof(__be32));
		if (rv == 0)
			break;
	}
	if (rv == 0)		/* address already there is an error */
		goto done;
	for (j=psl->sl_count-1; j>=i; j--)
		psl->sl_addr[j+1] = psl->sl_addr[j];
	psl->sl_addr[i] = mreqs->imr_sourceaddr;
	psl->sl_count++;
	err = 0;
	/* update the interface list */
	ip_mc_add_src(in_dev, &mreqs->imr_multiaddr, omode, 1,
		&mreqs->imr_sourceaddr, 1);
done:
	rtnl_unlock();
	if (leavegroup)
		return ip_mc_leave_group(sk, &imr);
	return err;
}

int ip_mc_msfilter(struct sock *sk, struct ip_msfilter *msf, int ifindex)
{
	int err = 0;
	struct ip_mreqn	imr;
	__be32 addr = msf->imsf_multiaddr;
	struct ip_mc_socklist *pmc;
	struct in_device *in_dev;
	struct inet_sock *inet = inet_sk(sk);
	struct ip_sf_socklist *newpsl, *psl;
	struct net *net = sock_net(sk);
	int leavegroup = 0;

	if (!ipv4_is_multicast(addr))
		return -EINVAL;
	if (msf->imsf_fmode != MCAST_INCLUDE &&
	    msf->imsf_fmode != MCAST_EXCLUDE)
		return -EINVAL;

	rtnl_lock();

	imr.imr_multiaddr.s_addr = msf->imsf_multiaddr;
	imr.imr_address.s_addr = msf->imsf_interface;
	imr.imr_ifindex = ifindex;
	in_dev = ip_mc_find_dev(net, &imr);

	if (!in_dev) {
		err = -ENODEV;
		goto done;
	}

	/* special case - (INCLUDE, empty) == LEAVE_GROUP */
	if (msf->imsf_fmode == MCAST_INCLUDE && msf->imsf_numsrc == 0) {
		leavegroup = 1;
		goto done;
	}

	for (pmc=inet->mc_list; pmc; pmc=pmc->next) {
		if (pmc->multi.imr_multiaddr.s_addr == msf->imsf_multiaddr &&
		    pmc->multi.imr_ifindex == imr.imr_ifindex)
			break;
	}
	if (!pmc) {		/* must have a prior join */
		err = -EINVAL;
		goto done;
	}
	if (msf->imsf_numsrc) {
		newpsl = sock_kmalloc(sk, IP_SFLSIZE(msf->imsf_numsrc),
							   GFP_KERNEL);
		if (!newpsl) {
			err = -ENOBUFS;
			goto done;
		}
		newpsl->sl_max = newpsl->sl_count = msf->imsf_numsrc;
		memcpy(newpsl->sl_addr, msf->imsf_slist,
			msf->imsf_numsrc * sizeof(msf->imsf_slist[0]));
		err = ip_mc_add_src(in_dev, &msf->imsf_multiaddr,
			msf->imsf_fmode, newpsl->sl_count, newpsl->sl_addr, 0);
		if (err) {
			sock_kfree_s(sk, newpsl, IP_SFLSIZE(newpsl->sl_max));
			goto done;
		}
	} else {
		newpsl = NULL;
		(void) ip_mc_add_src(in_dev, &msf->imsf_multiaddr,
				     msf->imsf_fmode, 0, NULL, 0);
	}
	psl = pmc->sflist;
	if (psl) {
		(void) ip_mc_del_src(in_dev, &msf->imsf_multiaddr, pmc->sfmode,
			psl->sl_count, psl->sl_addr, 0);
		sock_kfree_s(sk, psl, IP_SFLSIZE(psl->sl_max));
	} else
		(void) ip_mc_del_src(in_dev, &msf->imsf_multiaddr, pmc->sfmode,
			0, NULL, 0);
	pmc->sflist = newpsl;
	pmc->sfmode = msf->imsf_fmode;
	err = 0;
done:
	rtnl_unlock();
	if (leavegroup)
		err = ip_mc_leave_group(sk, &imr);
	return err;
}

int ip_mc_msfget(struct sock *sk, struct ip_msfilter *msf,
	struct ip_msfilter __user *optval, int __user *optlen)
{
	int err, len, count, copycount;
	struct ip_mreqn	imr;
	__be32 addr = msf->imsf_multiaddr;
	struct ip_mc_socklist *pmc;
	struct in_device *in_dev;
	struct inet_sock *inet = inet_sk(sk);
	struct ip_sf_socklist *psl;
	struct net *net = sock_net(sk);

	if (!ipv4_is_multicast(addr))
		return -EINVAL;

	rtnl_lock();

	imr.imr_multiaddr.s_addr = msf->imsf_multiaddr;
	imr.imr_address.s_addr = msf->imsf_interface;
	imr.imr_ifindex = 0;
	in_dev = ip_mc_find_dev(net, &imr);

	if (!in_dev) {
		err = -ENODEV;
		goto done;
	}
	err = -EADDRNOTAVAIL;

	for (pmc=inet->mc_list; pmc; pmc=pmc->next) {
		if (pmc->multi.imr_multiaddr.s_addr == msf->imsf_multiaddr &&
		    pmc->multi.imr_ifindex == imr.imr_ifindex)
			break;
	}
	if (!pmc)		/* must have a prior join */
		goto done;
	msf->imsf_fmode = pmc->sfmode;
	psl = pmc->sflist;
	rtnl_unlock();
	if (!psl) {
		len = 0;
		count = 0;
	} else {
		count = psl->sl_count;
	}
	copycount = count < msf->imsf_numsrc ? count : msf->imsf_numsrc;
	len = copycount * sizeof(psl->sl_addr[0]);
	msf->imsf_numsrc = count;
	if (put_user(IP_MSFILTER_SIZE(copycount), optlen) ||
	    copy_to_user(optval, msf, IP_MSFILTER_SIZE(0))) {
		return -EFAULT;
	}
	if (len &&
	    copy_to_user(&optval->imsf_slist[0], psl->sl_addr, len))
		return -EFAULT;
	return 0;
done:
	rtnl_unlock();
	return err;
}

int ip_mc_gsfget(struct sock *sk, struct group_filter *gsf,
	struct group_filter __user *optval, int __user *optlen)
{
	int err, i, count, copycount;
	struct sockaddr_in *psin;
	__be32 addr;
	struct ip_mc_socklist *pmc;
	struct inet_sock *inet = inet_sk(sk);
	struct ip_sf_socklist *psl;

	psin = (struct sockaddr_in *)&gsf->gf_group;
	if (psin->sin_family != AF_INET)
		return -EINVAL;
	addr = psin->sin_addr.s_addr;
	if (!ipv4_is_multicast(addr))
		return -EINVAL;

	rtnl_lock();

	err = -EADDRNOTAVAIL;

	for (pmc=inet->mc_list; pmc; pmc=pmc->next) {
		if (pmc->multi.imr_multiaddr.s_addr == addr &&
		    pmc->multi.imr_ifindex == gsf->gf_interface)
			break;
	}
	if (!pmc)		/* must have a prior join */
		goto done;
	gsf->gf_fmode = pmc->sfmode;
	psl = pmc->sflist;
	rtnl_unlock();
	count = psl ? psl->sl_count : 0;
	copycount = count < gsf->gf_numsrc ? count : gsf->gf_numsrc;
	gsf->gf_numsrc = count;
	if (put_user(GROUP_FILTER_SIZE(copycount), optlen) ||
	    copy_to_user(optval, gsf, GROUP_FILTER_SIZE(0))) {
		return -EFAULT;
	}
	for (i=0; i<copycount; i++) {
		struct sockaddr_storage ss;

		psin = (struct sockaddr_in *)&ss;
		memset(&ss, 0, sizeof(ss));
		psin->sin_family = AF_INET;
		psin->sin_addr.s_addr = psl->sl_addr[i];
		if (copy_to_user(&optval->gf_slist[i], &ss, sizeof(ss)))
			return -EFAULT;
	}
	return 0;
done:
	rtnl_unlock();
	return err;
}

/*
 * check if a multicast source filter allows delivery for a given <src,dst,intf>
 */
int ip_mc_sf_allow(struct sock *sk, __be32 loc_addr, __be32 rmt_addr, int dif)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ip_mc_socklist *pmc;
	struct ip_sf_socklist *psl;
	int i;

	if (!ipv4_is_multicast(loc_addr))
		return 1;

	for (pmc=inet->mc_list; pmc; pmc=pmc->next) {
		if (pmc->multi.imr_multiaddr.s_addr == loc_addr &&
		    pmc->multi.imr_ifindex == dif)
			break;
	}
	if (!pmc)
		return 1;
	psl = pmc->sflist;
	if (!psl)
		return pmc->sfmode == MCAST_EXCLUDE;

	for (i=0; i<psl->sl_count; i++) {
		if (psl->sl_addr[i] == rmt_addr)
			break;
	}
	if (pmc->sfmode == MCAST_INCLUDE && i >= psl->sl_count)
		return 0;
	if (pmc->sfmode == MCAST_EXCLUDE && i < psl->sl_count)
		return 0;
	return 1;
}

/*
 *	A socket is closing.
 */

void ip_mc_drop_socket(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ip_mc_socklist *iml;
	struct net *net = sock_net(sk);

	if (inet->mc_list == NULL)
		return;

	rtnl_lock();
	while ((iml = inet->mc_list) != NULL) {
		struct in_device *in_dev;
		inet->mc_list = iml->next;

		in_dev = inetdev_by_index(net, iml->multi.imr_ifindex);
		(void) ip_mc_leave_src(sk, iml, in_dev);
		if (in_dev != NULL) {
			ax8netfilter_ip_mc_dec_group(in_dev, iml->multi.imr_multiaddr.s_addr);
			in_dev_put(in_dev);
		}
		sock_kfree_s(sk, iml, sizeof(*iml));
	}
	rtnl_unlock();
}

int ip_check_mc(struct in_device *in_dev, __be32 mc_addr, __be32 src_addr, u16 proto)
{
	struct ip_mc_list *im;
	struct ip_sf_list *psf;
	int rv = 0;

	read_lock(&in_dev->mc_list_lock);
	for (im=in_dev->mc_list; im; im=im->next) {
		if (im->multiaddr == mc_addr)
			break;
	}
	if (im && proto == IPPROTO_IGMP) {
		rv = 1;
	} else if (im) {
		if (src_addr) {
			for (psf=im->sources; psf; psf=psf->sf_next) {
				if (psf->sf_inaddr == src_addr)
					break;
			}
			if (psf)
				rv = psf->sf_count[MCAST_INCLUDE] ||
					psf->sf_count[MCAST_EXCLUDE] !=
					im->sfcount[MCAST_EXCLUDE];
			else
				rv = im->sfcount[MCAST_EXCLUDE] != 0;
		} else
			rv = 1; /* unspecified source; tentatively allow */
	}
	read_unlock(&in_dev->mc_list_lock);
	return rv;
}


