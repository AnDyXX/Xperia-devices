/* Event cache for netfilter. */

/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2003,2004 USAGI/WIDE Project <http://www.linux-ipv6.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/stddef.h>
#include <linux/err.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>

ATOMIC_NOTIFIER_HEAD(nf_conntrack_chain);
EXPORT_SYMBOL_GPL(nf_conntrack_chain);

ATOMIC_NOTIFIER_HEAD(nf_ct_expect_chain);
EXPORT_SYMBOL_GPL(nf_ct_expect_chain);

/* deliver cached events and clear cache entry - must be called with locally
 * disabled softirqs */
static inline void
__nf_ct_deliver_cached_events(struct nf_conntrack_ecache *ecache)
{
	if (nf_ct_is_confirmed(ecache->ct) && !nf_ct_is_dying(ecache->ct)
	    && ecache->events) {
		struct nf_ct_event item = {
			.ct 	= ecache->ct,
			.pid	= 0,
			.report	= 0
		};

		atomic_notifier_call_chain(&nf_conntrack_chain,
					   ecache->events,
					   &item);
	}

	ecache->events = 0;
	nf_ct_put(ecache->ct);
	ecache->ct = NULL;
}

/* Deliver all cached events for a particular conntrack. This is called
 * by code prior to async packet handling for freeing the skb */
void nf_ct_deliver_cached_events(const struct nf_conn *ct)
{
#ifndef CONFIG_AX8_NETFILTER
	struct net *net = nf_ct_net(ct);
#endif
	struct nf_conntrack_ecache *ecache;

	local_bh_disable();
#ifdef CONFIG_AX8_NETFILTER
	ecache = per_cpu_ptr(init_ax8netfilter_net.ct.ecache, raw_smp_processor_id());
#else
	ecache = per_cpu_ptr(net->ct.ecache, raw_smp_processor_id());
#endif
	if (ecache->ct == ct)
		__nf_ct_deliver_cached_events(ecache);
	local_bh_enable();
}
EXPORT_SYMBOL_GPL(nf_ct_deliver_cached_events);

/* Deliver cached events for old pending events, if current conntrack != old */
void __nf_ct_event_cache_init(struct nf_conn *ct)
{
#ifndef CONFIG_AX8_NETFILTER
	struct net *net = nf_ct_net(ct);
#endif

	struct nf_conntrack_ecache *ecache;

	/* take care of delivering potentially old events */
#ifdef CONFIG_AX8_NETFILTER
	ecache = per_cpu_ptr(init_ax8netfilter_net.ct.ecache, raw_smp_processor_id());
#else
	ecache = per_cpu_ptr(net->ct.ecache, raw_smp_processor_id());
#endif

	BUG_ON(ecache->ct == ct);
	if (ecache->ct)
		__nf_ct_deliver_cached_events(ecache);
	/* initialize for this conntrack/packet */
	ecache->ct = ct;
	nf_conntrack_get(&ct->ct_general);
}
EXPORT_SYMBOL_GPL(__nf_ct_event_cache_init);

/* flush the event cache - touches other CPU's data and must not be called
 * while packets are still passing through the code */
void nf_ct_event_cache_flush(struct net *net)
{
	struct nf_conntrack_ecache *ecache;
	int cpu;

	for_each_possible_cpu(cpu) {
#ifdef CONFIG_AX8_NETFILTER
		ecache = per_cpu_ptr(init_ax8netfilter_net.ct.ecache, cpu);
#else
		ecache = per_cpu_ptr(net->ct.ecache, cpu);
#endif
		if (ecache->ct)
			nf_ct_put(ecache->ct);
	}
}

int nf_conntrack_ecache_init(struct net *net)
{
#ifdef CONFIG_AX8_NETFILTER
	init_ax8netfilter_net.ct.ecache = alloc_percpu(struct nf_conntrack_ecache);
	if (!init_ax8netfilter_net.ct.ecache)
		return -ENOMEM;
	return 0;
#else
	net->ct.ecache = alloc_percpu(struct nf_conntrack_ecache);
	if (!net->ct.ecache)
		return -ENOMEM;
	return 0;
#endif
}

void nf_conntrack_ecache_fini(struct net *net)
{
#ifdef CONFIG_AX8_NETFILTER
	free_percpu(init_ax8netfilter_net.ct.ecache);
#else
	free_percpu(net->ct.ecache);
#endif
}

int nf_conntrack_register_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_register(&nf_conntrack_chain, nb);
}
EXPORT_SYMBOL_GPL(nf_conntrack_register_notifier);

int nf_conntrack_unregister_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_unregister(&nf_conntrack_chain, nb);
}
EXPORT_SYMBOL_GPL(nf_conntrack_unregister_notifier);

int nf_ct_expect_register_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_register(&nf_ct_expect_chain, nb);
}
EXPORT_SYMBOL_GPL(nf_ct_expect_register_notifier);

int nf_ct_expect_unregister_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_unregister(&nf_ct_expect_chain, nb);
}
EXPORT_SYMBOL_GPL(nf_ct_expect_unregister_notifier);
