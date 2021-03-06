/*
 * Notify applications of memory pressure via /dev/mem_notify
 *
 * Copyright (C) 2008 Marcelo Tosatti <marcelo@kvack.org>,
 *                    KOSAKI Motohiro <kosaki.motohiro@jp.fujitsu.com>
 *
 * Released under the GPL, see the file COPYING for details.
 */

#ifndef _LINUX_MEM_NOTIFY_H
#define _LINUX_MEM_NOTIFY_H

#define MEM_NOTIFY_FREQ (HZ/5)

#ifdef EXTERNAL_SWAP_MODULE
extern atomic_long_t * ax8swap_last_mem_notify;
#define  last_mem_notify (*ax8swap_last_mem_notify)
#else
extern atomic_long_t last_mem_notify;
#endif

extern const struct file_operations mem_notify_fops;

#ifdef EXTERNAL_SWAP_MODULE
typedef void (*ax8swap___memory_pressure_notify_type)(struct zone *zone, int pressure);
extern ax8swap___memory_pressure_notify_type ax8swap___memory_pressure_notify;
#define __memory_pressure_notify ax8swap___memory_pressure_notify
#else
extern void __memory_pressure_notify(struct zone *zone, int pressure);
#endif

static inline void memory_pressure_notify(struct zone *zone, int pressure)
{
	unsigned long target;
	unsigned long pages_high, pages_free, pages_reserve;

	if (unlikely(zone->mem_notify_status == -1))
		return;

	if (pressure) {
		target = atomic_long_read(&last_mem_notify) + MEM_NOTIFY_FREQ;
		if (likely(time_before(jiffies, target)))
			return;

		pages_high = zone->pages_high;
		pages_free = zone_page_state(zone, NR_FREE_PAGES);
		pages_reserve = zone->lowmem_reserve[MAX_NR_ZONES-1];
		if (unlikely(pages_free > (pages_high+pages_reserve)*2))
			return;

	} else if (likely(!zone->mem_notify_status))
		return;

	__memory_pressure_notify(zone, pressure);
}

#endif /* _LINUX_MEM_NOTIFY_H */
