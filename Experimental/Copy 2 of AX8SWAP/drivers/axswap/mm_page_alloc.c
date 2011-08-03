/*
 *  linux/mm/page_alloc.c
 *
 *  Manages the free list, the system allocates free pages here.
 *  Note that kmalloc() lives in slab.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  Reshaped it to be a zoned allocator, Ingo Molnar, Red Hat, 1999
 *  Discontiguous memory support, Kanoj Sarcar, SGI, Nov 1999
 *  Zone balancing, Kanoj Sarcar, SGI, Jan 2000
 *  Per cpu hot/cold page lists, bulk allocation, Martin J. Bligh, Sept 2002
 *          (lots of bits borrowed from Ingo Molnar & Andrew Morton)
 */

#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/interrupt.h>
#include <linux/pagemap.h>
#include <linux/jiffies.h>
#include <linux/bootmem.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/oom.h>
#include <linux/notifier.h>
#include <linux/topology.h>
#include <linux/sysctl.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/memory_hotplug.h>
#include <linux/nodemask.h>
#include <linux/vmalloc.h>
#include <linux/mempolicy.h>
#include <linux/stop_machine.h>
#include <linux/sort.h>
#include <linux/pfn.h>
#include <linux/backing-dev.h>
#include <linux/fault-inject.h>
#include <linux/page-isolation.h>
#include <linux/page_cgroup.h>
#include <linux/debugobjects.h>
#include <linux/mem_notify.h>

#include "../../mm/internal.h"

#include "hijacked_types.h"

void ax8swap_set_pageblock_migratetype(struct page *page, int migratetype)
{
	set_pageblock_flags_group(page, (unsigned long)migratetype,
					PB_migrate, PB_migrate_end);
}

#ifdef CONFIG_DEBUG_VM
static int ax8swap_page_outside_zone_boundaries(struct zone *zone, struct page *page)
{
	int ret = 0;
	unsigned seq;
	unsigned long pfn = page_to_pfn(page);

	do {
		seq = zone_span_seqbegin(zone);
		if (pfn >= zone->zone_start_pfn + zone->spanned_pages)
			ret = 1;
		else if (pfn < zone->zone_start_pfn)
			ret = 1;
	} while (zone_span_seqretry(zone, seq));

	return ret;
}

static int ax8swap_page_is_consistent(struct zone *zone, struct page *page)
{
	if (!pfn_valid_within(page_to_pfn(page)))
		return 0;
	if (zone != page_zone(page))
		return 0;

	return 1;
}
/*
 * Temporary debugging check for pages not lying within a given zone.
 */
static int ax8swap_bad_range(struct zone *zone, struct page *page)
{
	if (page_outside_zone_boundaries(zone, page))
		return 1;
	if (!page_is_consistent(zone, page))
		return 1;

	return 0;
}
#else
static inline int ax8swap_bad_range(struct zone *zone, struct page *page)
{
	return 0;
}
#endif

void ax8swap_bad_page(struct page *page)
{
	static unsigned long resume;
	static unsigned long nr_shown;
	static unsigned long nr_unshown;

	/*
	 * Allow a burst of 60 reports, then keep quiet for that minute;
	 * or allow a steady drip of one report per second.
	 */
	if (nr_shown == 60) {
		if (time_before(jiffies, resume)) {
			nr_unshown++;
			goto out;
		}
		if (nr_unshown) {
			printk(KERN_ALERT
			      "BUG: Bad page state: %lu messages suppressed\n",
				nr_unshown);
			nr_unshown = 0;
		}
		nr_shown = 0;
	}
	if (nr_shown++ == 0)
		resume = jiffies + 60 * HZ;

	printk(KERN_ALERT "BUG: Bad page state in process %s  pfn:%05lx\n",
		current->comm, page_to_pfn(page));
	printk(KERN_ALERT
		"page:%p flags:%p count:%d mapcount:%d mapping:%p index:%lx\n",
		page, (void *)page->flags, page_count(page),
		page_mapcount(page), page->mapping, page->index);

	dump_stack();
out:
	/* Leave bad fields for debug, except PageBuddy could make trouble */
	__ClearPageBuddy(page);
	add_taint(TAINT_BAD_PAGE);
}

/*
 * Higher-order pages are called "compound pages".  They are structured thusly:
 *
 * The first PAGE_SIZE page is called the "head page".
 *
 * The remaining PAGE_SIZE pages are called "tail pages".
 *
 * All pages have PG_compound set.  All pages have their ->private pointing at
 * the head page (even the head page has this).
 *
 * The first tail page's ->lru.next holds the address of the compound page's
 * put_page() function.  Its ->lru.prev holds the order of allocation.
 * This usage means that zero-order pages may not be compound.
 */

static void ax8swap_free_compound_page(struct page *page)
{
	ax8swap___free_pages_ok(page, compound_order(page));
}

void ax8swap_prep_compound_page(struct page *page, unsigned long order)
{
	int i;
	int nr_pages = 1 << order;

	set_compound_page_dtor(page, ax8swap_free_compound_page);
	set_compound_order(page, order);
	__SetPageHead(page);
	for (i = 1; i < nr_pages; i++) {
		struct page *p = page + i;

		__SetPageTail(p);
		p->first_page = page;
	}
}

#ifdef CONFIG_HUGETLBFS
void ax8swap_prep_compound_gigantic_page(struct page *page, unsigned long order)
{
	int i;
	int nr_pages = 1 << order;
	struct page *p = page + 1;

	set_compound_page_dtor(page, free_compound_page);
	set_compound_order(page, order);
	__SetPageHead(page);
	for (i = 1; i < nr_pages; i++, p = mem_map_next(p, page, i)) {
		__SetPageTail(p);
		p->first_page = page;
	}
}
#endif

static int ax8swap_destroy_compound_page(struct page *page, unsigned long order)
{
	int i;
	int nr_pages = 1 << order;
	int bad = 0;

	if (unlikely(compound_order(page) != order) ||
	    unlikely(!PageHead(page))) {
		ax8swap_bad_page(page);
		bad++;
	}

	__ClearPageHead(page);

	for (i = 1; i < nr_pages; i++) {
		struct page *p = page + i;

		if (unlikely(!PageTail(p) | (p->first_page != page))) {
			ax8swap_bad_page(page);
			bad++;
		}
		__ClearPageTail(p);
	}

	return bad;
}

static inline void ax8swap_prep_zero_page(struct page *page, int order, gfp_t gfp_flags)
{
	int i;

	/*
	 * clear_highpage() will use KM_USER0, so it's a bug to use __GFP_ZERO
	 * and __GFP_HIGHMEM from hard or soft interrupt context.
	 */
	VM_BUG_ON((gfp_flags & __GFP_HIGHMEM) && in_interrupt());
	for (i = 0; i < (1 << order); i++)
		clear_highpage(page + i);
}

static inline void ax8swap_set_page_order(struct page *page, int order)
{
	set_page_private(page, order);
	__SetPageBuddy(page);
}

static inline void ax8swap_rmv_page_order(struct page *page)
{
	__ClearPageBuddy(page);
	set_page_private(page, 0);
}

/*
 * Locate the struct page for both the matching buddy in our
 * pair (buddy1) and the combined O(n+1) page they form (page).
 *
 * 1) Any buddy B1 will have an order O twin B2 which satisfies
 * the following equation:
 *     B2 = B1 ^ (1 << O)
 * For example, if the starting buddy (buddy2) is #8 its order
 * 1 buddy is #10:
 *     B2 = 8 ^ (1 << 1) = 8 ^ 2 = 10
 *
 * 2) Any buddy B will have an order O+1 parent P which
 * satisfies the following equation:
 *     P = B & ~(1 << O)
 *
 * Assumption: *_mem_map is contiguous at least up to MAX_ORDER
 */
static inline struct page *
ax8swap___page_find_buddy(struct page *page, unsigned long page_idx, unsigned int order)
{
	unsigned long buddy_idx = page_idx ^ (1 << order);

	return page + (buddy_idx - page_idx);
}

static inline unsigned long
ax8swap___find_combined_index(unsigned long page_idx, unsigned int order)
{
	return (page_idx & ~(1 << order));
}

/*
 * This function checks whether a page is free && is the buddy
 * we can do coalesce a page and its buddy if
 * (a) the buddy is not in a hole &&
 * (b) the buddy is in the buddy system &&
 * (c) a page and its buddy have the same order &&
 * (d) a page and its buddy are in the same zone.
 *
 * For recording whether a page is in the buddy system, we use PG_buddy.
 * Setting, clearing, and testing PG_buddy is serialized by zone->lock.
 *
 * For recording page's order, we use page_private(page).
 */
static inline int ax8swap_page_is_buddy(struct page *page, struct page *buddy,
								int order)
{
	if (!pfn_valid_within(page_to_pfn(buddy)))
		return 0;

	if (page_zone_id(page) != page_zone_id(buddy))
		return 0;

	if (PageBuddy(buddy) && page_order(buddy) == order) {
		BUG_ON(page_count(buddy) != 0);
		return 1;
	}
	return 0;
}

/*
 * Freeing function for a buddy system allocator.
 *
 * The concept of a buddy system is to maintain direct-mapped table
 * (containing bit values) for memory blocks of various "orders".
 * The bottom level table contains the map for the smallest allocatable
 * units of memory (here, pages), and each level above it describes
 * pairs of units from the levels below, hence, "buddies".
 * At a high level, all that happens here is marking the table entry
 * at the bottom level available, and propagating the changes upward
 * as necessary, plus some accounting needed to play nicely with other
 * parts of the VM system.
 * At each level, we keep a list of pages, which are heads of continuous
 * free pages of length of (1 << order) and marked with PG_buddy. Page's
 * order is recorded in page_private(page) field.
 * So when we are allocating or freeing one, we can derive the state of the
 * other.  That is, if we allocate a small block, and both were   
 * free, the remainder of the region must be split into blocks.   
 * If a block is freed, and its buddy is also free, then this
 * triggers coalescing into a block of larger size.            
 *
 * -- wli
 */

static inline void ax8swap___free_one_page(struct page *page,
		struct zone *zone, unsigned int order)
{
	unsigned long page_idx;
	int order_size = 1 << order;
	int migratetype = get_pageblock_migratetype(page);
	unsigned long prev_free;
	unsigned long notify_threshold;

	if (unlikely(PageCompound(page)))
		if (unlikely(ax8swap_destroy_compound_page(page, order)))
			return;

	page_idx = page_to_pfn(page) & ((1 << MAX_ORDER) - 1);

	VM_BUG_ON(page_idx & (order_size - 1));
	VM_BUG_ON(bad_range(zone, page));

	prev_free = zone_page_state(zone, NR_FREE_PAGES);
	__mod_zone_page_state(zone, NR_FREE_PAGES, order_size);
	while (order < MAX_ORDER-1) {
		unsigned long combined_idx;
		struct page *buddy;

		buddy = ax8swap___page_find_buddy(page, page_idx, order);
		if (!ax8swap_page_is_buddy(page, buddy, order))
			break;

		/* Our buddy is free, merge with it and move up one order. */
		list_del(&buddy->lru);
		zone->free_area[order].nr_free--;
		ax8swap_rmv_page_order(buddy);
		combined_idx = ax8swap___find_combined_index(page_idx, order);
		page = page + (combined_idx - page_idx);
		page_idx = combined_idx;
		order++;
	}
	ax8swap_set_page_order(page, order);
	list_add(&page->lru,
		&zone->free_area[order].free_list[migratetype]);
	zone->free_area[order].nr_free++;

	notify_threshold = (zone->pages_high +
			    zone->lowmem_reserve[MAX_NR_ZONES-1]) * 2;

	if (unlikely((zone->mem_notify_status == 1) &&
		     (prev_free <= notify_threshold) &&
		     (zone_page_state(zone, NR_FREE_PAGES) > notify_threshold)))
		memory_pressure_notify(zone, 0);
}

static inline int ax8swap_free_pages_check(struct page *page)
{
	free_page_mlock(page);
	if (unlikely(page_mapcount(page) |
		(page->mapping != NULL)  |
		(page_count(page) != 0)  |
		(page->flags & PAGE_FLAGS_CHECK_AT_FREE))) {
		ax8swap_bad_page(page);
		return 1;
	}
	if (page->flags & PAGE_FLAGS_CHECK_AT_PREP)
		page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
	return 0;
}

/*
 * Frees a list of pages. 
 * Assumes all pages on list are in same zone, and of same order.
 * count is the number of pages to free.
 *
 * If the zone was previously in an "all pages pinned" state then look to
 * see if this freeing clears that state.
 *
 * And clear the zone's pages_scanned counter, to hold off the "all pages are
 * pinned" detection logic.
 */
static void ax8swap_free_pages_bulk(struct zone *zone, int count,
					struct list_head *list, int order)
{
	spin_lock(&zone->lock);
	zone_clear_flag(zone, ZONE_ALL_UNRECLAIMABLE);
	zone->pages_scanned = 0;
	while (count--) {
		struct page *page;

		VM_BUG_ON(list_empty(list));
		page = list_entry(list->prev, struct page, lru);
		/* have to delete it as __free_one_page list manipulates */
		list_del(&page->lru);
		ax8swap___free_one_page(page, zone, order);
	}
	spin_unlock(&zone->lock);
}

static void ax8swap_free_one_page(struct zone *zone, struct page *page, int order)
{
	spin_lock(&zone->lock);
	zone_clear_flag(zone, ZONE_ALL_UNRECLAIMABLE);
	zone->pages_scanned = 0;
	ax8swap___free_one_page(page, zone, order);
	spin_unlock(&zone->lock);
}

void ax8swap___free_pages_ok(struct page *page, unsigned int order)
{
	unsigned long flags;
	int i;
	int bad = 0;

	for (i = 0 ; i < (1 << order) ; ++i)
		bad += ax8swap_free_pages_check(page + i);
	if (bad)
		return;

	if (!PageHighMem(page)) {
		debug_check_no_locks_freed(page_address(page),PAGE_SIZE<<order);
		debug_check_no_obj_freed(page_address(page),
					   PAGE_SIZE << order);
	}
	arch_free_page(page, order);
	kernel_map_pages(page, 1 << order, 0);

	local_irq_save(flags);
	__count_vm_events(PGFREE, 1 << order);
	ax8swap_free_one_page(page_zone(page), page, order);
	local_irq_restore(flags);
}

void ax8swap_free_hot_cold_page(struct page *page, int cold)
{
	struct zone *zone = page_zone(page);
	struct per_cpu_pages *pcp;
	unsigned long flags;

	if (PageAnon(page))
		page->mapping = NULL;
	if (ax8swap_free_pages_check(page))
		return;

	if (!PageHighMem(page)) {
		debug_check_no_locks_freed(page_address(page), PAGE_SIZE);
		debug_check_no_obj_freed(page_address(page), PAGE_SIZE);
	}
	arch_free_page(page, 0);
	kernel_map_pages(page, 1, 0);

	pcp = &zone_pcp(zone, get_cpu())->pcp;
	local_irq_save(flags);
	__count_vm_event(PGFREE);
	if (cold)
		list_add_tail(&page->lru, &pcp->list);
	else
		list_add(&page->lru, &pcp->list);
	set_page_private(page, get_pageblock_migratetype(page));
	pcp->count++;
	if (pcp->count >= pcp->high) {
		ax8swap_free_pages_bulk(zone, pcp->batch, &pcp->list, 0);
		pcp->count -= pcp->batch;
	}
	local_irq_restore(flags);
	put_cpu();
}

static inline void show_node(struct zone *zone)
{
	if (NUMA_BUILD)
		printk("Node %d ", zone_to_nid(zone));
} 

#define K(x) ((x) << (PAGE_SHIFT-10))

/*
 * Show free area list (used inside shift_scroll-lock stuff)
 * We also calculate the percentage fragmentation. We do this by counting the
 * memory on each free list with the exception of the first item on the list.
 */
void ax8swap_show_free_areas(void)
{
	int cpu;
	struct zone *zone;

	for_each_zone(zone) {
		if (!populated_zone(zone))
			continue;

		show_node(zone);
		printk("%s per-cpu:\n", zone->name);

		for_each_online_cpu(cpu) {
			struct per_cpu_pageset *pageset;

			pageset = zone_pcp(zone, cpu);

			printk("CPU %4d: hi:%5d, btch:%4d usd:%4d\n",
			       cpu, pageset->pcp.high,
			       pageset->pcp.batch, pageset->pcp.count);
		}
	}

	printk("Active_anon:%lu active_file:%lu inactive_anon:%lu\n"
		" inactive_file:%lu"
//TODO:  check/adjust line lengths
#ifdef CONFIG_UNEVICTABLE_LRU
		" unevictable:%lu"
#endif
		" dirty:%lu writeback:%lu unstable:%lu\n"
		" free:%lu slab:%lu mapped:%lu pagetables:%lu bounce:%lu\n",
		global_page_state(NR_ACTIVE_ANON),
		global_page_state(NR_ACTIVE_FILE),
		global_page_state(NR_INACTIVE_ANON),
		global_page_state(NR_INACTIVE_FILE),
#ifdef CONFIG_UNEVICTABLE_LRU
		global_page_state(NR_UNEVICTABLE),
#endif
		global_page_state(NR_FILE_DIRTY),
		global_page_state(NR_WRITEBACK),
		global_page_state(NR_UNSTABLE_NFS),
		global_page_state(NR_FREE_PAGES),
		global_page_state(NR_SLAB_RECLAIMABLE) +
			global_page_state(NR_SLAB_UNRECLAIMABLE),
		global_page_state(NR_FILE_MAPPED),
		global_page_state(NR_PAGETABLE),
		global_page_state(NR_BOUNCE));

	for_each_zone(zone) {
		int i;

		if (!populated_zone(zone))
			continue;

		show_node(zone);
		printk("%s"
			" free:%lukB"
			" min:%lukB"
			" low:%lukB"
			" high:%lukB"
			" active_anon:%lukB"
			" inactive_anon:%lukB"
			" active_file:%lukB"
			" inactive_file:%lukB"
#ifdef CONFIG_UNEVICTABLE_LRU
			" unevictable:%lukB"
#endif
			" present:%lukB"
			" pages_scanned:%lu"
			" all_unreclaimable? %s"
			"\n",
			zone->name,
			K(zone_page_state(zone, NR_FREE_PAGES)),
			K(zone->pages_min),
			K(zone->pages_low),
			K(zone->pages_high),
			K(zone_page_state(zone, NR_ACTIVE_ANON)),
			K(zone_page_state(zone, NR_INACTIVE_ANON)),
			K(zone_page_state(zone, NR_ACTIVE_FILE)),
			K(zone_page_state(zone, NR_INACTIVE_FILE)),
#ifdef CONFIG_UNEVICTABLE_LRU
			K(zone_page_state(zone, NR_UNEVICTABLE)),
#endif
			K(zone->present_pages),
			zone->pages_scanned,
			(zone_is_all_unreclaimable(zone) ? "yes" : "no")
			);
		printk("lowmem_reserve[]:");
		for (i = 0; i < MAX_NR_ZONES; i++)
			printk(" %lu", zone->lowmem_reserve[i]);
		printk("\n");
	}

	for_each_zone(zone) {
 		unsigned long nr[MAX_ORDER], flags, order, total = 0;

		if (!populated_zone(zone))
			continue;

		show_node(zone);
		printk("%s: ", zone->name);

		spin_lock_irqsave(&zone->lock, flags);
		for (order = 0; order < MAX_ORDER; order++) {
			nr[order] = zone->free_area[order].nr_free;
			total += nr[order] << order;
		}
		spin_unlock_irqrestore(&zone->lock, flags);
		for (order = 0; order < MAX_ORDER; order++)
			printk("%lu*%lukB ", nr[order], K(1UL) << order);
		printk("= %lukB\n", K(total));
	}

	printk("%ld total pagecache pages\n", global_page_state(NR_FILE_PAGES));

	show_swap_cache_info();
} 
