/*
 *  linux/mm/vmscan.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *
 *  Swap reorganised 29.12.95, Stephen Tweedie.
 *  kswapd added: 7.1.96  sct
 *  Removed kswapd_ctl limits, and swap out as many pages as needed
 *  to bring the system back to freepages.high: 2.4.97, Rik van Riel.
 *  Zone aware kswapd started 02/00, Kanoj Sarcar (kanoj@sgi.com).
 *  Multiqueue VM started 5.8.00, Rik van Riel.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/vmstat.h>
#include <linux/file.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>	/* for try_to_release_page(),
					buffer_heads_over_limit */
#include <linux/mm_inline.h>
#include <linux/pagevec.h>
#include <linux/backing-dev.h>
#include <linux/rmap.h>
#include <linux/topology.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/notifier.h>
#include <linux/rwsem.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/memcontrol.h>
#include <linux/mem_notify.h>
#include <linux/delayacct.h>
#include <linux/sysctl.h>

#include <asm/tlbflush.h>
#include <asm/div64.h>

#include <linux/swapops.h>

#include "hijacked_types.h"

#define lru_to_page(_head) (list_entry((_head)->prev, struct page, lru))

#ifdef ARCH_HAS_PREFETCH
#define prefetch_prev_lru_page(_page, _base, _field)			\
	do {								\
		if ((_page)->lru.prev != _base) {			\
			struct page *prev;				\
									\
			prev = lru_to_page(&(_page->lru));		\
			prefetch(&prev->_field);			\
		}							\
	} while (0)
#else
#define prefetch_prev_lru_page(_page, _base, _field) do { } while (0)
#endif

#ifdef ARCH_HAS_PREFETCHW
#define prefetchw_prev_lru_page(_page, _base, _field)			\
	do {								\
		if ((_page)->lru.prev != _base) {			\
			struct page *prev;				\
									\
			prev = lru_to_page(&(_page->lru));		\
			prefetchw(&prev->_field);			\
		}							\
	} while (0)
#else
#define prefetchw_prev_lru_page(_page, _base, _field) do { } while (0)
#endif

#ifdef CONFIG_CGROUP_MEM_RES_CTLR
#define scanning_global_lru(sc)	(!(sc)->mem_cgroup)
#else
#define scanning_global_lru(sc)	(1)
#endif

/* LRU Isolation modes. */
#define ISOLATE_INACTIVE 0	/* Isolate inactive pages. */
#define ISOLATE_ACTIVE 1	/* Isolate active pages. */
#define ISOLATE_BOTH 2		/* Isolate both active and inactive pages. */

static struct zone_reclaim_stat *ax8swap_get_reclaim_stat(struct zone *zone,
						  struct scan_control *sc)
{
	if (!scanning_global_lru(sc))
		return mem_cgroup_get_reclaim_stat(sc->mem_cgroup, zone);

	return &zone->reclaim_stat;
}

static unsigned long ax8swap_zone_nr_pages(struct zone *zone, struct scan_control *sc,
				   enum lru_list lru)
{
	if (!scanning_global_lru(sc))
		return mem_cgroup_zone_nr_pages(sc->mem_cgroup, zone, lru);

	return zone_page_state(zone, NR_LRU_BASE + lru);
}

/* Called without lock on whether page is mapped, so answer is unstable */
static inline int ax8swap_page_mapping_inuse(struct page *page)
{
	struct address_space *mapping;

	/* Page is in somebody's page tables. */
	if (page_mapped(page))
		return 1;

	/* Be more reluctant to reclaim swapcache than pagecache */
	if (PageSwapCache(page))
		return 1;

	mapping = page_mapping(page);
	if (!mapping)
		return 0;

	/* File is mmap'd by somebody? */
	return mapping_mapped(mapping);
}

static inline int ax8swap_is_page_cache_freeable(struct page *page)
{
	return page_count(page) - !!PagePrivate(page) == 2;
}

static int ax8swap_may_write_to_queue(struct backing_dev_info *bdi)
{
	if (current->flags & PF_SWAPWRITE)
		return 1;
	if (!bdi_write_congested(bdi))
		return 1;
	if (bdi == current->backing_dev_info)
		return 1;
	return 0;
}

/*
 * We detected a synchronous write error writing a page out.  Probably
 * -ENOSPC.  We need to propagate that into the address_space for a subsequent
 * fsync(), msync() or close().
 *
 * The tricky part is that after writepage we cannot touch the mapping: nothing
 * prevents it from being freed up.  But we have a ref on the page and once
 * that page is locked, the mapping is pinned.
 *
 * We're allowed to run sleeping lock_page() here because we know the caller has
 * __GFP_FS.
 */
static void ax8swap_handle_write_error(struct address_space *mapping,
				struct page *page, int error)
{
	lock_page(page);
	if (page_mapping(page) == mapping)
		mapping_set_error(mapping, error);
	unlock_page(page);
}

/*
 * pageout is called by shrink_page_list() for each dirty page.
 * Calls ->writepage().
 */
static pageout_t ax8swap_pageout(struct page *page, struct address_space *mapping,
						enum pageout_io sync_writeback)
{
	/*
	 * If the page is dirty, only perform writeback if that write
	 * will be non-blocking.  To prevent this allocation from being
	 * stalled by pagecache activity.  But note that there may be
	 * stalls if we need to run get_block().  We could test
	 * PagePrivate for that.
	 *
	 * If this process is currently in generic_file_write() against
	 * this page's queue, we can perform writeback even if that
	 * will block.
	 *
	 * If the page is swapcache, write it back even if that would
	 * block, for some throttling. This happens by accident, because
	 * swap_backing_dev_info is bust: it doesn't reflect the
	 * congestion state of the swapdevs.  Easy to fix, if needed.
	 * See swapfile.c:page_queue_congested().
	 */
	if (!ax8swap_is_page_cache_freeable(page))
		return PAGE_KEEP;
	if (!mapping) {
		/*
		 * Some data journaling orphaned pages can have
		 * page->mapping == NULL while being dirty with clean buffers.
		 */
		if (PagePrivate(page)) {
			if (try_to_free_buffers(page)) {
				ClearPageDirty(page);
				printk("%s: orphaned page\n", __func__);
				return PAGE_CLEAN;
			}
		}
		return PAGE_KEEP;
	}
	if (mapping->a_ops->writepage == NULL)
		return PAGE_ACTIVATE;
	if (!ax8swap_may_write_to_queue(mapping->backing_dev_info))
		return PAGE_KEEP;

	if (clear_page_dirty_for_io(page)) {
		int res;
		struct writeback_control wbc = {
			.sync_mode = WB_SYNC_NONE,
			.nr_to_write = SWAP_CLUSTER_MAX,
			.range_start = 0,
			.range_end = LLONG_MAX,
			.nonblocking = 1,
			.for_reclaim = 1,
		};

		SetPageReclaim(page);
		res = mapping->a_ops->writepage(page, &wbc);
		if (res < 0)
			ax8swap_handle_write_error(mapping, page, res);
		if (res == AOP_WRITEPAGE_ACTIVATE) {
			ClearPageReclaim(page);
			return PAGE_ACTIVATE;
		}

		/*
		 * Wait on writeback if requested to. This happens when
		 * direct reclaiming a large contiguous area and the
		 * first attempt to free a range of pages fails.
		 */
		if (PageWriteback(page) && sync_writeback == PAGEOUT_IO_SYNC)
			wait_on_page_writeback(page);

		if (!PageWriteback(page)) {
			/* synchronous write or broken a_ops? */
			ClearPageReclaim(page);
		}
		inc_zone_page_state(page, NR_VMSCAN_WRITE);
		return PAGE_SUCCESS;
	}

	return PAGE_CLEAN;
}

/*
 * Same as remove_mapping, but if the page is removed from the mapping, it
 * gets returned with a refcount of 0.
 */
int ax8swap___remove_mapping(struct address_space *mapping, struct page *page)
{
	BUG_ON(!PageLocked(page));
	BUG_ON(mapping != page_mapping(page));

	spin_lock_irq(&mapping->tree_lock);
	/*
	 * The non racy check for a busy page.
	 *
	 * Must be careful with the order of the tests. When someone has
	 * a ref to the page, it may be possible that they dirty it then
	 * drop the reference. So if PageDirty is tested before page_count
	 * here, then the following race may occur:
	 *
	 * get_user_pages(&page);
	 * [user mapping goes away]
	 * write_to(page);
	 *				!PageDirty(page)    [good]
	 * SetPageDirty(page);
	 * put_page(page);
	 *				!page_count(page)   [good, discard it]
	 *
	 * [oops, our write_to data is lost]
	 *
	 * Reversing the order of the tests ensures such a situation cannot
	 * escape unnoticed. The smp_rmb is needed to ensure the page->flags
	 * load is not satisfied before that of page->_count.
	 *
	 * Note that if SetPageDirty is always performed via set_page_dirty,
	 * and thus under tree_lock, then this ordering is not required.
	 */
	if (!page_freeze_refs(page, 2))
		goto cannot_free;
	/* note: atomic_cmpxchg in page_freeze_refs provides the smp_rmb */
	if (unlikely(PageDirty(page))) {
		page_unfreeze_refs(page, 2);
		goto cannot_free;
	}

	if (PageSwapCache(page)) {
		swp_entry_t swap = { .val = page_private(page) };
		__delete_from_swap_cache(page);
		spin_unlock_irq(&mapping->tree_lock);
		swap_free(swap);
	} else {
		__remove_from_page_cache(page);
		spin_unlock_irq(&mapping->tree_lock);
	}

	return 1;

cannot_free:
	spin_unlock_irq(&mapping->tree_lock);
	return 0;
}

/*
 * shrink_page_list() returns the number of reclaimed pages
 */
unsigned long ax8swap_shrink_page_list(struct list_head *page_list,
					struct scan_control *sc,
					enum pageout_io sync_writeback)
{
	LIST_HEAD(ret_pages);
	struct pagevec freed_pvec;
	int pgactivate = 0;
	unsigned long nr_reclaimed = 0;

	cond_resched();

	pagevec_init(&freed_pvec, 1);
	while (!list_empty(page_list)) {
		struct address_space *mapping;
		struct page *page;
		int may_enter_fs;
		int referenced;

		cond_resched();

		page = lru_to_page(page_list);
		list_del(&page->lru);

		if (!trylock_page(page))
			goto keep;

		VM_BUG_ON(PageActive(page));

		sc->nr_scanned++;

		if (unlikely(!page_evictable(page, NULL)))
			goto cull_mlocked;

		if (!sc->may_swap && page_mapped(page))
			goto keep_locked;

		/* Double the slab pressure for mapped and swapcache pages */
		if (page_mapped(page) || PageSwapCache(page))
			sc->nr_scanned++;

		may_enter_fs = (sc->gfp_mask & __GFP_FS) ||
			(PageSwapCache(page) && (sc->gfp_mask & __GFP_IO));

		if (PageWriteback(page)) {
			/*
			 * Synchronous reclaim is performed in two passes,
			 * first an asynchronous pass over the list to
			 * start parallel writeback, and a second synchronous
			 * pass to wait for the IO to complete.  Wait here
			 * for any page for which writeback has already
			 * started.
			 */
			if (sync_writeback == PAGEOUT_IO_SYNC && may_enter_fs)
				wait_on_page_writeback(page);
			else
				goto keep_locked;
		}

		referenced = page_referenced(page, 1, sc->mem_cgroup);
		/* In active use or really unfreeable?  Activate it. */
		if (sc->order <= PAGE_ALLOC_COSTLY_ORDER &&
					referenced && ax8swap_page_mapping_inuse(page))
			goto activate_locked;

		/*
		 * Anonymous process memory has backing store?
		 * Try to allocate it some swap space here.
		 */
		if (PageAnon(page) && !PageSwapCache(page)) {
			if (!(sc->gfp_mask & __GFP_IO))
				goto keep_locked;
			if (!add_to_swap(page))
				goto activate_locked;
			may_enter_fs = 1;
		}

		mapping = page_mapping(page);

		/*
		 * The page is mapped into the page tables of one or more
		 * processes. Try to unmap it here.
		 */
		if (page_mapped(page) && mapping) {
			switch (try_to_unmap(page, 0)) {
			case SWAP_FAIL:
				goto activate_locked;
			case SWAP_AGAIN:
				goto keep_locked;
			case SWAP_MLOCK:
				goto cull_mlocked;
			case SWAP_SUCCESS:
				; /* try to free the page below */
			}
		}

		if (PageDirty(page)) {
			if (sc->order <= PAGE_ALLOC_COSTLY_ORDER && referenced)
				goto keep_locked;
			if (!may_enter_fs)
				goto keep_locked;
			if (!sc->may_writepage)
				goto keep_locked;

			/* Page is dirty, try to write it out here */
			switch (ax8swap_pageout(page, mapping, sync_writeback)) {
			case PAGE_KEEP:
				goto keep_locked;
			case PAGE_ACTIVATE:
				goto activate_locked;
			case PAGE_SUCCESS:
				if (PageWriteback(page) || PageDirty(page))
					goto keep;
				/*
				 * A synchronous write - probably a ramdisk.  Go
				 * ahead and try to reclaim the page.
				 */
				if (!trylock_page(page))
					goto keep;
				if (PageDirty(page) || PageWriteback(page))
					goto keep_locked;
				mapping = page_mapping(page);
			case PAGE_CLEAN:
				; /* try to free the page below */
			}
		}

		/*
		 * If the page has buffers, try to free the buffer mappings
		 * associated with this page. If we succeed we try to free
		 * the page as well.
		 *
		 * We do this even if the page is PageDirty().
		 * try_to_release_page() does not perform I/O, but it is
		 * possible for a page to have PageDirty set, but it is actually
		 * clean (all its buffers are clean).  This happens if the
		 * buffers were written out directly, with submit_bh(). ext3
		 * will do this, as well as the blockdev mapping.
		 * try_to_release_page() will discover that cleanness and will
		 * drop the buffers and mark the page clean - it can be freed.
		 *
		 * Rarely, pages can have buffers and no ->mapping.  These are
		 * the pages which were not successfully invalidated in
		 * truncate_complete_page().  We try to drop those buffers here
		 * and if that worked, and the page is no longer mapped into
		 * process address space (page_count == 1) it can be freed.
		 * Otherwise, leave the page on the LRU so it is swappable.
		 */
		if (PagePrivate(page)) {
			if (!try_to_release_page(page, sc->gfp_mask))
				goto activate_locked;
			if (!mapping && page_count(page) == 1) {
				unlock_page(page);
				if (put_page_testzero(page))
					goto free_it;
				else {
					/*
					 * rare race with speculative reference.
					 * the speculative reference will free
					 * this page shortly, so we may
					 * increment nr_reclaimed here (and
					 * leave it off the LRU).
					 */
					nr_reclaimed++;
					continue;
				}
			}
		}

		if (!mapping || !ax8swap___remove_mapping(mapping, page))
			goto keep_locked;

		/*
		 * At this point, we have no other references and there is
		 * no way to pick any more up (removed from LRU, removed
		 * from pagecache). Can use non-atomic bitops now (and
		 * we obviously don't have to worry about waking up a process
		 * waiting on the page lock, because there are no references.
		 */
		__clear_page_locked(page);
free_it:
		nr_reclaimed++;
		if (!pagevec_add(&freed_pvec, page)) {
			__pagevec_free(&freed_pvec);
			pagevec_reinit(&freed_pvec);
		}
		continue;

cull_mlocked:
		if (PageSwapCache(page))
			try_to_free_swap(page);
		unlock_page(page);
		ax8swap_putback_lru_page(page);
		continue;

activate_locked:
		/* Not a candidate for swapping, so reclaim swap space. */
		if (PageSwapCache(page) && vm_swap_full())
			try_to_free_swap(page);
		VM_BUG_ON(PageActive(page));
		SetPageActive(page);
		pgactivate++;
keep_locked:
		unlock_page(page);
keep:
		list_add(&page->lru, &ret_pages);
		VM_BUG_ON(PageLRU(page) || PageUnevictable(page));
	}
	list_splice(&ret_pages, page_list);
	if (pagevec_count(&freed_pvec))
		__pagevec_free(&freed_pvec);
	count_vm_events(PGACTIVATE, pgactivate);
	return nr_reclaimed;
}

static int ax8swap_inactive_anon_is_low_global(struct zone *zone)
{
	unsigned long active, inactive;

	active = zone_page_state(zone, NR_ACTIVE_ANON);
	inactive = zone_page_state(zone, NR_INACTIVE_ANON);

	if (inactive * zone->inactive_ratio < active)
		return 1;

	return 0;
}

/**
 * inactive_anon_is_low - check if anonymous pages need to be deactivated
 * @zone: zone to check
 * @sc:   scan control of this context
 *
 * Returns true if the zone does not have enough inactive anon pages,
 * meaning some active anon pages need to be deactivated.
 */
static int ax8swap_inactive_anon_is_low(struct zone *zone, struct scan_control *sc)
{
	int low;

	if (scanning_global_lru(sc))
		low = ax8swap_inactive_anon_is_low_global(zone);
	else
		low = mem_cgroup_inactive_anon_is_low(sc->mem_cgroup);
	return low;
}

/*
 * This moves pages from the active list to the inactive list.
 *
 * We move them the other way if the page is referenced by one or more
 * processes, from rmap.
 *
 * If the pages are mostly unmapped, the processing is fast and it is
 * appropriate to hold zone->lru_lock across the whole operation.  But if
 * the pages are mapped, the processing is slow (page_referenced()) so we
 * should drop zone->lru_lock around each page.  It's impossible to balance
 * this, so instead we remove the pages from the LRU while processing them.
 * It is safe to rely on PG_active against the non-LRU pages in here because
 * nobody will play with that bit on a non-LRU page.
 *
 * The downside is that we have to touch page->_count against each page.
 * But we had to alter page->flags anyway.
 */


void ax8swap_shrink_active_list(unsigned long nr_pages, struct zone *zone,
			struct scan_control *sc, int priority, int file)
{
	unsigned long pgmoved;
	int pgdeactivate = 0;
	unsigned long pgscanned;
	LIST_HEAD(l_hold);	/* The pages which were snipped off */
	LIST_HEAD(l_inactive);
	struct page *page;
	struct pagevec pvec;
	enum lru_list lru;
	struct zone_reclaim_stat *reclaim_stat = ax8swap_get_reclaim_stat(zone, sc);
	int mem_notify = 0;

	/* Are we low on system memory ? */
	if (!ax8swap_inactive_anon_is_low(zone, sc))
		memory_pressure_notify(zone, 0);

	lru_add_drain();
	spin_lock_irq(&zone->lru_lock);
	pgmoved = sc->isolate_pages(nr_pages, &l_hold, &pgscanned, sc->order,
					ISOLATE_ACTIVE, zone,
					sc->mem_cgroup, 1, file);
	/*
	 * zone->pages_scanned is used for detect zone's oom
	 * mem_cgroup remembers nr_scan by itself.
	 */
	if (scanning_global_lru(sc)) {
		zone->pages_scanned += pgscanned;
	}
	reclaim_stat->recent_scanned[!!file] += pgmoved;

	if (file)
		__mod_zone_page_state(zone, NR_ACTIVE_FILE, -pgmoved);
	else
		__mod_zone_page_state(zone, NR_ACTIVE_ANON, -pgmoved);
	spin_unlock_irq(&zone->lru_lock);

	pgmoved = 0;
	while (!list_empty(&l_hold)) {
		cond_resched();
		page = lru_to_page(&l_hold);
		list_del(&page->lru);

		if (unlikely(!page_evictable(page, NULL))) {
			ax8swap_putback_lru_page(page);
			continue;
		}

		/* page_referenced clears PageReferenced */
		if (ax8swap_page_mapping_inuse(page) &&
		    page_referenced(page, 0, sc->mem_cgroup))
			pgmoved++;

		if (PageAnon(page))
			mem_notify = 1;

		list_add(&page->lru, &l_inactive);
	}

	if (mem_notify)
		memory_pressure_notify(zone, 1);

	/*
	 * Move the pages to the [file or anon] inactive list.
	 */
	pagevec_init(&pvec, 1);
	lru = LRU_BASE + file * LRU_FILE;

	spin_lock_irq(&zone->lru_lock);
	/*
	 * Count referenced pages from currently used mappings as
	 * rotated, even though they are moved to the inactive list.
	 * This helps balance scan pressure between file and anonymous
	 * pages in get_scan_ratio.
	 */
	reclaim_stat->recent_rotated[!!file] += pgmoved;

	pgmoved = 0;
	while (!list_empty(&l_inactive)) {
		page = lru_to_page(&l_inactive);
		prefetchw_prev_lru_page(page, &l_inactive, flags);
		VM_BUG_ON(PageLRU(page));
		SetPageLRU(page);
		VM_BUG_ON(!PageActive(page));
		ClearPageActive(page);

		list_move(&page->lru, &zone->lru[lru].list);
		mem_cgroup_add_lru_list(page, lru);
		pgmoved++;
		if (!pagevec_add(&pvec, page)) {
			__mod_zone_page_state(zone, NR_LRU_BASE + lru, pgmoved);
			spin_unlock_irq(&zone->lru_lock);
			pgdeactivate += pgmoved;
			pgmoved = 0;
			if (buffer_heads_over_limit)
				pagevec_strip(&pvec);
			__pagevec_release(&pvec);
			spin_lock_irq(&zone->lru_lock);
		}
	}
	__mod_zone_page_state(zone, NR_LRU_BASE + lru, pgmoved);
	pgdeactivate += pgmoved;
	if (buffer_heads_over_limit) {
		spin_unlock_irq(&zone->lru_lock);
		pagevec_strip(&pvec);
		spin_lock_irq(&zone->lru_lock);
	}

	/* Are we low on system memory ? */
	if (!ax8swap_inactive_anon_is_low(zone, sc))
		memory_pressure_notify(zone, 0);

	__count_zone_vm_events(PGREFILL, zone, pgscanned);
	__count_vm_events(PGDEACTIVATE, pgdeactivate);
	spin_unlock_irq(&zone->lru_lock);
	if (vm_swap_full())
		pagevec_swap_free(&pvec);

	pagevec_release(&pvec);
}


/*
 * page_evictable - test whether a page is evictable
 * @page: the page to test
 * @vma: the VMA in which the page is or will be mapped, may be NULL
 *
 * Test whether page is evictable--i.e., should be placed on active/inactive
 * lists vs unevictable list.  The vma argument is !NULL when called from the
 * fault path to determine how to instantate a new page.
 *
 * Reasons page might not be evictable:
 * (1) page's mapping marked unevictable
 * (2) page is part of an mlocked VMA
 *
 */
int ax8swap_page_evictable(struct page *page, struct vm_area_struct *vma)
{

	if (mapping_unevictable(page_mapping(page)))
		return 0;

	if (PageMlocked(page) || (vma && ax8swap_is_mlocked_vma(vma, page)))
		return 0;

	return 1;
}


/*
 * Determine how aggressively the anon and file LRU lists should be
 * scanned.  The relative value of each set of LRU lists is determined
 * by looking at the fraction of the pages scanned we did rotate back
 * onto the active list instead of evict.
 *
 * percent[0] specifies how much pressure to put on ram/swap backed
 * memory, while percent[1] determines pressure on the file LRUs.
 */
static void ax8swap_get_scan_ratio(struct zone *zone, struct scan_control *sc,
					unsigned long *percent)
{
	unsigned long anon, file, free;
	unsigned long anon_prio, file_prio;
	unsigned long ap, fp;
	struct zone_reclaim_stat *reclaim_stat = ax8swap_get_reclaim_stat(zone, sc);

	/* If we have no swap space, do not bother scanning anon pages. */
	if (nr_swap_pages <= 0) {
		percent[0] = 0;
		percent[1] = 100;
		return;
	}

	anon  = ax8swap_zone_nr_pages(zone, sc, LRU_ACTIVE_ANON) +
		ax8swap_zone_nr_pages(zone, sc, LRU_INACTIVE_ANON);
	file  = ax8swap_zone_nr_pages(zone, sc, LRU_ACTIVE_FILE) +
		ax8swap_zone_nr_pages(zone, sc, LRU_INACTIVE_FILE);

	if (scanning_global_lru(sc)) {
		free  = zone_page_state(zone, NR_FREE_PAGES);
		/* If we have very few page cache pages,
		   force-scan anon pages. */
		if (unlikely(file + free <= zone->pages_high)) {
			percent[0] = 100;
			percent[1] = 0;
			return;
		}
	}

	/*
	 * OK, so we have swap space and a fair amount of page cache
	 * pages.  We use the recently rotated / recently scanned
	 * ratios to determine how valuable each cache is.
	 *
	 * Because workloads change over time (and to avoid overflow)
	 * we keep these statistics as a floating average, which ends
	 * up weighing recent references more than old ones.
	 *
	 * anon in [0], file in [1]
	 */
	if (unlikely(reclaim_stat->recent_scanned[0] > anon / 4)) {
		spin_lock_irq(&zone->lru_lock);
		reclaim_stat->recent_scanned[0] /= 2;
		reclaim_stat->recent_rotated[0] /= 2;
		spin_unlock_irq(&zone->lru_lock);
	}

	if (unlikely(reclaim_stat->recent_scanned[1] > file / 4)) {
		spin_lock_irq(&zone->lru_lock);
		reclaim_stat->recent_scanned[1] /= 2;
		reclaim_stat->recent_rotated[1] /= 2;
		spin_unlock_irq(&zone->lru_lock);
	}

	/*
	 * With swappiness at 100, anonymous and file have the same priority.
	 * This scanning priority is essentially the inverse of IO cost.
	 */
	anon_prio = sc->swappiness;
	file_prio = 200 - sc->swappiness;

	/*
	 * The amount of pressure on anon vs file pages is inversely
	 * proportional to the fraction of recently scanned pages on
	 * each list that were recently referenced and in active use.
	 */
	ap = (anon_prio + 1) * (reclaim_stat->recent_scanned[0] + 1);
	ap /= reclaim_stat->recent_rotated[0] + 1;

	fp = (file_prio + 1) * (reclaim_stat->recent_scanned[1] + 1);
	fp /= reclaim_stat->recent_rotated[1] + 1;

	/* Normalize to percentages */
	percent[0] = 100 * ap / (ap + fp + 1);
	percent[1] = 100 - percent[0];
}


/*
 * This is a basic per-zone page freer.  Used by both kswapd and direct reclaim.
 */
void ax8swap_shrink_zone(int priority, struct zone *zone,
				struct scan_control *sc)
{
	unsigned long nr[NR_LRU_LISTS];
	unsigned long nr_to_scan;
	unsigned long percent[2];	/* anon @ 0; file @ 1 */
	enum lru_list l;
	unsigned long nr_reclaimed = sc->nr_reclaimed;
	unsigned long swap_cluster_max = sc->swap_cluster_max;

	ax8swap_get_scan_ratio(zone, sc, percent);

	for_each_evictable_lru(l) {
		int file = is_file_lru(l);
		int scan;

		scan = ax8swap_zone_nr_pages(zone, sc, l);
		if (priority) {
			scan >>= priority;
			scan = (scan * percent[file]) / 100;
		}
		if (scanning_global_lru(sc)) {
			zone->lru[l].nr_scan += scan;
			nr[l] = zone->lru[l].nr_scan;
			if (nr[l] >= swap_cluster_max)
				zone->lru[l].nr_scan = 0;
			else
				nr[l] = 0;
		} else
			nr[l] = scan;
	}

	while (nr[LRU_INACTIVE_ANON] || nr[LRU_ACTIVE_FILE] ||
					nr[LRU_INACTIVE_FILE]) {
		for_each_evictable_lru(l) {
			if (nr[l]) {
				nr_to_scan = min(nr[l], swap_cluster_max);
				nr[l] -= nr_to_scan;

				nr_reclaimed += ax8swap_shrink_list(l, nr_to_scan,
							    zone, sc, priority);
			}
		}
		/*
		 * On large memory systems, scan >> priority can become
		 * really large. This is fine for the starting priority;
		 * we want to put equal scanning pressure on each zone.
		 * However, if the VM has a harder time of freeing pages,
		 * with multiple processes reclaiming pages, the total
		 * freeing target can get unreasonably large.
		 */
		if (nr_reclaimed > swap_cluster_max &&
			priority < DEF_PRIORITY && !current_is_kswapd())
			break;
	}

	sc->nr_reclaimed = nr_reclaimed;

	/*
	 * Even if we did not try to evict anon pages at all, we want to
	 * rebalance the anon lru active/inactive ratio.
	 */
	if (ax8swap_inactive_anon_is_low(zone, sc))
		ax8swap_shrink_active_list(SWAP_CLUSTER_MAX, zone, sc, priority, 0);

	throttle_vm_writeout(sc->gfp_mask);
}

/*
 * We are about to scan this zone at a certain priority level.  If that priority
 * level is smaller (ie: more urgent) than the previous priority, then note
 * that priority level within the zone.  This is done so that when the next
 * process comes in to scan this zone, it will immediately start out at this
 * priority level rather than having to build up its own scanning priority.
 * Here, this priority affects only the reclaim-mapped threshold.
 */
static inline void note_zone_scanning_priority(struct zone *zone, int priority)
{
	if (priority < zone->prev_priority)
		zone->prev_priority = priority;
} 

/*
 * This is the direct reclaim path, for page-allocating processes.  We only
 * try to reclaim pages from zones which will satisfy the caller's allocation
 * request.
 *
 * We reclaim from a zone even if that zone is over pages_high.  Because:
 * a) The caller may be trying to free *extra* pages to satisfy a higher-order
 *    allocation or
 * b) The zones may be over pages_high but they must go *over* pages_high to
 *    satisfy the `incremental min' zone defense algorithm.
 *
 * If a zone is deemed to be full of pinned pages then just give it a light
 * scan then give up on it.
 */
static void ax8swap_shrink_zones(int priority, struct zonelist *zonelist,
					struct scan_control *sc)
{
	enum zone_type high_zoneidx = gfp_zone(sc->gfp_mask);
	struct zoneref *z;
	struct zone *zone;

	sc->all_unreclaimable = 1;
	for_each_zone_zonelist(zone, z, zonelist, high_zoneidx) {
		if (!populated_zone(zone))
			continue;
		/*
		 * Take care memory controller reclaiming has small influence
		 * to global LRU.
		 */
		if (scanning_global_lru(sc)) {
			if (!cpuset_zone_allowed_hardwall(zone, GFP_KERNEL))
				continue;
			note_zone_scanning_priority(zone, priority);

			if (zone_is_all_unreclaimable(zone) &&
						priority != DEF_PRIORITY)
				continue;	/* Let kswapd poll it */
			sc->all_unreclaimable = 0;
		} else {
			/*
			 * Ignore cpuset limitation here. We just want to reduce
			 * # of used pages by us regardless of memory shortage.
			 */
			sc->all_unreclaimable = 0;
			mem_cgroup_note_reclaim_priority(sc->mem_cgroup,
							priority);
		}

		ax8swap_shrink_zone(priority, zone, sc);
	}
} 

/*
 * This is the main entry point to direct page reclaim.
 *
 * If a full scan of the inactive list fails to free enough memory then we
 * are "out of memory" and something needs to be killed.
 *
 * If the caller is !__GFP_FS then the probability of a failure is reasonably
 * high - the zone may be full of dirty or under-writeback pages, which this
 * caller can't do much about.  We kick pdflush and take explicit naps in the
 * hope that some of these pages can be written.  But if the allocating task
 * holds filesystem locks which prevent writeout this might not work, and the
 * allocation attempt will fail.
 *
 * returns:	0, if no pages reclaimed
 * 		else, the number of pages reclaimed
 */
static unsigned long ax8swap_do_try_to_free_pages(struct zonelist *zonelist,
					struct scan_control *sc)
{
	int priority;
	unsigned long ret = 0;
	unsigned long total_scanned = 0;
	struct reclaim_state *reclaim_state = current->reclaim_state;
	unsigned long lru_pages = 0;
	struct zoneref *z;
	struct zone *zone;
	enum zone_type high_zoneidx = gfp_zone(sc->gfp_mask);

	delayacct_freepages_start();

	if (scanning_global_lru(sc))
		count_vm_event(ALLOCSTALL);
	/*
	 * mem_cgroup will not do shrink_slab.
	 */
	if (scanning_global_lru(sc)) {
		for_each_zone_zonelist(zone, z, zonelist, high_zoneidx) {

			if (!cpuset_zone_allowed_hardwall(zone, GFP_KERNEL))
				continue;

			lru_pages += zone_lru_pages(zone);
		}
	}

	for (priority = DEF_PRIORITY; priority >= 0; priority--) {
		sc->nr_scanned = 0;
		if (!priority)
			disable_swap_token();
		ax8swap_shrink_zones(priority, zonelist, sc);
		/*
		 * Don't shrink slabs when reclaiming memory from
		 * over limit cgroups
		 */
		if (scanning_global_lru(sc)) {
			shrink_slab(sc->nr_scanned, sc->gfp_mask, lru_pages);
			if (reclaim_state) {
				sc->nr_reclaimed += reclaim_state->reclaimed_slab;
				reclaim_state->reclaimed_slab = 0;
			}
		}
		total_scanned += sc->nr_scanned;
		if (sc->nr_reclaimed >= sc->swap_cluster_max) {
			ret = sc->nr_reclaimed;
			goto out;
		}

		/*
		 * Try to write back as many pages as we just scanned.  This
		 * tends to cause slow streaming writers to write data to the
		 * disk smoothly, at the dirtying rate, which is nice.   But
		 * that's undesirable in laptop mode, where we *want* lumpy
		 * writeout.  So in laptop mode, write out the whole world.
		 */
		if (total_scanned > sc->swap_cluster_max +
					sc->swap_cluster_max / 2) {
			wakeup_pdflush(laptop_mode ? 0 : total_scanned);
			sc->may_writepage = 1;
		}

		/* Take a nap, wait for some writeback to complete */
		if (sc->nr_scanned && priority < DEF_PRIORITY - 2)
			congestion_wait(WRITE, HZ/10);
	}
	/* top priority shrink_zones still had more to do? don't OOM, then */
	if (!sc->all_unreclaimable && scanning_global_lru(sc))
		ret = sc->nr_reclaimed;
out:
	/*
	 * Now that we've scanned all the zones at this priority level, note
	 * that level within the zone so that the next thread which performs
	 * scanning of this zone will immediately start out at this priority
	 * level.  This affects only the decision whether or not to bring
	 * mapped pages onto the inactive list.
	 */
	if (priority < 0)
		priority = 0;

	if (scanning_global_lru(sc)) {
		for_each_zone_zonelist(zone, z, zonelist, high_zoneidx) {

			if (!cpuset_zone_allowed_hardwall(zone, GFP_KERNEL))
				continue;

			zone->prev_priority = priority;
		}
	} else
		mem_cgroup_record_reclaim_priority(sc->mem_cgroup, priority);

	delayacct_freepages_end();

	return ret;
}

unsigned long ax8swap_try_to_free_pages(struct zonelist *zonelist, int order,
								gfp_t gfp_mask)
{
	struct scan_control sc = {
		.gfp_mask = gfp_mask,
		.may_writepage = !laptop_mode,
		.swap_cluster_max = SWAP_CLUSTER_MAX,
		.may_swap = 1,
		.swappiness = vm_swappiness,
		.order = order,
		.mem_cgroup = NULL,
		.isolate_pages = ax8swap_isolate_pages_global,
	};

	return ax8swap_do_try_to_free_pages(zonelist, &sc);
} 
