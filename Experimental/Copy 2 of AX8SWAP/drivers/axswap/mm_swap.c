/*
 *  linux/mm/swap.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * This file contains the default values for the operation of the
 * Linux VM subsystem. Fine-tuning documentation can be found in
 * Documentation/sysctl/vm.txt.
 * Started 18.12.91
 * Swap aging added 23.2.95, Stephen Tweedie.
 * Buffermem limits added 12.3.98, Rik van Riel.
 */

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm_inline.h>
#include <linux/buffer_head.h>	/* for try_to_release_page() */
#include <linux/percpu_counter.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/backing-dev.h>
#include <linux/memcontrol.h>



/**
 * pagevec_swap_free - try to free swap space from the pages in a pagevec
 * @pvec: pagevec with swapcache pages to free the swap space of
 *
 * The caller needs to hold an extra reference to each page and
 * not hold the page lock on the pages.  This function uses a
 * trylock on the page lock so it may not always free the swap
 * space associated with a page.
 */
void ax8swap_pagevec_swap_free(struct pagevec *pvec)
{
	int i;

	for (i = 0; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];

		if (PageSwapCache(page) && trylock_page(page)) {
			try_to_free_swap(page);
			unlock_page(page);
		}
	}
}
