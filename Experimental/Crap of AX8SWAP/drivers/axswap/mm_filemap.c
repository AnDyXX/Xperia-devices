/*
 *	linux/mm/filemap.c
 *
 * Copyright (C) 1994-1999  Linus Torvalds
 */

/*
 * This file handles the generic file mmap semantics used by
 * most "normal" filesystems (but you don't /have/ to use this:
 * the NFS filesystem used to do this differently, for example)
 */
#define EXTERNAL_SWAP_MODULE

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/compiler.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/aio.h>
#include <linux/capability.h>
#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/hash.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/cpuset.h>
#include <linux/hardirq.h> /* for BUG_ON(!in_atomic()) only */
#include <linux/memcontrol.h>
#include <linux/mm_inline.h> /* for page_is_file_cache() */

#include "hijacked_types.h"
#include "internal.h"

/*
 * FIXME: remove all knowledge of the buffer layer from the core VM
 */
#include <linux/buffer_head.h> /* for generic_osync_inode */

#include <asm/mman.h>


/*
 * Shared mappings implemented 30.11.1994. It's not fully working yet,
 * though.
 *
 * Shared mappings now work. 15.8.1995  Bruno.
 *
 * finished 'unifying' the page and buffer cache and SMP-threaded the
 * page-cache, 21.05.1999, Ingo Molnar <mingo@redhat.com>
 *
 * SMP-threaded pagemap-LRU 1999, Andrea Arcangeli <andrea@suse.de>
 */

/*
 * Lock ordering:
 *
 *  ->i_mmap_lock		(vmtruncate)
 *    ->private_lock		(__free_pte->__set_page_dirty_buffers)
 *      ->swap_lock		(exclusive_swap_page, others)
 *        ->mapping->tree_lock
 *
 *  ->i_mutex
 *    ->i_mmap_lock		(truncate->unmap_mapping_range)
 *
 *  ->mmap_sem
 *    ->i_mmap_lock
 *      ->page_table_lock or pte_lock	(various, mainly in memory.c)
 *        ->mapping->tree_lock	(arch-dependent flush_dcache_mmap_lock)
 *
 *  ->mmap_sem
 *    ->lock_page		(access_process_vm)
 *
 *  ->i_mutex			(generic_file_buffered_write)
 *    ->mmap_sem		(fault_in_pages_readable->do_page_fault)
 *
 *  ->i_mutex
 *    ->i_alloc_sem             (various)
 *
 *  ->inode_lock
 *    ->sb_lock			(fs/fs-writeback.c)
 *    ->mapping->tree_lock	(__sync_single_inode)
 *
 *  ->i_mmap_lock
 *    ->anon_vma.lock		(vma_adjust)
 *
 *  ->anon_vma.lock
 *    ->page_table_lock or pte_lock	(anon_vma_prepare and various)
 *
 *  ->page_table_lock or pte_lock
 *    ->swap_lock		(try_to_unmap_one)
 *    ->private_lock		(try_to_unmap_one)
 *    ->tree_lock		(try_to_unmap_one)
 *    ->zone.lru_lock		(follow_page->mark_page_accessed)
 *    ->zone.lru_lock		(check_pte_range->isolate_lru_page)
 *    ->private_lock		(page_remove_rmap->set_page_dirty)
 *    ->tree_lock		(page_remove_rmap->set_page_dirty)
 *    ->inode_lock		(page_remove_rmap->set_page_dirty)
 *    ->inode_lock		(zap_pte_range->set_page_dirty)
 *    ->private_lock		(zap_pte_range->__set_page_dirty_buffers)
 *
 *  ->task->proc_lock
 *    ->dcache_lock		(proc_pid_lookup)
 */

/*
 * Remove a page from the page cache and free it. Caller has to make
 * sure the page is locked and that nobody else uses it - or that usage
 * is safe.  The caller must hold the mapping's tree_lock.
 */
void ax8swap___remove_from_page_cache(struct page *page)
{
	struct address_space *mapping = page->mapping;

	radix_tree_delete(&mapping->page_tree, page->index);
	page->mapping = NULL;
	mapping->nrpages--;
	__dec_zone_page_state(page, NR_FILE_PAGES);
	BUG_ON(page_mapped(page));
	mem_cgroup_uncharge_cache_page(page);

	/*
	 * Some filesystems seem to re-dirty the page even after
	 * the VM has canceled the dirty bit (eg ext3 journaling).
	 *
	 * Fix it up by doing a final dirty accounting check after
	 * having removed the page entirely.
	 */
	if (PageDirty(page) && mapping_cap_account_dirty(mapping)) {
		dec_zone_page_state(page, NR_FILE_DIRTY);
		dec_bdi_stat(mapping->backing_dev_info, BDI_RECLAIMABLE);
	}
}

void ax8swap_remove_from_page_cache(struct page *page)
{
	struct address_space *mapping = page->mapping;

	BUG_ON(!PageLocked(page));

	spin_lock_irq(&mapping->tree_lock);
	__remove_from_page_cache(page);
	spin_unlock_irq(&mapping->tree_lock);
}

int ax8swap_sync_page(void *word)
{
	struct address_space *mapping;
	struct page *page;

	page = container_of((unsigned long *)word, struct page, flags);

	/*
	 * page_mapping() is being called without PG_locked held.
	 * Some knowledge of the state and use of the page is used to
	 * reduce the requirements down to a memory barrier.
	 * The danger here is of a stale page_mapping() return value
	 * indicating a struct address_space different from the one it's
	 * associated with when it is associated with one.
	 * After smp_mb(), it's either the correct page_mapping() for
	 * the page, or an old page_mapping() and the page's own
	 * page_mapping() has gone NULL.
	 * The ->sync_page() address_space operation must tolerate
	 * page_mapping() going NULL. By an amazing coincidence,
	 * this comes about because none of the users of the page
	 * in the ->sync_page() methods make essential use of the
	 * page_mapping(), merely passing the page down to the backing
	 * device's unplug functions when it's non-NULL, which in turn
	 * ignore it for all cases but swap, where only page_private(page) is
	 * of interest. When page_mapping() does go NULL, the entire
	 * call stack gracefully ignores the page and returns.
	 * -- wli
	 */
	smp_mb();
	mapping = page_mapping(page);
	if (mapping && mapping->a_ops && mapping->a_ops->sync_page)
		mapping->a_ops->sync_page(page);
	io_schedule();
	return 0;
}


