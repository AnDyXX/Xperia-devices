/*
 * Resizable virtual memory filesystem for Linux.
 *
 * Copyright (C) 2000 Linus Torvalds.
 *		 2000 Transmeta Corp.
 *		 2000-2001 Christoph Rohland
 *		 2000-2001 SAP AG
 *		 2002 Red Hat Inc.
 * Copyright (C) 2002-2005 Hugh Dickins.
 * Copyright (C) 2002-2005 VERITAS Software Corporation.
 * Copyright (C) 2004 Andi Kleen, SuSE Labs
 *
 * Extended attribute support for tmpfs:
 * Copyright (c) 2004, Luke Kenneth Casson Leighton <lkcl@lkcl.net>
 * Copyright (c) 2004 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *
 * tiny-shmem:
 * Copyright (c) 2004, 2008 Matt Mackall <mpm@selenic.com>
 *
 * This file is released under the GPL.
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/vfs.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/swap.h>

#include <linux/shmem_fs.h>
#include <linux/mman.h>


/*
 * This virtual memory filesystem is heavily based on the ramfs. It
 * extends ramfs by the ability to use swap and honor resource limits
 * which makes it a completely usable filesystem.
 */

#include <linux/xattr.h>
#include <linux/exportfs.h>
#include <linux/generic_acl.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>
#include <linux/shmem_fs.h>
#include <linux/writeback.h>
#include <linux/vfs.h>
#include <linux/blkdev.h>
#include <linux/security.h>
#include <linux/swapops.h>
#include <linux/mempolicy.h>
#include <linux/namei.h>
#include <linux/ctype.h>
#include <linux/migrate.h>
#include <linux/highmem.h>
#include <linux/seq_file.h>
#include <linux/magic.h>

#include <asm/uaccess.h>
#include <asm/div64.h>
#include <asm/pgtable.h>

#include <linux/fs.h>

#include "hijacked_types.h"

#define ENTRIES_PER_PAGE (PAGE_CACHE_SIZE/sizeof(unsigned long))
#define ENTRIES_PER_PAGEPAGE (ENTRIES_PER_PAGE*ENTRIES_PER_PAGE)
#define BLOCKS_PER_PAGE  (PAGE_CACHE_SIZE/512)

#define SHMEM_MAX_INDEX  (SHMEM_NR_DIRECT + (ENTRIES_PER_PAGEPAGE/2) * (ENTRIES_PER_PAGE+1))
#define SHMEM_MAX_BYTES  ((unsigned long long)SHMEM_MAX_INDEX << PAGE_CACHE_SHIFT)

#define VM_ACCT(size)    (PAGE_CACHE_ALIGN(size) >> PAGE_SHIFT)

/* info->flags needs VM_flags to handle pagein/truncate races efficiently */
#define SHMEM_PAGEIN	 VM_READ
#define SHMEM_TRUNCATE	 VM_WRITE

/* Definition to limit shmem_truncate's steps between cond_rescheds */
#define LATENCY_LIMIT	 64

/* Pretend that each entry is of this size in directory's i_size */
#define BOGO_DIRENT_SIZE 20

#ifdef CONFIG_TMPFS
 unsigned long ax8swap_shmem_default_max_blocks(void)
{
	return totalram_pages / 2;
}

 unsigned long ax8swap_shmem_default_max_inodes(void)
{
	return min(totalram_pages - totalhigh_pages, totalram_pages / 2);
}
#endif

int ax8swap_shmem_getpage(struct inode *inode, unsigned long idx,
			 struct page **pagep, enum sgp_type sgp, int *type);

static inline struct page *ax8swap_shmem_dir_alloc(gfp_t gfp_mask)
{
	/*
	 * The above definition of ENTRIES_PER_PAGE, and the use of
	 * BLOCKS_PER_PAGE on indirect pages, assume PAGE_CACHE_SIZE:
	 * might be reconsidered if it ever diverges from PAGE_SIZE.
	 *
	 * Mobility flags are masked out as swap vectors cannot move
	 */
	return alloc_pages((gfp_mask & ~GFP_MOVABLE_MASK) | __GFP_ZERO,
				PAGE_CACHE_SHIFT-PAGE_SHIFT);
}

static inline void ax8swap_shmem_dir_free(struct page *page)
{
	__free_pages(page, PAGE_CACHE_SHIFT-PAGE_SHIFT);
}

static struct page **ax8swap_shmem_dir_map(struct page *page)
{
	return (struct page **)kmap_atomic(page, KM_USER0);
}

static inline void ax8swap_shmem_dir_unmap(struct page **dir)
{
	kunmap_atomic(dir, KM_USER0);
}

static swp_entry_t *ax8swap_shmem_swp_map(struct page *page)
{
	return (swp_entry_t *)kmap_atomic(page, KM_USER1);
}

static inline void ax8swap_shmem_swp_balance_unmap(void)
{
	/*
	 * When passing a pointer to an i_direct entry, to code which
	 * also handles indirect entries and so will shmem_swp_unmap,
	 * we must arrange for the preempt count to remain in balance.
	 * What kmap_atomic of a lowmem page does depends on config
	 * and architecture, so pretend to kmap_atomic some lowmem page.
	 */
	(void) kmap_atomic(ZERO_PAGE(0), KM_USER1);
}

static inline void ax8swap_shmem_swp_unmap(swp_entry_t *entry)
{
	kunmap_atomic(entry, KM_USER1);
}

static inline struct shmem_sb_info *SHMEM_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

/*
 * shmem_file_setup pre-accounts the whole fixed size of a VM object,
 * for shared memory and for shared anonymous (/dev/zero) mappings
 * (unless MAP_NORESERVE and sysctl_overcommit_memory <= 1),
 * consistent with the pre-accounting of private mappings ...
 */
static inline int ax8swap_shmem_acct_size(unsigned long flags, loff_t size)
{
	return (flags & VM_NORESERVE) ?
		0 : security_vm_enough_memory_kern(VM_ACCT(size));
}

static inline void ax8swap_shmem_unacct_size(unsigned long flags, loff_t size)
{
	if (!(flags & VM_NORESERVE))
		vm_unacct_memory(VM_ACCT(size));
}

/*
 * ... whereas tmpfs objects are accounted incrementally as
 * pages are allocated, in order to allow huge sparse files.
 * shmem_getpage reports shmem_acct_block failure as -ENOSPC not -ENOMEM,
 * so that a failure on a sparse tmpfs mapping will give SIGBUS not OOM.
 */
static inline int ax8swap_shmem_acct_block(unsigned long flags)
{
	return (flags & VM_NORESERVE) ?
		security_vm_enough_memory_kern(VM_ACCT(PAGE_CACHE_SIZE)) : 0;
}

static inline void ax8swap_shmem_unacct_blocks(unsigned long flags, long pages)
{
	if (flags & VM_NORESERVE)
		vm_unacct_memory(pages * VM_ACCT(PAGE_CACHE_SIZE));
}

static void ax8swap_shmem_free_blocks(struct inode *inode, long pages)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(inode->i_sb);
	if (sbinfo->max_blocks) {
		spin_lock(&sbinfo->stat_lock);
		sbinfo->free_blocks += pages;
		inode->i_blocks -= pages*BLOCKS_PER_PAGE;
		spin_unlock(&sbinfo->stat_lock);
	}
}

 int ax8swap_shmem_reserve_inode(struct super_block *sb)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(sb);
	if (sbinfo->max_inodes) {
		spin_lock(&sbinfo->stat_lock);
		if (!sbinfo->free_inodes) {
			spin_unlock(&sbinfo->stat_lock);
			return -ENOSPC;
		}
		sbinfo->free_inodes--;
		spin_unlock(&sbinfo->stat_lock);
	}
	return 0;
}

static void ax8swap_shmem_free_inode(struct super_block *sb)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(sb);
	if (sbinfo->max_inodes) {
		spin_lock(&sbinfo->stat_lock);
		sbinfo->free_inodes++;
		spin_unlock(&sbinfo->stat_lock);
	}
}

/**
 * shmem_recalc_inode - recalculate the size of an inode
 * @inode: inode to recalc
 *
 * We have to calculate the free blocks since the mm can drop
 * undirtied hole pages behind our back.
 *
 * But normally   info->alloced == inode->i_mapping->nrpages + info->swapped
 * So mm freed is info->alloced - (inode->i_mapping->nrpages + info->swapped)
 *
 * It has to be called with the spinlock held.
 */
static void ax8swap_shmem_recalc_inode(struct inode *inode)
{
	struct shmem_inode_info *info = SHMEM_I(inode);
	long freed;

	freed = info->alloced - info->swapped - inode->i_mapping->nrpages;
	if (freed > 0) {
		info->alloced -= freed;
		ax8swap_shmem_unacct_blocks(info->flags, freed);
		ax8swap_shmem_free_blocks(inode, freed);
	}
}

/**
 * shmem_swp_entry - find the swap vector position in the info structure
 * @info:  info structure for the inode
 * @index: index of the page to find
 * @page:  optional page to add to the structure. Has to be preset to
 *         all zeros
 *
 * If there is no space allocated yet it will return NULL when
 * page is NULL, else it will use the page for the needed block,
 * setting it to NULL on return to indicate that it has been used.
 *
 * The swap vector is organized the following way:
 *
 * There are SHMEM_NR_DIRECT entries directly stored in the
 * shmem_inode_info structure. So small files do not need an addional
 * allocation.
 *
 * For pages with index > SHMEM_NR_DIRECT there is the pointer
 * i_indirect which points to a page which holds in the first half
 * doubly indirect blocks, in the second half triple indirect blocks:
 *
 * For an artificial ENTRIES_PER_PAGE = 4 this would lead to the
 * following layout (for SHMEM_NR_DIRECT == 16):
 *
 * i_indirect -> dir --> 16-19
 * 	      |	     +-> 20-23
 * 	      |
 * 	      +-->dir2 --> 24-27
 * 	      |	       +-> 28-31
 * 	      |	       +-> 32-35
 * 	      |	       +-> 36-39
 * 	      |
 * 	      +-->dir3 --> 40-43
 * 	       	       +-> 44-47
 * 	      	       +-> 48-51
 * 	      	       +-> 52-55
 */
swp_entry_t *ax8swap_shmem_swp_entry(struct shmem_inode_info *info, unsigned long index, struct page **page)
{
	unsigned long offset;
	struct page **dir;
	struct page *subdir;

	if (index < SHMEM_NR_DIRECT) {
		ax8swap_shmem_swp_balance_unmap();
		return info->i_direct+index;
	}
	if (!info->i_indirect) {
		if (page) {
			info->i_indirect = *page;
			*page = NULL;
		}
		return NULL;			/* need another page */
	}

	index -= SHMEM_NR_DIRECT;
	offset = index % ENTRIES_PER_PAGE;
	index /= ENTRIES_PER_PAGE;
	dir = ax8swap_shmem_dir_map(info->i_indirect);

	if (index >= ENTRIES_PER_PAGE/2) {
		index -= ENTRIES_PER_PAGE/2;
		dir += ENTRIES_PER_PAGE/2 + index/ENTRIES_PER_PAGE;
		index %= ENTRIES_PER_PAGE;
		subdir = *dir;
		if (!subdir) {
			if (page) {
				*dir = *page;
				*page = NULL;
			}
			ax8swap_shmem_dir_unmap(dir);
			return NULL;		/* need another page */
		}
		ax8swap_shmem_dir_unmap(dir);
		dir = ax8swap_shmem_dir_map(subdir);
	}

	dir += index;
	subdir = *dir;
	if (!subdir) {
		if (!page || !(subdir = *page)) {
			ax8swap_shmem_dir_unmap(dir);
			return NULL;		/* need a page */
		}
		*dir = subdir;
		*page = NULL;
	}
	ax8swap_shmem_dir_unmap(dir);
	return ax8swap_shmem_swp_map(subdir) + offset;
}

static void ax8swap_shmem_swp_set(struct shmem_inode_info *info, swp_entry_t *entry, unsigned long value)
{
	long incdec = value? 1: -1;

	entry->val = value;
	info->swapped += incdec;
	if ((unsigned long)(entry - info->i_direct) >= SHMEM_NR_DIRECT) {
		struct page *page = kmap_atomic_to_page(entry);
		set_page_private(page, page_private(page) + incdec);
	}
}

/**
 * shmem_swp_alloc - get the position of the swap entry for the page.
 * @info:	info structure for the inode
 * @index:	index of the page to find
 * @sgp:	check and recheck i_size? skip allocation?
 *
 * If the entry does not exist, allocate it.
 */
swp_entry_t *ax8swap_shmem_swp_alloc(struct shmem_inode_info *info, unsigned long index, enum sgp_type sgp)
{
	struct inode *inode = &info->vfs_inode;
	struct shmem_sb_info *sbinfo = SHMEM_SB(inode->i_sb);
	struct page *page = NULL;
	swp_entry_t *entry;

	if (sgp != SGP_WRITE &&
	    ((loff_t) index << PAGE_CACHE_SHIFT) >= i_size_read(inode))
		return ERR_PTR(-EINVAL);

	while (!(entry = ax8swap_shmem_swp_entry(info, index, &page))) {
		if (sgp == SGP_READ)
			return ax8swap_shmem_swp_map(ZERO_PAGE(0));
		/*
		 * Test free_blocks against 1 not 0, since we have 1 data
		 * page (and perhaps indirect index pages) yet to allocate:
		 * a waste to allocate index if we cannot allocate data.
		 */
		if (sbinfo->max_blocks) {
			spin_lock(&sbinfo->stat_lock);
			if (sbinfo->free_blocks <= 1) {
				spin_unlock(&sbinfo->stat_lock);
				return ERR_PTR(-ENOSPC);
			}
			sbinfo->free_blocks--;
			inode->i_blocks += BLOCKS_PER_PAGE;
			spin_unlock(&sbinfo->stat_lock);
		}

		spin_unlock(&info->lock);
		page = ax8swap_shmem_dir_alloc(mapping_gfp_mask(inode->i_mapping));
		if (page)
			set_page_private(page, 0);
		spin_lock(&info->lock);

		if (!page) {
			ax8swap_shmem_free_blocks(inode, 1);
			return ERR_PTR(-ENOMEM);
		}
		if (sgp != SGP_WRITE &&
		    ((loff_t) index << PAGE_CACHE_SHIFT) >= i_size_read(inode)) {
			entry = ERR_PTR(-EINVAL);
			break;
		}
		if (info->next_index <= index)
			info->next_index = index + 1;
	}
	if (page) {
		/* another task gave its page, or truncated the file */
		ax8swap_shmem_free_blocks(inode, 1);
		ax8swap_shmem_dir_free(page);
	}
	if (info->next_index <= index && !IS_ERR(entry))
		info->next_index = index + 1;
	return entry;
}

/**
 * shmem_free_swp - free some swap entries in a directory
 * @dir:        pointer to the directory
 * @edir:       pointer after last entry of the directory
 * @punch_lock: pointer to spinlock when needed for the holepunch case
 */
int ax8swap_shmem_free_swp(swp_entry_t *dir, swp_entry_t *edir,
						spinlock_t *punch_lock)
{
	spinlock_t *punch_unlock = NULL;
	swp_entry_t *ptr;
	int freed = 0;

	for (ptr = dir; ptr < edir; ptr++) {
		if (ptr->val) {
			if (unlikely(punch_lock)) {
				punch_unlock = punch_lock;
				punch_lock = NULL;
				spin_lock(punch_unlock);
				if (!ptr->val)
					continue;
			}
			free_swap_and_cache(*ptr);
			*ptr = (swp_entry_t){0};
			freed++;
		}
	}
	if (punch_unlock)
		spin_unlock(punch_unlock);
	return freed;
}

static int ax8swap_shmem_map_and_free_swp(struct page *subdir, int offset,
		int limit, struct page ***dir, spinlock_t *punch_lock)
{
	swp_entry_t *ptr;
	int freed = 0;

	ptr = ax8swap_shmem_swp_map(subdir);
	for (; offset < limit; offset += LATENCY_LIMIT) {
		int size = limit - offset;
		if (size > LATENCY_LIMIT)
			size = LATENCY_LIMIT;
		freed += ax8swap_shmem_free_swp(ptr+offset, ptr+offset+size,
							punch_lock);
		if (need_resched()) {
			ax8swap_shmem_swp_unmap(ptr);
			if (*dir) {
				ax8swap_shmem_dir_unmap(*dir);
				*dir = NULL;
			}
			cond_resched();
			ptr = ax8swap_shmem_swp_map(subdir);
		}
	}
	ax8swap_shmem_swp_unmap(ptr);
	return freed;
}

static void ax8swap_shmem_free_pages(struct list_head *next)
{
	struct page *page;
	int freed = 0;

	do {
		page = container_of(next, struct page, lru);
		next = next->next;
		ax8swap_shmem_dir_free(page);
		freed++;
		if (freed >= LATENCY_LIMIT) {
			cond_resched();
			freed = 0;
		}
	} while (next);
}

void ax8swap_shmem_truncate_range(struct inode *inode, loff_t start, loff_t end)
{
	struct shmem_inode_info *info = SHMEM_I(inode);
	unsigned long idx;
	unsigned long size;
	unsigned long limit;
	unsigned long stage;
	unsigned long diroff;
	struct page **dir;
	struct page *topdir;
	struct page *middir;
	struct page *subdir;
	swp_entry_t *ptr;
	LIST_HEAD(pages_to_free);
	long nr_pages_to_free = 0;
	long nr_swaps_freed = 0;
	int offset;
	int freed;
	int punch_hole;
	spinlock_t *needs_lock;
	spinlock_t *punch_lock;
	unsigned long upper_limit;

	inode->i_ctime = inode->i_mtime = CURRENT_TIME;
	idx = (start + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	if (idx >= info->next_index)
		return;

	spin_lock(&info->lock);
	info->flags |= SHMEM_TRUNCATE;
	if (likely(end == (loff_t) -1)) {
		limit = info->next_index;
		upper_limit = SHMEM_MAX_INDEX;
		info->next_index = idx;
		needs_lock = NULL;
		punch_hole = 0;
	} else {
		if (end + 1 >= inode->i_size) {	/* we may free a little more */
			limit = (inode->i_size + PAGE_CACHE_SIZE - 1) >>
							PAGE_CACHE_SHIFT;
			upper_limit = SHMEM_MAX_INDEX;
		} else {
			limit = (end + 1) >> PAGE_CACHE_SHIFT;
			upper_limit = limit;
		}
		needs_lock = &info->lock;
		punch_hole = 1;
	}

	topdir = info->i_indirect;
	if (topdir && idx <= SHMEM_NR_DIRECT && !punch_hole) {
		info->i_indirect = NULL;
		nr_pages_to_free++;
		list_add(&topdir->lru, &pages_to_free);
	}
	spin_unlock(&info->lock);

	if (info->swapped && idx < SHMEM_NR_DIRECT) {
		ptr = info->i_direct;
		size = limit;
		if (size > SHMEM_NR_DIRECT)
			size = SHMEM_NR_DIRECT;
		nr_swaps_freed = ax8swap_shmem_free_swp(ptr+idx, ptr+size, needs_lock);
	}

	/*
	 * If there are no indirect blocks or we are punching a hole
	 * below indirect blocks, nothing to be done.
	 */
	if (!topdir || limit <= SHMEM_NR_DIRECT)
		goto done2;

	/*
	 * The truncation case has already dropped info->lock, and we're safe
	 * because i_size and next_index have already been lowered, preventing
	 * access beyond.  But in the punch_hole case, we still need to take
	 * the lock when updating the swap directory, because there might be
	 * racing accesses by shmem_getpage(SGP_CACHE), shmem_unuse_inode or
	 * shmem_writepage.  However, whenever we find we can remove a whole
	 * directory page (not at the misaligned start or end of the range),
	 * we first NULLify its pointer in the level above, and then have no
	 * need to take the lock when updating its contents: needs_lock and
	 * punch_lock (either pointing to info->lock or NULL) manage this.
	 */

	upper_limit -= SHMEM_NR_DIRECT;
	limit -= SHMEM_NR_DIRECT;
	idx = (idx > SHMEM_NR_DIRECT)? (idx - SHMEM_NR_DIRECT): 0;
	offset = idx % ENTRIES_PER_PAGE;
	idx -= offset;

	dir = ax8swap_shmem_dir_map(topdir);
	stage = ENTRIES_PER_PAGEPAGE/2;
	if (idx < ENTRIES_PER_PAGEPAGE/2) {
		middir = topdir;
		diroff = idx/ENTRIES_PER_PAGE;
	} else {
		dir += ENTRIES_PER_PAGE/2;
		dir += (idx - ENTRIES_PER_PAGEPAGE/2)/ENTRIES_PER_PAGEPAGE;
		while (stage <= idx)
			stage += ENTRIES_PER_PAGEPAGE;
		middir = *dir;
		if (*dir) {
			diroff = ((idx - ENTRIES_PER_PAGEPAGE/2) %
				ENTRIES_PER_PAGEPAGE) / ENTRIES_PER_PAGE;
			if (!diroff && !offset && upper_limit >= stage) {
				if (needs_lock) {
					spin_lock(needs_lock);
					*dir = NULL;
					spin_unlock(needs_lock);
					needs_lock = NULL;
				} else
					*dir = NULL;
				nr_pages_to_free++;
				list_add(&middir->lru, &pages_to_free);
			}
			ax8swap_shmem_dir_unmap(dir);
			dir = ax8swap_shmem_dir_map(middir);
		} else {
			diroff = 0;
			offset = 0;
			idx = stage;
		}
	}

	for (; idx < limit; idx += ENTRIES_PER_PAGE, diroff++) {
		if (unlikely(idx == stage)) {
			ax8swap_shmem_dir_unmap(dir);
			dir = ax8swap_shmem_dir_map(topdir) +
			    ENTRIES_PER_PAGE/2 + idx/ENTRIES_PER_PAGEPAGE;
			while (!*dir) {
				dir++;
				idx += ENTRIES_PER_PAGEPAGE;
				if (idx >= limit)
					goto done1;
			}
			stage = idx + ENTRIES_PER_PAGEPAGE;
			middir = *dir;
			if (punch_hole)
				needs_lock = &info->lock;
			if (upper_limit >= stage) {
				if (needs_lock) {
					spin_lock(needs_lock);
					*dir = NULL;
					spin_unlock(needs_lock);
					needs_lock = NULL;
				} else
					*dir = NULL;
				nr_pages_to_free++;
				list_add(&middir->lru, &pages_to_free);
			}
			ax8swap_shmem_dir_unmap(dir);
			cond_resched();
			dir = ax8swap_shmem_dir_map(middir);
			diroff = 0;
		}
		punch_lock = needs_lock;
		subdir = dir[diroff];
		if (subdir && !offset && upper_limit-idx >= ENTRIES_PER_PAGE) {
			if (needs_lock) {
				spin_lock(needs_lock);
				dir[diroff] = NULL;
				spin_unlock(needs_lock);
				punch_lock = NULL;
			} else
				dir[diroff] = NULL;
			nr_pages_to_free++;
			list_add(&subdir->lru, &pages_to_free);
		}
		if (subdir && page_private(subdir) /* has swap entries */) {
			size = limit - idx;
			if (size > ENTRIES_PER_PAGE)
				size = ENTRIES_PER_PAGE;
			freed = ax8swap_shmem_map_and_free_swp(subdir,
					offset, size, &dir, punch_lock);
			if (!dir)
				dir = ax8swap_shmem_dir_map(middir);
			nr_swaps_freed += freed;
			if (offset || punch_lock) {
				spin_lock(&info->lock);
				set_page_private(subdir,
					page_private(subdir) - freed);
				spin_unlock(&info->lock);
			} else
				BUG_ON(page_private(subdir) != freed);
		}
		offset = 0;
	}
done1:
	ax8swap_shmem_dir_unmap(dir);
done2:
	if (inode->i_mapping->nrpages && (info->flags & SHMEM_PAGEIN)) {
		/*
		 * Call truncate_inode_pages again: racing shmem_unuse_inode
		 * may have swizzled a page in from swap since vmtruncate or
		 * generic_delete_inode did it, before we lowered next_index.
		 * Also, though shmem_getpage checks i_size before adding to
		 * cache, no recheck after: so fix the narrow window there too.
		 *
		 * Recalling truncate_inode_pages_range and unmap_mapping_range
		 * every time for punch_hole (which never got a chance to clear
		 * SHMEM_PAGEIN at the start of vmtruncate_range) is expensive,
		 * yet hardly ever necessary: try to optimize them out later.
		 */
		truncate_inode_pages_range(inode->i_mapping, start, end);
		if (punch_hole)
			unmap_mapping_range(inode->i_mapping, start,
							end - start, 1);
	}

	spin_lock(&info->lock);
	info->flags &= ~SHMEM_TRUNCATE;
	info->swapped -= nr_swaps_freed;
	if (nr_pages_to_free)
		ax8swap_shmem_free_blocks(inode, nr_pages_to_free);
	ax8swap_shmem_recalc_inode(inode);
	spin_unlock(&info->lock);

	/*
	 * Empty swap vector directory pages to be freed?
	 */
	if (!list_empty(&pages_to_free)) {
		pages_to_free.prev->next = NULL;
		ax8swap_shmem_free_pages(pages_to_free.next);
	}
}

void ax8swap_shmem_truncate(struct inode *inode)
{
	ax8swap_shmem_truncate_range(inode, inode->i_size, (loff_t)-1);
}

int ax8swap_shmem_notify_change(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	struct page *page = NULL;
	int error;

	if (S_ISREG(inode->i_mode) && (attr->ia_valid & ATTR_SIZE)) {
		if (attr->ia_size < inode->i_size) {
			/*
			 * If truncating down to a partial page, then
			 * if that page is already allocated, hold it
			 * in memory until the truncation is over, so
			 * truncate_partial_page cannnot miss it were
			 * it assigned to swap.
			 */
			if (attr->ia_size & (PAGE_CACHE_SIZE-1)) {
				(void) ax8swap_shmem_getpage(inode,
					attr->ia_size>>PAGE_CACHE_SHIFT,
						&page, SGP_READ, NULL);
				if (page)
					unlock_page(page);
			}
			/*
			 * Reset SHMEM_PAGEIN flag so that shmem_truncate can
			 * detect if any pages might have been added to cache
			 * after truncate_inode_pages.  But we needn't bother
			 * if it's being fully truncated to zero-length: the
			 * nrpages check is efficient enough in that case.
			 */
			if (attr->ia_size) {
				struct shmem_inode_info *info = SHMEM_I(inode);
				spin_lock(&info->lock);
				info->flags &= ~SHMEM_PAGEIN;
				spin_unlock(&info->lock);
			}
		}
	}

	error = inode_change_ok(inode, attr);
	if (!error)
		error = inode_setattr(inode, attr);
#ifdef CONFIG_TMPFS_POSIX_ACL
	if (!error && (attr->ia_valid & ATTR_MODE))
		error = generic_acl_chmod(inode, &shmem_acl_ops);
#endif
	if (page)
		page_cache_release(page);
	return error;
}

 void ax8swap_shmem_delete_inode(struct inode *inode)
{
	struct shmem_inode_info *info = SHMEM_I(inode);

	if (inode->i_op->truncate == ax8swap_shmem_truncate) {
		truncate_inode_pages(inode->i_mapping, 0);
		ax8swap_shmem_unacct_size(info->flags, inode->i_size);
		inode->i_size = 0;
		ax8swap_shmem_truncate(inode);
		if (!list_empty(&info->swaplist)) {
			mutex_lock(ax8swap_shmem_swaplist_mutex);
			list_del_init(&info->swaplist);
			mutex_unlock(ax8swap_shmem_swaplist_mutex);
		}
	}
	BUG_ON(inode->i_blocks);
	ax8swap_shmem_free_inode(inode->i_sb);
	clear_inode(inode);
}

static inline int ax8swap_shmem_find_swp(swp_entry_t entry, swp_entry_t *dir, swp_entry_t *edir)
{
	swp_entry_t *ptr;

	for (ptr = dir; ptr < edir; ptr++) {
		if (ptr->val == entry.val)
			return ptr - dir;
	}
	return -1;
}

static int ax8swap_shmem_unuse_inode(struct shmem_inode_info *info, swp_entry_t entry, struct page *page)
{
	struct inode *inode;
	unsigned long idx;
	unsigned long size;
	unsigned long limit;
	unsigned long stage;
	struct page **dir;
	struct page *subdir;
	swp_entry_t *ptr;
	int offset;
	int error;

	idx = 0;
	ptr = info->i_direct;
	spin_lock(&info->lock);
	if (!info->swapped) {
		list_del_init(&info->swaplist);
		goto lost2;
	}
	limit = info->next_index;
	size = limit;
	if (size > SHMEM_NR_DIRECT)
		size = SHMEM_NR_DIRECT;
	offset = ax8swap_shmem_find_swp(entry, ptr, ptr+size);
	if (offset >= 0)
		goto found;
	if (!info->i_indirect)
		goto lost2;

	dir = ax8swap_shmem_dir_map(info->i_indirect);
	stage = SHMEM_NR_DIRECT + ENTRIES_PER_PAGEPAGE/2;

	for (idx = SHMEM_NR_DIRECT; idx < limit; idx += ENTRIES_PER_PAGE, dir++) {
		if (unlikely(idx == stage)) {
			ax8swap_shmem_dir_unmap(dir-1);
			if (cond_resched_lock(&info->lock)) {
				/* check it has not been truncated */
				if (limit > info->next_index) {
					limit = info->next_index;
					if (idx >= limit)
						goto lost2;
				}
			}
			dir = ax8swap_shmem_dir_map(info->i_indirect) +
			    ENTRIES_PER_PAGE/2 + idx/ENTRIES_PER_PAGEPAGE;
			while (!*dir) {
				dir++;
				idx += ENTRIES_PER_PAGEPAGE;
				if (idx >= limit)
					goto lost1;
			}
			stage = idx + ENTRIES_PER_PAGEPAGE;
			subdir = *dir;
			ax8swap_shmem_dir_unmap(dir);
			dir = ax8swap_shmem_dir_map(subdir);
		}
		subdir = *dir;
		if (subdir && page_private(subdir)) {
			ptr = ax8swap_shmem_swp_map(subdir);
			size = limit - idx;
			if (size > ENTRIES_PER_PAGE)
				size = ENTRIES_PER_PAGE;
			offset = ax8swap_shmem_find_swp(entry, ptr, ptr+size);
			ax8swap_shmem_swp_unmap(ptr);
			if (offset >= 0) {
				ax8swap_shmem_dir_unmap(dir);
				goto found;
			}
		}
	}
lost1:
	ax8swap_shmem_dir_unmap(dir-1);
lost2:
	spin_unlock(&info->lock);
	return 0;
found:
	idx += offset;
	inode = igrab(&info->vfs_inode);
	spin_unlock(&info->lock);

	/*
	 * Move _head_ to start search for next from here.
	 * But be careful: shmem_delete_inode checks list_empty without taking
	 * mutex, and there's an instant in list_move_tail when info->swaplist
	 * would appear empty, if it were the only one on shmem_swaplist.  We
	 * could avoid doing it if inode NULL; or use this minor optimization.
	 */
	if ((*ax8swap_shmem_swaplist).next != &info->swaplist)
		list_move_tail(ax8swap_shmem_swaplist, &info->swaplist);
	mutex_unlock(ax8swap_shmem_swaplist_mutex);

	error = 1;
	if (!inode)
		goto out;
	/*
	 * Charge page using GFP_KERNEL while we can wait.
	 * Charged back to the user(not to caller) when swap account is used.
	 * add_to_page_cache() will be called with GFP_NOWAIT.
	 */
	error = mem_cgroup_cache_charge(page, current->mm, GFP_KERNEL);
	if (error)
		goto out;
	error = radix_tree_preload(GFP_KERNEL);
	if (error) {
		mem_cgroup_uncharge_cache_page(page);
		goto out;
	}
	error = 1;

	spin_lock(&info->lock);
	ptr = ax8swap_shmem_swp_entry(info, idx, NULL);
	if (ptr && ptr->val == entry.val) {
		error = add_to_page_cache_locked(page, inode->i_mapping,
						idx, GFP_NOWAIT);
		/* does mem_cgroup_uncharge_cache_page on error */
	} else	/* we must compensate for our precharge above */
		mem_cgroup_uncharge_cache_page(page);

	if (error == -EEXIST) {
		struct page *filepage = find_get_page(inode->i_mapping, idx);
		error = 1;
		if (filepage) {
			/*
			 * There might be a more uptodate page coming down
			 * from a stacked writepage: forget our swappage if so.
			 */
			if (PageUptodate(filepage))
				error = 0;
			page_cache_release(filepage);
		}
	}
	if (!error) {
		delete_from_swap_cache(page);
		set_page_dirty(page);
		info->flags |= SHMEM_PAGEIN;
		ax8swap_shmem_swp_set(info, ptr, 0);
		swap_free(entry);
		error = 1;	/* not an error, but entry was found */
	}
	if (ptr)
		ax8swap_shmem_swp_unmap(ptr);
	spin_unlock(&info->lock);
	radix_tree_preload_end();
out:
	unlock_page(page);
	page_cache_release(page);
	iput(inode);		/* allows for NULL */
	return error;
}

/*
 * shmem_unuse() search for an eventually swapped out shmem page.
 */
int ax8swap_shmem_unuse(swp_entry_t entry, struct page *page)
{
	struct list_head *p, *next;
	struct shmem_inode_info *info;
	int found = 0;

	mutex_lock(ax8swap_shmem_swaplist_mutex);
	list_for_each_safe(p, next, ax8swap_shmem_swaplist) {
		info = list_entry(p, struct shmem_inode_info, swaplist);
		found = ax8swap_shmem_unuse_inode(info, entry, page);
		cond_resched();
		if (found)
			goto out;
	}
	mutex_unlock(ax8swap_shmem_swaplist_mutex);
out:	return found;	/* 0 or 1 or -ENOMEM */
}

/*
 * Move the page from the page cache to the swap cache.
 */
int ax8swap_shmem_writepage(struct page *page, struct writeback_control *wbc)
{
	struct shmem_inode_info *info;
	swp_entry_t *entry, swap;
	struct address_space *mapping;
	unsigned long index;
	struct inode *inode;

	BUG_ON(!PageLocked(page));
	mapping = page->mapping;
	index = page->index;
	inode = mapping->host;
	info = SHMEM_I(inode);
	if (info->flags & VM_LOCKED)
		goto redirty;
	if (!total_swap_pages)
		goto redirty;

	/*
	 * shmem_backing_dev_info's capabilities prevent regular writeback or
	 * sync from ever calling shmem_writepage; but a stacking filesystem
	 * may use the ->writepage of its underlying filesystem, in which case
	 * tmpfs should write out to swap only in response to memory pressure,
	 * and not for pdflush or sync.  However, in those cases, we do still
	 * want to check if there's a redundant swappage to be discarded.
	 */
	if (wbc->for_reclaim)
		swap = get_swap_page();
	else
		swap.val = 0;

	spin_lock(&info->lock);
	if (index >= info->next_index) {
		BUG_ON(!(info->flags & SHMEM_TRUNCATE));
		goto unlock;
	}
	entry = ax8swap_shmem_swp_entry(info, index, NULL);
	if (entry->val) {
		/*
		 * The more uptodate page coming down from a stacked
		 * writepage should replace our old swappage.
		 */
		free_swap_and_cache(*entry);
		ax8swap_shmem_swp_set(info, entry, 0);
	}
	ax8swap_shmem_recalc_inode(inode);

	if (swap.val && add_to_swap_cache(page, swap, GFP_ATOMIC) == 0) {
		remove_from_page_cache(page);
		ax8swap_shmem_swp_set(info, entry, swap.val);
		ax8swap_shmem_swp_unmap(entry);
		if (list_empty(&info->swaplist))
			inode = igrab(inode);
		else
			inode = NULL;
		spin_unlock(&info->lock);
		swap_duplicate(swap);
		BUG_ON(page_mapped(page));
		page_cache_release(page);	/* pagecache ref */
		set_page_dirty(page);
		unlock_page(page);
		if (inode) {
			mutex_lock(ax8swap_shmem_swaplist_mutex);
			/* move instead of add in case we're racing */
			list_move_tail(&info->swaplist, ax8swap_shmem_swaplist);
			mutex_unlock(ax8swap_shmem_swaplist_mutex);
			iput(inode);
		}
		return 0;
	}

	ax8swap_shmem_swp_unmap(entry);
unlock:
	spin_unlock(&info->lock);
	swap_free(swap);
redirty:
	set_page_dirty(page);
	if (wbc->for_reclaim)
		return AOP_WRITEPAGE_ACTIVATE;	/* Return with page locked */
	unlock_page(page);
	return 0;
}

#ifdef CONFIG_NUMA
#ifdef CONFIG_TMPFS
static void ax8swap_shmem_show_mpol(struct seq_file *seq, struct mempolicy *mpol)
{
	char buffer[64];

	if (!mpol || mpol->mode == MPOL_DEFAULT)
		return;		/* show nothing */

	mpol_to_str(buffer, sizeof(buffer), mpol, 1);

	seq_printf(seq, ",mpol=%s", buffer);
}

static struct mempolicy *ax8swap_shmem_get_sbmpol(struct shmem_sb_info *sbinfo)
{
	struct mempolicy *mpol = NULL;
	if (sbinfo->mpol) {
		spin_lock(&sbinfo->stat_lock);	/* prevent replace/use races */
		mpol = sbinfo->mpol;
		mpol_get(mpol);
		spin_unlock(&sbinfo->stat_lock);
	}
	return mpol;
}
#endif /* CONFIG_TMPFS */

static struct page *ax8swap_shmem_swapin(swp_entry_t entry, gfp_t gfp,
			struct shmem_inode_info *info, unsigned long idx)
{
	struct mempolicy mpol, *spol;
	struct vm_area_struct pvma;
	struct page *page;

	spol = mpol_cond_copy(&mpol,
				mpol_shared_policy_lookup(&info->policy, idx));

	/* Create a pseudo vma that just contains the policy */
	pvma.vm_start = 0;
	pvma.vm_pgoff = idx;
	pvma.vm_ops = NULL;
	pvma.vm_policy = spol;
	page = swapin_readahead(entry, gfp, &pvma, 0);
	return page;
}

static struct page *ax8swap_shmem_alloc_page(gfp_t gfp,
			struct shmem_inode_info *info, unsigned long idx)
{
	struct vm_area_struct pvma;

	/* Create a pseudo vma that just contains the policy */
	pvma.vm_start = 0;
	pvma.vm_pgoff = idx;
	pvma.vm_ops = NULL;
	pvma.vm_policy = mpol_shared_policy_lookup(&info->policy, idx);

	/*
	 * alloc_page_vma() will drop the shared policy reference
	 */
	return alloc_page_vma(gfp, &pvma, 0);
}
#else /* !CONFIG_NUMA */
#ifdef CONFIG_TMPFS
static inline void ax8swap_shmem_show_mpol(struct seq_file *seq, struct mempolicy *p)
{
}
#endif /* CONFIG_TMPFS */

static inline struct page *ax8swap_shmem_swapin(swp_entry_t entry, gfp_t gfp,
			struct shmem_inode_info *info, unsigned long idx)
{
	return swapin_readahead(entry, gfp, NULL, 0);
}

static inline struct page *ax8swap_shmem_alloc_page(gfp_t gfp,
			struct shmem_inode_info *info, unsigned long idx)
{
	return alloc_page(gfp);
}
#endif /* CONFIG_NUMA */

#if !defined(CONFIG_NUMA) || !defined(CONFIG_TMPFS)
static inline struct mempolicy *ax8swap_shmem_get_sbmpol(struct shmem_sb_info *sbinfo)
{
	return NULL;
}
#endif

/*
 * shmem_getpage - either get the page from swap or allocate a new one
 *
 * If we allocate a new one we do not mark it dirty. That's up to the
 * vm. If we swap it in we mark it dirty since we also free the swap
 * entry since a page cannot live in both the swap and page cache
 */
int ax8swap_shmem_getpage(struct inode *inode, unsigned long idx,
			struct page **pagep, enum sgp_type sgp, int *type)
{
	struct address_space *mapping = inode->i_mapping;
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct shmem_sb_info *sbinfo;
	struct page *filepage = *pagep;
	struct page *swappage;
	swp_entry_t *entry;
	swp_entry_t swap;
	gfp_t gfp;
	int error;

	if (idx >= SHMEM_MAX_INDEX)
		return -EFBIG;

	if (type)
		*type = 0;

	/*
	 * Normally, filepage is NULL on entry, and either found
	 * uptodate immediately, or allocated and zeroed, or read
	 * in under swappage, which is then assigned to filepage.
	 * But shmem_readpage (required for splice) passes in a locked
	 * filepage, which may be found not uptodate by other callers
	 * too, and may need to be copied from the swappage read in.
	 */
repeat:
	if (!filepage)
		filepage = find_lock_page(mapping, idx);
	if (filepage && PageUptodate(filepage))
		goto done;
	error = 0;
	gfp = mapping_gfp_mask(mapping);
	if (!filepage) {
		/*
		 * Try to preload while we can wait, to not make a habit of
		 * draining atomic reserves; but don't latch on to this cpu.
		 */
		error = radix_tree_preload(gfp & ~__GFP_HIGHMEM);
		if (error)
			goto failed;
		radix_tree_preload_end();
	}

	spin_lock(&info->lock);
	ax8swap_shmem_recalc_inode(inode);
	entry = ax8swap_shmem_swp_alloc(info, idx, sgp);
	if (IS_ERR(entry)) {
		spin_unlock(&info->lock);
		error = PTR_ERR(entry);
		goto failed;
	}
	swap = *entry;

	if (swap.val) {
		/* Look it up and read it in.. */
		swappage = lookup_swap_cache(swap);
		if (!swappage) {
			ax8swap_shmem_swp_unmap(entry);
			/* here we actually do the io */
			if (type && !(*type & VM_FAULT_MAJOR)) {
				__count_vm_event(PGMAJFAULT);
				*type |= VM_FAULT_MAJOR;
			}
			spin_unlock(&info->lock);
			swappage = ax8swap_shmem_swapin(swap, gfp, info, idx);
			if (!swappage) {
				spin_lock(&info->lock);
				entry = ax8swap_shmem_swp_alloc(info, idx, sgp);
				if (IS_ERR(entry))
					error = PTR_ERR(entry);
				else {
					if (entry->val == swap.val)
						error = -ENOMEM;
					ax8swap_shmem_swp_unmap(entry);
				}
				spin_unlock(&info->lock);
				if (error)
					goto failed;
				goto repeat;
			}
			wait_on_page_locked(swappage);
			page_cache_release(swappage);
			goto repeat;
		}

		/* We have to do this with page locked to prevent races */
		if (!trylock_page(swappage)) {
			ax8swap_shmem_swp_unmap(entry);
			spin_unlock(&info->lock);
			wait_on_page_locked(swappage);
			page_cache_release(swappage);
			goto repeat;
		}
		if (PageWriteback(swappage)) {
			ax8swap_shmem_swp_unmap(entry);
			spin_unlock(&info->lock);
			wait_on_page_writeback(swappage);
			unlock_page(swappage);
			page_cache_release(swappage);
			goto repeat;
		}
		if (!PageUptodate(swappage)) {
			ax8swap_shmem_swp_unmap(entry);
			spin_unlock(&info->lock);
			unlock_page(swappage);
			page_cache_release(swappage);
			error = -EIO;
			goto failed;
		}

		if (filepage) {
			ax8swap_shmem_swp_set(info, entry, 0);
			ax8swap_shmem_swp_unmap(entry);
			delete_from_swap_cache(swappage);
			spin_unlock(&info->lock);
			copy_highpage(filepage, swappage);
			unlock_page(swappage);
			page_cache_release(swappage);
			flush_dcache_page(filepage);
			SetPageUptodate(filepage);
			set_page_dirty(filepage);
			swap_free(swap);
		} else if (!(error = add_to_page_cache_locked(swappage, mapping,
					idx, GFP_NOWAIT))) {
			info->flags |= SHMEM_PAGEIN;
			ax8swap_shmem_swp_set(info, entry, 0);
			ax8swap_shmem_swp_unmap(entry);
			delete_from_swap_cache(swappage);
			spin_unlock(&info->lock);
			filepage = swappage;
			set_page_dirty(filepage);
			swap_free(swap);
		} else {
			ax8swap_shmem_swp_unmap(entry);
			spin_unlock(&info->lock);
			if (error == -ENOMEM) {
				/* allow reclaim from this memory cgroup */
				error = mem_cgroup_shrink_usage(swappage,
								current->mm,
								gfp);
				if (error) {
					unlock_page(swappage);
					page_cache_release(swappage);
					goto failed;
				}
			}
			unlock_page(swappage);
			page_cache_release(swappage);
			goto repeat;
		}
	} else if (sgp == SGP_READ && !filepage) {
		ax8swap_shmem_swp_unmap(entry);
		filepage = find_get_page(mapping, idx);
		if (filepage &&
		    (!PageUptodate(filepage) || !trylock_page(filepage))) {
			spin_unlock(&info->lock);
			wait_on_page_locked(filepage);
			page_cache_release(filepage);
			filepage = NULL;
			goto repeat;
		}
		spin_unlock(&info->lock);
	} else {
		ax8swap_shmem_swp_unmap(entry);
		sbinfo = SHMEM_SB(inode->i_sb);
		if (sbinfo->max_blocks) {
			spin_lock(&sbinfo->stat_lock);
			if (sbinfo->free_blocks == 0 ||
			    ax8swap_shmem_acct_block(info->flags)) {
				spin_unlock(&sbinfo->stat_lock);
				spin_unlock(&info->lock);
				error = -ENOSPC;
				goto failed;
			}
			sbinfo->free_blocks--;
			inode->i_blocks += BLOCKS_PER_PAGE;
			spin_unlock(&sbinfo->stat_lock);
		} else if (ax8swap_shmem_acct_block(info->flags)) {
			spin_unlock(&info->lock);
			error = -ENOSPC;
			goto failed;
		}

		if (!filepage) {
			int ret;

			spin_unlock(&info->lock);
			filepage = ax8swap_shmem_alloc_page(gfp, info, idx);
			if (!filepage) {
				ax8swap_shmem_unacct_blocks(info->flags, 1);
				ax8swap_shmem_free_blocks(inode, 1);
				error = -ENOMEM;
				goto failed;
			}
			SetPageSwapBacked(filepage);

			/* Precharge page while we can wait, compensate after */
			error = mem_cgroup_cache_charge(filepage, current->mm,
					GFP_KERNEL);
			if (error) {
				page_cache_release(filepage);
				ax8swap_shmem_unacct_blocks(info->flags, 1);
				ax8swap_shmem_free_blocks(inode, 1);
				filepage = NULL;
				goto failed;
			}

			spin_lock(&info->lock);
			entry = ax8swap_shmem_swp_alloc(info, idx, sgp);
			if (IS_ERR(entry))
				error = PTR_ERR(entry);
			else {
				swap = *entry;
				ax8swap_shmem_swp_unmap(entry);
			}
			ret = error || swap.val;
			if (ret)
				mem_cgroup_uncharge_cache_page(filepage);
			else
				ret = add_to_page_cache_lru(filepage, mapping,
						idx, GFP_NOWAIT);
			/*
			 * At add_to_page_cache_lru() failure, uncharge will
			 * be done automatically.
			 */
			if (ret) {
				spin_unlock(&info->lock);
				page_cache_release(filepage);
				ax8swap_shmem_unacct_blocks(info->flags, 1);
				ax8swap_shmem_free_blocks(inode, 1);
				filepage = NULL;
				if (error)
					goto failed;
				goto repeat;
			}
			info->flags |= SHMEM_PAGEIN;
		}

		info->alloced++;
		spin_unlock(&info->lock);
		clear_highpage(filepage);
		flush_dcache_page(filepage);
		SetPageUptodate(filepage);
		if (sgp == SGP_DIRTY)
			set_page_dirty(filepage);
	}
done:
	*pagep = filepage;
	return 0;

failed:
	if (*pagep != filepage) {
		unlock_page(filepage);
		page_cache_release(filepage);
	}
	return error;
}

int ax8swap_shmem_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct inode *inode = vma->vm_file->f_path.dentry->d_inode;
	int error;
	int ret;

	if (((loff_t)vmf->pgoff << PAGE_CACHE_SHIFT) >= i_size_read(inode))
		return VM_FAULT_SIGBUS;

	error = ax8swap_shmem_getpage(inode, vmf->pgoff, &vmf->page, SGP_CACHE, &ret);
	if (error)
		return ((error == -ENOMEM) ? VM_FAULT_OOM : VM_FAULT_SIGBUS);

	return ret | VM_FAULT_LOCKED;
}

#ifdef CONFIG_NUMA
static int ax8swap_shmem_set_policy(struct vm_area_struct *vma, struct mempolicy *new)
{
	struct inode *i = vma->vm_file->f_path.dentry->d_inode;
	return mpol_set_shared_policy(&SHMEM_I(i)->policy, vma, new);
}

static struct mempolicy *ax8swap_shmem_get_policy(struct vm_area_struct *vma,
					  unsigned long addr)
{
	struct inode *i = vma->vm_file->f_path.dentry->d_inode;
	unsigned long idx;

	idx = ((addr - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;
	return mpol_shared_policy_lookup(&SHMEM_I(i)->policy, idx);
}
#endif

int ax8swap_shmem_lock(struct file *file, int lock, struct user_struct *user)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct shmem_inode_info *info = SHMEM_I(inode);
	int retval = -ENOMEM;

	spin_lock(&info->lock);
	if (lock && !(info->flags & VM_LOCKED)) {
		if (!user_shm_lock(inode->i_size, user))
			goto out_nomem;
		info->flags |= VM_LOCKED;
		mapping_set_unevictable(file->f_mapping);
	}
	if (!lock && (info->flags & VM_LOCKED) && user) {
		user_shm_unlock(inode->i_size, user);
		info->flags &= ~VM_LOCKED;
		mapping_clear_unevictable(file->f_mapping);
		scan_mapping_unevictable_pages(file->f_mapping);
	}
	retval = 0;

out_nomem:
	spin_unlock(&info->lock);
	return retval;
}

