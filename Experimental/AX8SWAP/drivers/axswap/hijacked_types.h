#ifndef __HIJACKED_TYPE_H__
#define __HIJACKED_TYPE_H__

#include <linux/pipe_fs_i.h>
#include <linux/mmdebug.h>
#include <linux/mm.h>
#include <linux/cgroup.h>
#include <linux/shmem_fs.h>
#include <linux/pagevec.h>

/* Request for sync pageout. */
enum pageout_io {
	PAGEOUT_IO_ASYNC,
	PAGEOUT_IO_SYNC,
};

/* possible outcome of pageout() */
typedef enum {
	/* failed to write page out, page is locked */
	PAGE_KEEP,
	/* move page to the active list, page is locked */
	PAGE_ACTIVATE,
	/* page has been sent to the disk successfully, page is unlocked */
	PAGE_SUCCESS,
	/* page is clean and locked */
	PAGE_CLEAN,
} pageout_t;

/* Flag allocation requirements to shmem_getpage and shmem_swp_alloc */
enum sgp_type {
	SGP_READ,	/* don't exceed i_size, don't allocate page */
	SGP_CACHE,	/* don't exceed i_size, may allocate page */
	SGP_DIRTY,	/* like SGP_CACHE, but set new page dirty */
	SGP_WRITE,	/* may exceed i_size, may allocate page */
};

struct scan_control {
	/* Incremented by the number of inactive pages that were scanned */
	unsigned long nr_scanned;

	/* Number of pages freed so far during a call to shrink_zones() */
	unsigned long nr_reclaimed;

	/* This context's GFP mask */
	gfp_t gfp_mask;

	int may_writepage;

	/* Can pages be swapped as part of reclaim? */
	int may_swap;

	/* This context's SWAP_CLUSTER_MAX. If freeing memory for
	 * suspend, we effectively ignore SWAP_CLUSTER_MAX.
	 * In this context, it doesn't matter that we scan the
	 * whole list at once. */
	int swap_cluster_max;

	int swappiness;

	int all_unreclaimable;

	int order;

	/* Which cgroup do we reclaim from */
	struct mem_cgroup *mem_cgroup;

	/* Pluggable isolate pages callback */
	unsigned long (*isolate_pages)(unsigned long nr, struct list_head *dst,
			unsigned long *scanned, int order, int mode,
			struct zone *z, struct mem_cgroup *mem_cont,
			int active, int file);
};

asmlinkage long sys_ax8swap_mincore(unsigned long start, size_t len,
				unsigned char __user * vec);

void ax8swap_update_mmu_cache(struct vm_area_struct *vma, unsigned long addr, pte_t pte);

typedef int (*ax8swap_adjust_pte_type)(struct vm_area_struct *vma, unsigned long address);
extern ax8swap_adjust_pte_type ax8swap_adjust_pte;

void ax8swap_flush_dcache_page(struct page *page);
int ax8swap___set_page_dirty_buffers(struct page *page);

void ax8swap___set_page_dirty(struct page *page,
		struct address_space *mapping, int warn);

int ax8swap_page_cache_pipe_buf_steal(struct pipe_inode_info *pipe,
				     struct pipe_buffer *buf);

int ax8swap_sync_page(void *word);
void ax8swap_mark_buffer_dirty(struct buffer_head *bh);
void ax8swap_block_sync_page(struct page *page);

void ax8swap_set_page_dirty_balance(struct page *page, int page_mkwrite);
int ax8swap___set_page_dirty_nobuffers(struct page *page);
int ax8swap_set_page_dirty(struct page *page);
int ax8swap_clear_page_dirty_for_io(struct page *page);
int ax8swap_test_clear_page_writeback(struct page *page);
int ax8swap_test_set_page_writeback(struct page *page);

extern struct prop_descriptor * ax8swap_vm_completions;

int ax8swap_page_mkclean(struct page *page);

unsigned long ax8swap_shrink_page_list(struct list_head *page_list,
					struct scan_control *sc,
					enum pageout_io sync_writeback);

int ax8swap___remove_mapping(struct address_space *mapping, struct page *page);

void ax8swap_shrink_active_list(unsigned long nr_pages, struct zone *zone,
			struct scan_control *sc, int priority, int file);

int ax8swap_page_evictable(struct page *page, struct vm_area_struct *vma);

typedef void (*ax8swap_putback_lru_page_type)(struct page *page);
extern ax8swap_putback_lru_page_type ax8swap_putback_lru_page;

#ifdef CONFIG_UNEVICTABLE_LRU
/*
 * Called only in fault path via page_evictable() for a new page
 * to determine if it's being mapped into a LOCKED vma.
 * If so, mark page as mlocked.
 */
static inline int ax8swap_is_mlocked_vma(struct vm_area_struct *vma, struct page *page)
{
	VM_BUG_ON(PageLRU(page));

	if (likely((vma->vm_flags & (VM_LOCKED | VM_SPECIAL)) != VM_LOCKED))
		return 0;

	if (!TestSetPageMlocked(page)) {
		inc_zone_page_state(page, NR_MLOCK);
		count_vm_event(UNEVICTABLE_PGMLOCKED);
	}
	return 1;
}
#else
static inline int ax8swap_is_mlocked_vma(struct vm_area_struct *v, struct page *p)
{
	return 0;
}
#endif


void ax8swap_show_mem(void);

extern struct mutex * ax8swap_shmem_swaplist_mutex;
extern struct list_head * ax8swap_shmem_swaplist;

swp_entry_t *ax8swap_shmem_swp_entry(struct shmem_inode_info *info, unsigned long index, struct page **page);
swp_entry_t *ax8swap_shmem_swp_alloc(struct shmem_inode_info *info, unsigned long index, enum sgp_type sgp);
int ax8swap_shmem_free_swp(swp_entry_t *dir, swp_entry_t *edir,
						spinlock_t *punch_lock);
void ax8swap_shmem_truncate_range(struct inode *inode, loff_t start, loff_t end);
void ax8swap_shmem_truncate(struct inode *inode);
int ax8swap_shmem_notify_change(struct dentry *dentry, struct iattr *attr);
void ax8swap_shmem_delete_inode(struct inode *inode);
int ax8swap_shmem_unuse(swp_entry_t entry, struct page *page);
int ax8swap_shmem_writepage(struct page *page, struct writeback_control *wbc);

int ax8swap_shmem_getpage(struct inode *inode, unsigned long idx,
			struct page **pagep, enum sgp_type sgp, int *type);

int ax8swap_shmem_fault(struct vm_area_struct *vma, struct vm_fault *vmf);

int ax8swap_shmem_lock(struct file *file, int lock, struct user_struct *user);

void ax8swap_pagevec_swap_free(struct pagevec *pvec);


void ax8swap___free_pages_ok(struct page *page, unsigned int order);
void ax8swap_free_hot_cold_page(struct page *page, int cold);

void ax8swap_bad_page(struct page *page);







#endif
