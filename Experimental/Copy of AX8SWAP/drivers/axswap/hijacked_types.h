#ifndef __HIJACKED_TYPE_H__
#define __HIJACKED_TYPE_H__

#define for_each_nodebank(iter,mi,no)			\
	for (iter = 0; iter < (mi)->nr_banks; iter++)	\
		if ((mi)->bank[iter].node == no) 

/*
 * Memory map description
 */
#ifdef CONFIG_ARCH_LH7A40X
# define NR_BANKS 16
#else
# define NR_BANKS 8
#endif 

struct membank {
	unsigned long start;
	unsigned long size;
	int           node;
}; 

struct meminfo {
	int nr_banks;
	struct membank bank[NR_BANKS];
}; 

#define bank_pfn_start(bank)	__phys_to_pfn((bank)->start)
#define bank_pfn_end(bank)	__phys_to_pfn((bank)->start + (bank)->size) 

typedef void (*__lru_cache_add_type) (struct page *, enum lru_list lru);
typedef void (*release_pages_type) (struct page **pages, int nr, int cold);
typedef void (*page_add_anon_rmap_type)(struct page *, struct vm_area_struct *, unsigned long);
typedef int (*shmem_unuse_type) (swp_entry_t entry, struct page *page);
typedef void (*lru_add_drain_type)(void);
typedef unsigned long (*page_address_in_vma_type)(struct page *, struct vm_area_struct *);
typedef void (*pmd_clear_bad_type)(pmd_t *);
typedef int (*cap_vm_enough_memory_type)(struct mm_struct *mm, long pages);
typedef void (*activate_page_type)(struct page *);


extern  int * ax8swap_page_cluster;
extern  __lru_cache_add_type ax8swap___lru_cache_add;
extern  release_pages_type ax8swap_release_pages;
extern  page_add_anon_rmap_type ax8swap_page_add_anon_rmap;
extern  shmem_unuse_type ax8swap_shmem_unuse;
extern  lru_add_drain_type ax8swap_lru_add_drain;
extern  page_address_in_vma_type ax8swap_page_address_in_vma;
extern  pmd_clear_bad_type ax8swap_pmd_clear_bad;
extern  cap_vm_enough_memory_type ax8swap_cap_vm_enough_memory;
extern  activate_page_type ax8swap_activate_page;
extern  atomic_long_t *ax8swap_vm_committed_space;
extern  struct meminfo *ax8swap_meminfo; 

/**
 * lru_cache_add: add a page to the page lists
 * @page: the page to add
 */
static inline void ax8swap_lru_cache_add_anon(struct page *page)
{
	ax8swap___lru_cache_add(page, LRU_INACTIVE_ANON);
}

static inline void ax8swap_lru_cache_add_active_anon(struct page *page)
{
	ax8swap___lru_cache_add(page, LRU_ACTIVE_ANON);
}

static inline void ax8swap_lru_cache_add_file(struct page *page)
{
	ax8swap___lru_cache_add(page, LRU_INACTIVE_FILE);
}

static inline void ax8swap_lru_cache_add_active_file(struct page *page)
{
	ax8swap___lru_cache_add(page, LRU_ACTIVE_FILE);
}

static inline int ax8swap_pmd_none_or_clear_bad(pmd_t *pmd)
{
	if (pmd_none(*pmd))
		return 1;
	if (unlikely(pmd_bad(*pmd))) {
		ax8swap_pmd_clear_bad(pmd);
		return 1;
	}
	return 0;
}

static inline int ax8swap_security_vm_enough_memory(long pages)
{
	WARN_ON(current->mm == NULL);
	return ax8swap_cap_vm_enough_memory(current->mm, pages);
}

static inline void ax8swap_vm_acct_memory(long pages)
{
	atomic_long_add(pages, ax8swap_vm_committed_space);
}

static inline void ax8swap_vm_unacct_memory(long pages)
{
	ax8swap_vm_acct_memory(-pages);
}

static inline void __put_page(struct page *page)
{
	atomic_dec(&page->_count);
}

#endif
