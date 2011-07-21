#ifndef __HIJACKED_TYPE_H__
#define __HIJACKED_TYPE_H__

typedef void (*__lru_cache_add_type) (struct page *, enum lru_list lru);
typedef void (*release_pages_type) (struct page **pages, int nr, int cold);
typedef void (*page_add_anon_rmap_type)(struct page *, struct vm_area_struct *, unsigned long);
typedef int (*shmem_unuse_type) (swp_entry_t entry, struct page *page);
typedef void (*lru_add_drain_type)(void);
typedef unsigned long (*page_address_in_vma_type)(struct page *, struct vm_area_struct *);
typedef void (*pmd_clear_bad_type)(pmd_t *);
typedef int (*cap_vm_enough_memory_type)(struct mm_struct *mm, long pages);
typedef void (*activate_page_type)(struct page *);

extern int * ax8swap_page_cluster;
extern  __lru_cache_add_type ax8swap___lru_cache_add;
extern  release_pages_type ax8swap_release_pages;
extern  page_add_anon_rmap_type ax8swap_page_add_anon_rmap;
extern  shmem_unuse_type ax8swap_shmem_unuse;
extern  lru_add_drain_type ax8swap_lru_add_drain;
extern  page_address_in_vma_type ax8swap_page_address_in_vma;
extern  pmd_clear_bad_type ax8swap_pmd_clear_bad;
extern  cap_vm_enough_memory_type ax8swap_cap_vm_enough_memory;
extern  activate_page_type ax8swap_activate_page;

#endif
