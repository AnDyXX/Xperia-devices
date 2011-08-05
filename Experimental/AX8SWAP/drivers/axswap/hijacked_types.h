#ifndef __HIJACKED_TYPE_H__
#define __HIJACKED_TYPE_H__

#include <linux/pipe_fs_i.h>
#include <linux/mmdebug.h>
#include <linux/mm.h>
#include <linux/cgroup.h>
#include <linux/shmem_fs.h>
#include <linux/pagevec.h>
#include <asm/tlb.h>

extern struct mutex * ax8swap_mm_all_locks_mutex;
#define mm_all_locks_mutex (*ax8swap_mm_all_locks_mutex)

extern struct rw_semaphore * ax8swap_shrinker_rwsem;
#define shrinker_rwsem (*ax8swap_shrinker_rwsem)

extern struct list_head * ax8swap_shrinker_list;
#define shrinker_list (*ax8swap_shrinker_list)

extern int * ax8swap_min_free_order_shift;
#define min_free_order_shift (*ax8swap_min_free_order_shift)

extern unsigned long __meminitdata * ax8swap_dma_reserve;
#define dma_reserve (*ax8swap_dma_reserve)

extern int * ax8swap_min_free_kbytes;
#define min_free_kbytes (*ax8swap_min_free_kbytes)

extern int * ax8swap_percpu_pagelist_fraction;
#define percpu_pagelist_fraction (*ax8swap_percpu_pagelist_fraction)

extern long * ax8swap_ratelimit_pages;
#define ratelimit_pages (*ax8swap_ratelimit_pages)

extern int * ax8swap_dirty_background_ratio;
#define  dirty_background_ratio  (*ax8swap_dirty_background_ratio)

extern unsigned long * ax8swap_dirty_background_bytes;
#define  dirty_background_bytes  (*ax8swap_dirty_background_bytes)

extern int * ax8swap_vm_highmem_is_dirtyable;
#define vm_highmem_is_dirtyable   (*ax8swap_vm_highmem_is_dirtyable)

extern int * ax8swap_vm_dirty_ratio;
#define  vm_dirty_ratio  (*ax8swap_vm_dirty_ratio)

extern unsigned long * ax8swap_vm_dirty_bytes;
#define  vm_dirty_bytes  (*ax8swap_vm_dirty_bytes)

extern int * ax8swap_dirty_writeback_interval;
#define  dirty_writeback_interval  (*ax8swap_dirty_writeback_interval)

extern int * ax8swap_dirty_expire_interval;
#define  dirty_expire_interval  (*ax8swap_dirty_expire_interval)

extern int * ax8swap_block_dump;
#define  block_dump  (*ax8swap_block_dump)

extern int * ax8swap_laptop_mode;
#define   laptop_mode (*ax8swap_laptop_mode)

extern struct prop_descriptor * ax8swap_vm_completions;
#define   vm_completions (*ax8swap_vm_completions)

extern struct prop_descriptor * ax8swap_vm_dirties;
#define  vm_dirties  (*ax8swap_vm_dirties)

extern struct timer_list * ax8swap_wb_timer;
#define  wb_timer  (*ax8swap_wb_timer)

extern struct timer_list * ax8swap_laptop_mode_wb_timer;
#define  laptop_mode_wb_timer  (*ax8swap_laptop_mode_wb_timer)

extern unsigned int * ax8swap_bdi_min_ratio;
#define bdi_min_ratio (*ax8swap_bdi_min_ratio)

extern struct kmem_cache ** ax8swap_anon_vma_cachep;
#define anon_vma_cachep (*ax8swap_anon_vma_cachep)

extern struct mutex * ax8swap_shmem_swaplist_mutex;
#define shmem_swaplist_mutex (*ax8swap_shmem_swaplist_mutex)

extern struct list_head * ax8swap_shmem_swaplist;
#define shmem_swaplist (*ax8swap_shmem_swaplist)

/*  URES REF */
typedef void (*ax8swap_update_mmu_cache_type)(struct vm_area_struct * vma,
			     unsigned long address, pte_t pte); 
extern ax8swap_update_mmu_cache_type ax8swap_update_mmu_cache;

typedef void (*ax8swap_flush_ptrace_access_type)(struct vm_area_struct *vma, struct page *page,
				unsigned long uaddr, void *kaddr,
				unsigned long len, int write); 
extern ax8swap_flush_ptrace_access_type ax8swap_flush_ptrace_access;
#define flush_ptrace_access ax8swap_flush_ptrace_access

typedef long (*ax8swap_mlock_vma_pages_range_type)(struct vm_area_struct *vma,
			unsigned long start, unsigned long end); 
extern ax8swap_mlock_vma_pages_range_type ax8swap_mlock_vma_pages_range;

typedef void (*ax8swap_writeback_inodes_type)(struct writeback_control *wbc);
extern ax8swap_writeback_inodes_type ax8swap_writeback_inodes;
#define writeback_inodes ax8swap_writeback_inodes

typedef unsigned long (*ax8swap_max_sane_readahead_type)(unsigned long nr);
extern ax8swap_max_sane_readahead_type ax8swap_max_sane_readahead;
#define max_sane_readahead ax8swap_max_sane_readahead

typedef void (*ax8swap_clear_zonelist_oom_type)(struct zonelist *zonelist, gfp_t gfp_flags);
extern ax8swap_clear_zonelist_oom_type ax8swap_clear_zonelist_oom;
#define clear_zonelist_oom_type ax8swap_clear_zonelist_oom

extern int * ax8swap_page_cluster;
#define page_cluster (*ax8swap_page_cluster)

extern unsigned long __meminitdata * ax8swap_nr_kernel_pages;
#define nr_kernel_pages (*ax8swap_nr_kernel_pages)

typedef void (*ax8swap_munlock_vma_pages_range_type)(struct vm_area_struct *vma,
			unsigned long start, unsigned long end);
extern ax8swap_munlock_vma_pages_range_type ax8swap_munlock_vma_pages_range;

typedef int (*ax8swap_prop_descriptor_init_type)(struct prop_descriptor *pd, int shift);
extern ax8swap_prop_descriptor_init_type ax8swap_prop_descriptor_init;
#define prop_descriptor_init ax8swap_prop_descriptor_init

typedef void (*ax8swap_prop_fraction_single_type)(struct prop_descriptor *pd, struct prop_local_single *pl,
		long *numerator, long *denominator);
extern ax8swap_prop_fraction_single_type ax8swap_prop_fraction_single;

typedef struct zoneref * (*ax8swap_next_zones_zonelist_type)(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes,
					struct zone **zone);
extern ax8swap_next_zones_zonelist_type ax8swap_next_zones_zonelist;

typedef void (*ax8swap___clear_page_mlock_type)(struct page *page);
extern ax8swap___clear_page_mlock_type ax8swap___clear_page_mlock;

extern int *  ax8swap_page_group_by_mobility_disabled;
#define page_group_by_mobility_disabled (*ax8swap_page_group_by_mobility_disabled)

typedef void (*ax8swap_vma_prio_tree_remove_type) (struct vm_area_struct *, struct prio_tree_root *);
extern ax8swap_vma_prio_tree_remove_type ax8swap_vma_prio_tree_remove;
#define vma_prio_tree_remove ax8swap_vma_prio_tree_remove

extern int * ax8swap_sysctl_lowmem_reserve_ratio;
#define sysctl_lowmem_reserve_ratio (*ax8swap_sysctl_lowmem_reserve_ratio)

typedef long (*ax8swap_nr_blockdev_pages_type)(void);
extern ax8swap_nr_blockdev_pages_type ax8swap_nr_blockdev_pages;
#define nr_blockdev_pages ax8swap_nr_blockdev_pages

typedef struct vm_area_struct * (*ax8swap_vma_prio_tree_next_type)(struct vm_area_struct *vma,
	struct prio_tree_iter *iter);
extern ax8swap_vma_prio_tree_next_type ax8swap_vma_prio_tree_next;
#define vma_prio_tree_next ax8swap_vma_prio_tree_next

typedef void (*ax8swap___memory_pressure_notify_type)(struct zone *zone, int pressure);
extern ax8swap___memory_pressure_notify_type ax8swap___memory_pressure_notify;
#define __memory_pressure_notify ax8swap___memory_pressure_notify

typedef int (*ax8swap_cap_inode_need_killpriv_type)(struct dentry *dentry);
extern ax8swap_cap_inode_need_killpriv_type ax8swap_cap_inode_need_killpriv;
#define cap_inode_need_killpriv ax8swap_cap_inode_need_killpriv


extern pgprot_t * ax8swap_protection_map;
#define protection_map (*ax8swap_protection_map)

typedef void (*ax8swap_flush_cache_mm_type)(struct mm_struct *mm);
extern ax8swap_flush_cache_mm_type ax8swap_flush_cache_mm;
#define flush_cache_mm ax8swap_flush_cache_mm

typedef void (*ax8swap_show_mem_type) (void);
extern ax8swap_show_mem_type ax8swap_show_mem;
#define show_mem ax8swap_show_mem

typedef void (*ax8swap___pgd_error_type)(const char *file, int line, unsigned long val);
extern ax8swap___pgd_error_type ax8swap___pgd_error;
#define __pgd_error ax8swap___pgd_error

typedef struct pglist_data * (*ax8swap_first_online_pgdat_type)(void);
extern ax8swap_first_online_pgdat_type ax8swap_first_online_pgdat;
#define first_online_pgdat ax8swap_first_online_pgdat

typedef void (*ax8swap_user_shm_unlock_type)(size_t, struct user_struct *);
extern ax8swap_user_shm_unlock_type ax8swap_user_shm_unlock;
#define user_shm_unlock ax8swap_user_shm_unlock

typedef void (*ax8swap_prop_change_shift_type)(struct prop_descriptor *pd, int new_shift);
extern ax8swap_prop_change_shift_type ax8swap_prop_change_shift;
#define prop_change_shift ax8swap_prop_change_shift

typedef int (*ax8swap_pdflush_operation_type)(void (*fn)(unsigned long), unsigned long arg0);
extern ax8swap_pdflush_operation_type ax8swap_pdflush_operation;
#define pdflush_operation ax8swap_pdflush_operation

typedef void (*ax8swap_flush_cache_range_type)(struct vm_area_struct *vma, unsigned long start, unsigned long end);
extern ax8swap_flush_cache_range_type ax8swap_flush_cache_range;
#define flush_cache_range ax8swap_flush_cache_range

typedef void (*ax8swap_added_exe_file_vma_type)(struct mm_struct *mm);
extern ax8swap_added_exe_file_vma_type ax8swap_added_exe_file_vma;
#define added_exe_file_vma ax8swap_added_exe_file_vma


extern long * ax8swap_vm_total_pages;
#define vm_total_pages (*ax8swap_vm_total_pages)

extern struct inodes_stat_t * ax8swap_inodes_stat;
#define inodes_stat (*ax8swap_inodes_stat)

extern unsigned long * ax8swap_scan_unevictable_pages;
#define scan_unevictable_pages (*ax8swap_scan_unevictable_pages)

typedef int (*ax8swap_slab_is_available_type)(void);
extern ax8swap_slab_is_available_type ax8swap_slab_is_available;
#define slab_is_available ax8swap_slab_is_available

typedef void (*ax8swap___prop_inc_single_type)(struct prop_descriptor *pd, struct prop_local_single *pl);
extern ax8swap___prop_inc_single_type ax8swap___prop_inc_single;
#define __prop_inc_single ax8swap___prop_inc_single

typedef int (*ax8swap_user_shm_lock_type)(size_t, struct user_struct *);
extern ax8swap_user_shm_lock_type ax8swap_user_shm_lock;
#define user_shm_lock ax8swap_user_shm_lock

typedef void (*ax8swap_v6wbi_flush_user_tlb_range_type)(unsigned long, unsigned long, struct vm_area_struct *);
extern ax8swap_v6wbi_flush_user_tlb_range_type ax8swap_v6wbi_flush_user_tlb_range;
#define v6wbi_flush_user_tlb_range ax8swap_v6wbi_flush_user_tlb_range

extern int * ax8swap_buffer_heads_over_limit;
#define buffer_heads_over_limit (*ax8swap_buffer_heads_over_limit)

typedef int (*ax8swap_cap_inode_killpriv_type)(struct dentry *dentry);
extern ax8swap_cap_inode_killpriv_type ax8swap_cap_inode_killpriv;
#define cap_inode_killpriv ax8swap_cap_inode_killpriv

typedef void (*ax8swap_vma_prio_tree_insert_type)(struct vm_area_struct *, struct prio_tree_root *);
extern ax8swap_vma_prio_tree_insert_type ax8swap_vma_prio_tree_insert;
#define vma_prio_tree_insert ax8swap_vma_prio_tree_insert

typedef int (*ax8swap_locks_mandatory_locked_type)(struct inode *);
extern ax8swap_locks_mandatory_locked_type ax8swap_locks_mandatory_locked;
#define locks_mandatory_locked ax8swap_locks_mandatory_locked


extern int * ax8swap_sysctl_overcommit_memory;
#define sysctl_overcommit_memory (*ax8swap_sysctl_overcommit_memory)

extern int * ax8swap_sysctl_max_map_count;
#define sysctl_max_map_count (*ax8swap_sysctl_max_map_count)

typedef struct pglist_data * (*ax8swap_next_online_pgdat_type)(struct pglist_data *pgdat);
extern ax8swap_next_online_pgdat_type ax8swap_next_online_pgdat;
#define next_online_pgdat ax8swap_next_online_pgdat

typedef int (*ax8swap_force_page_cache_readahead_type)(struct address_space *mapping, struct file *filp,
			pgoff_t offset, unsigned long nr_to_read);
extern ax8swap_force_page_cache_readahead_type ax8swap_force_page_cache_readahead;
#define force_page_cache_readahead ax8swap_force_page_cache_readahead

extern int * ax8swap_sysctl_overcommit_ratio;
#define sysctl_overcommit_ratio (*ax8swap_sysctl_overcommit_ratio)

extern unsigned long * ax8swap_totalreserve_pages;
#define totalreserve_pages (*ax8swap_totalreserve_pages)

extern unsigned long __meminitdata * ax8swap_nr_all_pages;
#define nr_all_pages (*ax8swap_nr_all_pages)

typedef void (*ax8swap_prop_fraction_percpu_type)(struct prop_descriptor *pd, struct prop_local_percpu *pl,
		long *numerator, long *denominator);
extern ax8swap_prop_fraction_percpu_type ax8swap_prop_fraction_percpu;
#define prop_fraction_percpu ax8swap_prop_fraction_percpu

typedef void (*ax8swap_flush_cache_page_type)(struct vm_area_struct *vma, unsigned long user_addr, unsigned long pfn);
extern ax8swap_flush_cache_page_type ax8swap_flush_cache_page;
#define flush_cache_page ax8swap_flush_cache_page

typedef int (*ax8swap_try_set_zone_oom_type)(struct zonelist *zonelist, gfp_t gfp_flags);
extern ax8swap_try_set_zone_oom_type ax8swap_try_set_zone_oom;
#define try_set_zone_oom ax8swap_try_set_zone_oom

typedef  struct zone * (*ax8swap_next_zone_type)(struct zone *zone);
extern ax8swap_next_zone_type ax8swap_next_zone;
#define next_zone ax8swap_next_zone

typedef void (*ax8swap___pmd_error_type)(const char *file, int line, unsigned long val);
extern ax8swap___pmd_error_type ax8swap___pmd_error;
#define __pmd_error ax8swap___pmd_error

typedef void (*ax8swap___flush_anon_page_type)(struct vm_area_struct *vma,
				struct page *, unsigned long);
extern ax8swap___flush_anon_page_type ax8swap___flush_anon_page;
#define __flush_anon_page ax8swap___flush_anon_page

typedef int (*ax8swap_writeback_in_progress_type)(struct backing_dev_info *bdi);
extern ax8swap_writeback_in_progress_type ax8swap_writeback_in_progress;
#define writeback_in_progress ax8swap_writeback_in_progress

typedef void (*ax8swap_out_of_memory_type)(struct zonelist *zonelist, gfp_t gfp_mask, int order);
extern ax8swap_out_of_memory_type ax8swap_out_of_memory;
#define out_of_memory ax8swap_out_of_memory

typedef void * (*ax8swap___alloc_bootmem_nopanic_type)(unsigned long size,
			     unsigned long align,
			     unsigned long goal);
extern ax8swap___alloc_bootmem_nopanic_type ax8swap___alloc_bootmem_nopanic;
#define __alloc_bootmem_nopanic ax8swap___alloc_bootmem_nopanic

typedef void (*ax8swap_removed_exe_file_vma_type)(struct mm_struct *mm);
extern ax8swap_removed_exe_file_vma_type ax8swap_removed_exe_file_vma;
#define removed_exe_file_vma ax8swap_removed_exe_file_vma

extern struct kmem_cache ** ax8swap_vm_area_cachep;
#define vm_area_cachep (*ax8swap_vm_area_cachep)

typedef int (*ax8swap_cap_vm_enough_memory_type)(struct mm_struct *mm, long pages);
extern ax8swap_cap_vm_enough_memory_type ax8swap_cap_vm_enough_memory;
#define cap_vm_enough_memory ax8swap_cap_vm_enough_memory

typedef asmlinkage long (*ax8swap_sys_sync_type)(void);
extern ax8swap_sys_sync_type ax8swap_sys_sync;
#define sys_sync ax8swap_sys_sync

typedef int (*ax8swap_shmem_zero_setup_type)(struct vm_area_struct *);
extern ax8swap_shmem_zero_setup_type ax8swap_shmem_zero_setup;
#define shmem_zero_setup ax8swap_shmem_zero_setup

extern int * ax8swap_vm_swappiness;
#define vm_swappiness (*ax8swap_vm_swappiness)

typedef  unsigned long (*ax8swap_arch_get_unmapped_area_type)(struct file *, unsigned long, unsigned long,
		       unsigned long, unsigned long);
extern ax8swap_arch_get_unmapped_area_type ax8swap_arch_get_unmapped_area;
#define arch_get_unmapped_area ax8swap_arch_get_unmapped_area

extern unsigned long*  ax8swap_mmap_min_addr;
#define mmap_min_addr (*ax8swap_mmap_min_addr)

typedef int (*ax8swap_deny_write_access_type)(struct file *);
extern ax8swap_deny_write_access_type ax8swap_deny_write_access;
#define deny_write_access ax8swap_deny_write_access

typedef void (*ax8swap___prop_inc_percpu_max_type)(struct prop_descriptor *pd,
			   struct prop_local_percpu *pl, long frac);
extern ax8swap___prop_inc_percpu_max_type ax8swap___prop_inc_percpu_max;
#define __prop_inc_percpu_max ax8swap___prop_inc_percpu_max

typedef int (*ax8swap_do_page_cache_readahead_type)(struct address_space *mapping, struct file *filp,
			pgoff_t offset, unsigned long nr_to_read);
extern ax8swap_do_page_cache_readahead_type ax8swap_do_page_cache_readahead;
#define do_page_cache_readahead ax8swap_do_page_cache_readahead

typedef void * (*ax8swap___alloc_bootmem_node_type)(pg_data_t *pgdat,
				  unsigned long size,
				  unsigned long align,
				  unsigned long goal);
extern ax8swap___alloc_bootmem_node_type ax8swap___alloc_bootmem_node;
#define __alloc_bootmem_node ax8swap___alloc_bootmem_node

extern atomic_long_t * ax8swap_vm_committed_space;
#define vm_committed_space (*ax8swap_vm_committed_space)

typedef void (*ax8swap_sync_supers_type)(void);
extern ax8swap_sync_supers_type ax8swap_sync_supers;
#define sync_supers ax8swap_sync_supers










#endif
