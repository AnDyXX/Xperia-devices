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



#endif
