/*
 * Author: AnDyX <AnDyX at xda-developers>
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 *  This module contains code from kernel required to initialise and execute 
 *  netfilter.  
 */
#define EXTERNAL_SWAP_MODULE

#include <linux/types.h>
#include <linux/kthread.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/swap.h>
#include <asm/setup.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>

#include "hijacked_types.h"


#define AX_MODULE_VER			"v001 alpha"
#define AX_MODULE_NAME			"ax8swap"

#define X8
#define X10M_
#define X10MP_

// patch offsets

#ifdef X8
#define DEVICE_NAME			"X8"
#define OFS_KALLSYMS_LOOKUP_NAME	0xC00B0654			// kallsyms_lookup_name
#endif

#ifdef X10M
#define DEVICE_NAME			"X10 mini"
#define OFS_KALLSYMS_LOOKUP_NAME	0xC00AF6D8			// kallsyms_lookup_name
#endif

#ifdef X10MP
#define DEVICE_NAME			"X10 mini pro"
#define OFS_KALLSYMS_LOOKUP_NAME	0xC00B09F0			// kallsyms_lookup_name
#endif

struct mutex * ax8swap_mm_all_locks_mutex;
struct rw_semaphore * ax8swap_shrinker_rwsem;
struct list_head * ax8swap_shrinker_list;
int * ax8swap_min_free_order_shift;
unsigned long __meminitdata * ax8swap_dma_reserve;
int * ax8swap_min_free_kbytes;
long * ax8swap_ratelimit_pages;
int * ax8swap_dirty_background_ratio;
unsigned long * ax8swap_dirty_background_bytes;
int * ax8swap_vm_highmem_is_dirtyable;
int * ax8swap_vm_dirty_ratio;
unsigned long * ax8swap_vm_dirty_bytes;
int * ax8swap_dirty_writeback_interval;
int * ax8swap_dirty_expire_interval;
int * ax8swap_block_dump;
int * ax8swap_laptop_mode;
struct prop_descriptor * ax8swap_vm_completions;
struct prop_descriptor * ax8swap_vm_dirties;
struct timer_list * ax8swap_wb_timer;
struct timer_list * ax8swap_laptop_mode_wb_timer;
unsigned int * ax8swap_bdi_min_ratio;
struct kmem_cache ** ax8swap_anon_vma_cachep;
struct mutex * ax8swap_shmem_swaplist_mutex;
struct list_head * ax8swap_shmem_swaplist;
atomic_long_t * ax8swap_last_mem_notify; 
//urn
ax8swap_flush_ptrace_access_type ax8swap_flush_ptrace_access;
ax8swap_mlock_vma_pages_range_type ax8swap_mlock_vma_pages_range;
ax8swap_writeback_inodes_type ax8swap_writeback_inodes;
struct mmu_gather * ax8swap_per_cpu_mmu_gathers;
long * ax8swap_highest_memmap_pfn;
ax8swap_max_sane_readahead_type ax8swap_max_sane_readahead;
ax8swap_clear_zonelist_oom_type ax8swap_clear_zonelist_oom;
int * ax8swap_page_cluster;
unsigned long __meminitdata * ax8swap_nr_kernel_pages;
ax8swap_munlock_vma_pages_range_type ax8swap_munlock_vma_pages_range;
ax8swap_prop_descriptor_init_type ax8swap_prop_descriptor_init;
int * ax8swap_percpu_pagelist_fraction;
ax8swap_prop_fraction_single_type ax8swap_prop_fraction_single;
ax8swap_next_zones_zonelist_type ax8swap_next_zones_zonelist;
ax8swap___clear_page_mlock_type ax8swap___clear_page_mlock;
int * ax8swap_page_group_by_mobility_disabled;
ax8swap_vma_prio_tree_remove_type ax8swap_vma_prio_tree_remove;
int ** ax8swap_sysctl_lowmem_reserve_ratio;
ax8swap_nr_blockdev_pages_type ax8swap_nr_blockdev_pages;
ax8swap_vma_prio_tree_next_type ax8swap_vma_prio_tree_next;
ax8swap___memory_pressure_notify_type ax8swap___memory_pressure_notify;
ax8swap_cap_inode_need_killpriv_type ax8swap_cap_inode_need_killpriv;
pgprot_t ** ax8swap_protection_map;
ax8swap_flush_cache_mm_type ax8swap_flush_cache_mm;
ax8swap___pgd_error_type ax8swap___pgd_error;
ax8swap_first_online_pgdat_type ax8swap_first_online_pgdat;
ax8swap_user_shm_unlock_type ax8swap_user_shm_unlock;
ax8swap_prop_change_shift_type ax8swap_prop_change_shift;
ax8swap_pdflush_operation_type ax8swap_pdflush_operation;
ax8swap_flush_cache_range_type ax8swap_flush_cache_range;
ax8swap_added_exe_file_vma_type ax8swap_added_exe_file_vma;
long *  ax8swap_vm_total_pages;
struct inodes_stat_t * ax8swap_inodes_stat;
unsigned long * ax8swap_scan_unevictable_pages;
ax8swap_slab_is_available_type ax8swap_slab_is_available;
ax8swap___prop_inc_single_type ax8swap___prop_inc_single;
ax8swap_user_shm_lock_type ax8swap_user_shm_lock;
ax8swap_v6wbi_flush_user_tlb_range_type ax8swap_v6wbi_flush_user_tlb_range;
int * ax8swap_buffer_heads_over_limit;
ax8swap_cap_inode_killpriv_type ax8swap_cap_inode_killpriv;
ax8swap_vma_prio_tree_insert_type ax8swap_vma_prio_tree_insert;
ax8swap_locks_mandatory_locked_type ax8swap_locks_mandatory_locked;
int * ax8swap_sysctl_overcommit_memory;
int * ax8swap_sysctl_max_map_count;
ax8swap_next_online_pgdat_type ax8swap_next_online_pgdat;
ax8swap_force_page_cache_readahead_type ax8swap_force_page_cache_readahead;
int * ax8swap_sysctl_overcommit_ratio;
unsigned long * ax8swap_totalreserve_pages;
unsigned long __meminitdata * ax8swap_nr_all_pages;
ax8swap_prop_fraction_percpu_type ax8swap_prop_fraction_percpu;
ax8swap_flush_cache_page_type ax8swap_flush_cache_page;
ax8swap_try_set_zone_oom_type ax8swap_try_set_zone_oom;
ax8swap_next_zone_type ax8swap_next_zone;
ax8swap___pmd_error_type ax8swap___pmd_error;
ax8swap___flush_anon_page_type ax8swap___flush_anon_page;
ax8swap_writeback_in_progress_type ax8swap_writeback_in_progress;
ax8swap_out_of_memory_type ax8swap_out_of_memory;
ax8swap___alloc_bootmem_nopanic_type ax8swap___alloc_bootmem_nopanic;
ax8swap_removed_exe_file_vma_type ax8swap_removed_exe_file_vma;
struct kmem_cache ** ax8swap_vm_area_cachep;
ax8swap_cap_vm_enough_memory_type ax8swap_cap_vm_enough_memory;
ax8swap_sys_sync_type ax8swap_sys_sync;
int * ax8swap_vm_swappiness;
ax8swap_mlock_vma_pages_range_type ax8swap_mlock_vma_pages_range;
ax8swap_arch_get_unmapped_area_type ax8swap_arch_get_unmapped_area;
unsigned long * ax8swap_mmap_min_addr;
ax8swap_deny_write_access_type ax8swap_deny_write_access;
ax8swap___prop_inc_percpu_max_type ax8swap___prop_inc_percpu_max;
ax8swap_do_page_cache_readahead_type ax8swap_do_page_cache_readahead;
ax8swap___alloc_bootmem_node_type ax8swap___alloc_bootmem_node;
atomic_long_t * ax8swap_vm_committed_space;
ax8swap_sync_supers_type ax8swap_sync_supers;
ax8swap_mlock_vma_page_type ax8swap_mlock_vma_page;
ax8swap___lru_cache_add_type ax8swap___lru_cache_add;
ax8swap_adjust_pte_type ax8swap_adjust_pte;
ax8swap___flush_dcache_page_type ax8swap___flush_dcache_page;
struct meminfo *ax8swap_meminfo;
ax8swap_get_vmalloc_info_type ax8swap_get_vmalloc_info;
ax8swap_exit_aio_type ax8swap_exit_aio;
ax8swap_set_mm_exe_file_type ax8swap_set_mm_exe_file;
ax8swap_lru_add_drain_type ax8swap_lru_add_drain;
ax8swap_rotate_reclaimable_page_type ax8swap_rotate_reclaimable_page;
ax8swap_shmem_truncate_address_only_type ax8swap_shmem_truncate_address_only;
struct vfsmount **ax8swap_shm_mnt;
struct kmem_cache ** ax8swap_shmem_inode_cachep; 
ax8swap_put_filp_type ax8swap_put_filp;

int ax8swap_swap_enabled = 0;

// for get proc address
kallsyms_lookup_name_type kallsyms_lookup_name_ax;

static void patch(unsigned int addr, unsigned int value) {
	*(unsigned int*)addr = value;
}

// patch to an jump obcode
static void patch_to_jmp(unsigned int addr, void * func) {
	int write_value;
	// calculate the offset
	write_value = ((((unsigned int)func - 8 - addr) >> 2) & 0x00FFFFFF);
	// add the unconditional jump opcode
	write_value |= 0xEA000000;
	// and patch it
	patch(addr, write_value);
}

struct cfg_value_map {
	const char* name;
	void * new_func;
};

struct cfg_value_map2 {
	const char* name;
	void ** new_func;
};

static const struct cfg_value_map func_mapping_table[] = {
	{"shmem_swp_entry", 		&ax8swap_shmem_swp_entry},
	{"shmem_swp_alloc", 		&ax8swap_shmem_swp_alloc},
	{"shmem_free_swp", 		&ax8swap_shmem_free_swp},
	{"shmem_truncate_range", 	&ax8swap_shmem_truncate_range},
	{"shmem_truncate",		&ax8swap_shmem_truncate},
	{"shmem_notify_change", 	&ax8swap_shmem_notify_change},
	{"shmem_delete_inode", 		&ax8swap_shmem_delete_inode},
	{"shmem_unuse", 		&ax8swap_shmem_unuse},
	{"shmem_writepage", 		&ax8swap_shmem_writepage},
	{"shmem_getpage", 		&ax8swap_shmem_getpage},
	{"shmem_fault", 		&ax8swap_shmem_fault},
	{"shmem_lock", 			&ax8swap_shmem_lock},

	{"update_mmu_cache", 		&ax8swap_update_mmu_cache},
	{"flush_dcache_page",		&ax8swap_flush_dcache_page},
	{"__set_page_dirty_buffers",	&ax8swap___set_page_dirty_buffers},
	{"page_cache_pipe_buf_steal", 	&ax8swap_page_cache_pipe_buf_steal},
	{"sync_page",			&ax8swap_sync_page},
	{"mark_buffer_dirty", 		&ax8swap_mark_buffer_dirty},
	{"block_sync_page",		&ax8swap_block_sync_page},
	{"set_page_dirty_balance", 	&ax8swap_set_page_dirty_balance},
	{"__set_page_dirty_nobuffers", 	&ax8swap___set_page_dirty_nobuffers},
	{"set_page_dirty", 		&ax8swap_set_page_dirty},
	{"clear_page_dirty_for_io", 	&ax8swap_clear_page_dirty_for_io},
	{"test_clear_page_writeback", 	&ax8swap_test_clear_page_writeback},
	{"test_set_page_writeback", 	&ax8swap_test_set_page_writeback},
	{"page_mkclean", 		&ax8swap_page_mkclean},
	{"shrink_page_list",		&ax8swap_shrink_page_list},
	{"__remove_mapping",		&ax8swap___remove_mapping},
	{"shrink_active_list",		&ax8swap_shrink_active_list},
	{"page_evictable",		&ax8swap_page_evictable},
	{"pagevec_swap_free",		&ax8swap_pagevec_swap_free},
	{"__set_page_dirty", 		&ax8swap___set_page_dirty},
	{"__free_pages_ok",		&ax8swap___free_pages_ok},
	{"free_hot_cold_page",		&ax8swap_free_hot_cold_page},
	{"bad_page",			&ax8swap_bad_page},
	{"__vm_enough_memory",		&ax8swap___vm_enough_memory},
	{"zap_page_range", 		&ax8swap_zap_page_range},
	{"exit_mmap", 			&ax8swap_exit_mmap},
	{"copy_page_range", 		&ax8swap_copy_page_range},
	{"show_free_areas", 		&ax8swap_show_free_areas},
	/*{"try_to_unmap_one", 		&ax8swap_try_to_unmap_one},
	{"mmput", 			&ax8swap_mmput},
	{"page_referenced_one", 	&ax8swap_page_referenced_one},
	{"try_to_free_pages", 		&ax8swap_try_to_free_pages},
	{"sys_remap_file_pages", 	&sys_ax8swap_remap_file_pages},
	{"sys_mincore", 		&sys_ax8swap_mincore},
	{"meminfo_proc_show", 		&ax8swap_meminfo_proc_show},
	{"shrink_zone",			&ax8swap_shrink_zone},
	{"handle_mm_fault",	 	&ax8swap_handle_mm_fault},
	{"unmap_vmas", 			&ax8swap_unmap_vmas},*/
	{NULL, 				0},
};

static const struct cfg_value_map2 field_mapping_table[] = {
	{"mm_all_locks_mutex", 		(void**) &ax8swap_mm_all_locks_mutex},
	{"shrinker_rwsem", 		(void**) &ax8swap_shrinker_rwsem},
	{"shrinker_list", 		(void**) &ax8swap_shrinker_list},
	{"min_free_order_shift", 	(void**) &ax8swap_min_free_order_shift},
	{"dma_reserve", 		(void**) &ax8swap_dma_reserve},
	{"min_free_kbytes", 		(void**) &ax8swap_min_free_kbytes},
	{"ratelimit_pages", 		(void**) &ax8swap_ratelimit_pages},
	{"dirty_background_ratio", 	(void**) &ax8swap_dirty_background_ratio},
	{"dirty_background_bytes", 	(void**) &ax8swap_dirty_background_bytes},
	{"vm_highmem_is_dirtyable", 	(void**) &ax8swap_vm_highmem_is_dirtyable},
	{"vm_dirty_ratio", 		(void**) &ax8swap_vm_dirty_ratio},
	{"vm_dirty_bytes", 		(void**) &ax8swap_vm_dirty_bytes},
	{"dirty_writeback_interval", 	(void**) &ax8swap_dirty_writeback_interval},
	{"dirty_expire_interval", 	(void**) &ax8swap_dirty_expire_interval},
	{"block_dump", 			(void**) &ax8swap_block_dump},
	{"laptop_mode", 		(void**) &ax8swap_laptop_mode},
	{"vm_completions", 		(void**) &ax8swap_vm_completions},
	{"vm_dirties", 			(void**) &ax8swap_vm_dirties},
	{"wb_timer", 			(void**) &ax8swap_wb_timer},
	{"laptop_mode_wb_timer", 	(void**) &ax8swap_laptop_mode_wb_timer},
	{"bdi_min_ratio", 		(void**) &ax8swap_bdi_min_ratio},
	{"anon_vma_cachep", 		(void**) &ax8swap_anon_vma_cachep},
	{"shmem_swaplist_mutex", 	(void**) &ax8swap_shmem_swaplist_mutex},
	{"shmem_swaplist", 		(void**) &ax8swap_shmem_swaplist},
	{"last_mem_notify", 		(void**) &ax8swap_last_mem_notify},
	{"flush_ptrace_access", 	(void**) &ax8swap_flush_ptrace_access},
	{"mlock_vma_pages_range", 	(void**) &ax8swap_mlock_vma_pages_range},
	{"writeback_inodes", 		(void**) &ax8swap_writeback_inodes},
	{"per_cpu__mmu_gathers", 	(void**) &ax8swap_per_cpu_mmu_gathers},
	{"highest_memmap_pfn", 		(void**) &ax8swap_highest_memmap_pfn},
	{"max_sane_readahead", 		(void**) &ax8swap_max_sane_readahead},
	{"clear_zonelist_oom", 		(void**) &ax8swap_clear_zonelist_oom},
	{"page_cluster", 		(void**) &ax8swap_page_cluster},
	{"nr_kernel_pages", 		(void**) &ax8swap_nr_kernel_pages},
	{"munlock_vma_pages_range",	(void**) &ax8swap_munlock_vma_pages_range},
	{"prop_descriptor_init", 	(void**) &ax8swap_prop_descriptor_init},
	{"percpu_pagelist_fraction", 	(void**) &ax8swap_percpu_pagelist_fraction},
	{"prop_fraction_single", 	(void**) &ax8swap_prop_fraction_single},
	{"next_zones_zonelist", 	(void**) &ax8swap_next_zones_zonelist},
	{"__clear_page_mlock", 		(void**) &ax8swap___clear_page_mlock},
	{"page_group_by_mobility_disabled",(void**) &ax8swap_page_group_by_mobility_disabled },
	{"vma_prio_tree_remove",(void**) &ax8swap_vma_prio_tree_remove },
	{"sysctl_lowmem_reserve_ratio",(void**) &ax8swap_sysctl_lowmem_reserve_ratio },
	{"nr_blockdev_pages",(void**) &ax8swap_nr_blockdev_pages },
	{"vma_prio_tree_next",(void**) &ax8swap_vma_prio_tree_next },
	{"__memory_pressure_notify",(void**) &ax8swap___memory_pressure_notify },
	{"cap_inode_need_killpriv",(void**) &ax8swap_cap_inode_need_killpriv },
	{"protection_map",(void**) &ax8swap_protection_map },
	{"flush_cache_mm",(void**) &ax8swap_flush_cache_mm },
	{"__pgd_error",(void**) &ax8swap___pgd_error },
	{"first_online_pgdat",(void**) &ax8swap_first_online_pgdat },
	{"user_shm_unlock",(void**) &ax8swap_user_shm_unlock },
	{"prop_change_shift",(void**) &ax8swap_prop_change_shift },
	{"pdflush_operation",(void**) &ax8swap_pdflush_operation },
	{"flush_cache_range",(void**) &ax8swap_flush_cache_range },
	{"added_exe_file_vma",(void**) &ax8swap_added_exe_file_vma },
	{"vm_total_pages",(void**) &ax8swap_vm_total_pages },
	{"inodes_stat",(void**) &ax8swap_inodes_stat },
	{"scan_unevictable_pages",(void**) &ax8swap_scan_unevictable_pages },
	{"slab_is_available",(void**) &ax8swap_slab_is_available },
	{"__prop_inc_single",(void**) &ax8swap___prop_inc_single },
	{"user_shm_lock",(void**) &ax8swap_user_shm_lock },
	{"v6wbi_flush_user_tlb_range",(void**) &ax8swap_v6wbi_flush_user_tlb_range },
	{"buffer_heads_over_limit",(void**) &ax8swap_buffer_heads_over_limit },
	{"cap_inode_killpriv",(void**) &ax8swap_cap_inode_killpriv },
	{"vma_prio_tree_insert",(void**) &ax8swap_vma_prio_tree_insert },
	{"locks_mandatory_locked",(void**) &ax8swap_locks_mandatory_locked },
	{"sysctl_overcommit_memory",(void**) &ax8swap_sysctl_overcommit_memory },
	{"sysctl_max_map_count",(void**) &ax8swap_sysctl_max_map_count },
	{"next_online_pgdat",(void**) &ax8swap_next_online_pgdat },
	{"force_page_cache_readahead",(void**) &ax8swap_force_page_cache_readahead },
	{"sysctl_overcommit_ratio",(void**) &ax8swap_sysctl_overcommit_ratio },
	{"totalreserve_pages",(void**) &ax8swap_totalreserve_pages },
	{"nr_all_pages",(void**) &ax8swap_nr_all_pages },
	{"prop_fraction_percpu",(void**) &ax8swap_prop_fraction_percpu },
	{"flush_cache_page",(void**) &ax8swap_flush_cache_page },
	{"try_set_zone_oom",(void**) &ax8swap_try_set_zone_oom },
	{"next_zone",(void**) &ax8swap_next_zone },
	{"__pmd_error",(void**) &ax8swap___pmd_error },
	{"__flush_anon_page",(void**) &ax8swap___flush_anon_page },
	{"writeback_in_progress",(void**) &ax8swap_writeback_in_progress },
	{"out_of_memory",(void**) &ax8swap_out_of_memory },
	{"__alloc_bootmem_nopanic",(void**) &ax8swap___alloc_bootmem_nopanic },
	{"removed_exe_file_vma",(void**) &ax8swap_removed_exe_file_vma },
	{"vm_area_cachep",(void**) &ax8swap_vm_area_cachep },
	{"cap_vm_enough_memory",(void**) &ax8swap_cap_vm_enough_memory },
	{"sys_sync",(void**) &ax8swap_sys_sync },
	{"vm_swappiness",(void**) &ax8swap_vm_swappiness },
	{"mlock_vma_pages_range",(void**) &ax8swap_mlock_vma_pages_range },
	{"arch_get_unmapped_area",(void**) &ax8swap_arch_get_unmapped_area },
	{"mmap_min_addr",(void**) &ax8swap_mmap_min_addr },
	{"deny_write_access",(void**) &ax8swap_deny_write_access },
	{"__prop_inc_percpu_max",(void**) &ax8swap___prop_inc_percpu_max },
	{"do_page_cache_readahead",(void**) &ax8swap_do_page_cache_readahead },
	{"__alloc_bootmem_node",(void**) &ax8swap___alloc_bootmem_node },
	{"vm_committed_space",(void**) &ax8swap_vm_committed_space },
	{"sync_supers",(void**) &ax8swap_sync_supers },
	{"mlock_vma_page", (void**) &ax8swap_mlock_vma_page},
	{"__lru_cache_add", (void**) &ax8swap___lru_cache_add},
	{"adjust_pte", (void**) &ax8swap_adjust_pte},
	{"__flush_dcache_page", (void**) &ax8swap___flush_dcache_page},
	{"meminfo", (void**) &ax8swap_meminfo},
	{"get_vmalloc_info", (void**) &ax8swap_get_vmalloc_info},
	{"exit_aio", (void**) &ax8swap_exit_aio},
	{"set_mm_exe_file", (void**) &ax8swap_set_mm_exe_file},
	{"lru_add_drain", (void**) &ax8swap_lru_add_drain},
	{"rotate_reclaimable_page", (void**) &ax8swap_rotate_reclaimable_page},
	{"shmem_truncate", (void**) &ax8swap_shmem_truncate_address_only},
	{"shm_mnt", (void**) &ax8swap_shm_mnt},
	{"shmem_inode_cachep", (void**) &ax8swap_shmem_inode_cachep},
	{"put_filp", 		(void**) &ax8swap_put_filp},
	{NULL,				0},
};

static int hijack_functions(int check_only)
{	
	const struct cfg_value_map * t = func_mapping_table;
	int func, func_ax;
	int ret = 1;
	char path[256];

	while (t->name) {
		func = kallsyms_lookup_name_ax(t->name);
		if(check_only)
		{
			if(!func)
			{
				printk(KERN_ERR AX_MODULE_NAME ": Pointer to %s not found!!!\n", t->name);	
				ret = 0;
			}
			else
			{
				printk(KERN_ERR AX_MODULE_NAME ": Pointer to %s: %d\n", t->name,  func);
				sprintf(path, "ax8swap_%s", t->name);
				func_ax = kallsyms_lookup_name_ax(path);
				if(func_ax && abs(func - func_ax) < 200000 )
				{
					printk(KERN_ERR AX_MODULE_NAME ": Pointer to %s something wrong: %d %d !!!\n", t->name, func, func_ax);	
				}	
			}
		}
		else if(func)
		{
			patch_to_jmp(func, t->new_func);
			printk(KERN_ERR AX_MODULE_NAME ": Function %s hijacked\n", t->name);	
		}
		else
			ret = 0;
		t++;
	}

	return ret;
}

static int hijack_fields(int check_only)
{	
	const struct cfg_value_map2 * t = field_mapping_table;
	int func, func_ax;
	int ret = 1;
	char path[256];

	while (t->name) {
		func = kallsyms_lookup_name_ax(t->name);
		if(check_only)
		{
			if(!func)
			{
				printk(KERN_ERR AX_MODULE_NAME ": Pointer to %s not found!!!\n", t->name);	
				ret = 0;
			}
			else
			{
				printk(KERN_ERR AX_MODULE_NAME ": Pointer to %s: %d\n", t->name,  func);
				sprintf(path, "ax8swap_%s", t->name);
				func_ax = kallsyms_lookup_name_ax(path);
				if(func_ax && abs(func - func_ax) < 200000 )
				{
					printk(KERN_ERR AX_MODULE_NAME ": Pointer to %s something wrong: %d %d !!!\n", t->name, func, func_ax);	
				}	
			}
		} else if(func)
		{
			*(t->new_func) = (void *)func;
			printk(KERN_ERR AX_MODULE_NAME ": Field %s set\n", t->name);	
		}
		else
			ret = 0;
		t++;
	}

	return ret;
}

void check_pages(void)
{
	int node, i;
	struct meminfo * mi = ax8swap_meminfo;

	for_each_online_node(node) {
		pg_data_t *n = NODE_DATA(node);
		struct page *map = pgdat_page_nr(n, 0) - n->node_start_pfn;

		for_each_nodebank (i,mi,node) {
			struct membank *bank = &mi->bank[i];
			unsigned int pfn1, pfn2;
			struct page *page, *end;

			pfn1 = bank_pfn_start(bank);
			pfn2 = bank_pfn_end(bank);

			page = map + pfn1;
			end  = map + pfn2;

			do {
			        if (PageSwapCache(page))
				{
					printk(KERN_ERR AX_MODULE_NAME ": Page cached before cache \n");
				}

				page++;
			} while (page < end);
		}
	}
}

/* printk's without a loglevel use this.. */
#define DEFAULT_MESSAGE_LOGLEVEL 4 /* KERN_WARNING */

/* We show everything that is MORE important than this.. */
#define MINIMUM_CONSOLE_LOGLEVEL 1 /* Minimum loglevel we let people use */
#define DEFAULT_CONSOLE_LOGLEVEL 7 /* anything MORE serious than KERN_DEBUG */

int console_printk[4] = {
	DEFAULT_CONSOLE_LOGLEVEL,	/* console_loglevel */
	DEFAULT_MESSAGE_LOGLEVEL,	/* default_message_loglevel */
	MINIMUM_CONSOLE_LOGLEVEL,	/* minimum_console_loglevel */
	DEFAULT_CONSOLE_LOGLEVEL,	/* default_console_loglevel */
};

/*
 * We want to turn all lock-debugging facilities on/off at once,
 * via a global flag. The reason is that once a single bug has been
 * detected and reported, there might be cascade of followup bugs
 * that would just muddy the log. So we report the first one and
 * shut up after that.
 */
int debug_locks = 1;

/*
 * The locking-testsuite uses <debug_locks_silent> to get a
 * 'silent failure': nothing is printed to the console when
 * a locking bug is detected.
 */
int debug_locks_silent;

/*
 * Generic 'turn off all lock debugging' function:
 */
int debug_locks_off(void)
{
	if (xchg(&debug_locks, 0)) {
		if (!debug_locks_silent) {
			oops_in_progress = 1;
			console_verbose();
			return 1;
		}
	}
	return 0;
}

void __kprobes add_preempt_count(int val)
{
#ifdef CONFIG_DEBUG_PREEMPT
	/*
	 * Underflow?
	 */
	if (DEBUG_LOCKS_WARN_ON((preempt_count() < 0)))
		return;
#endif
	preempt_count() += val;
#ifdef CONFIG_DEBUG_PREEMPT
	/*
	 * Spinlock count overflowing soon?
	 */
	DEBUG_LOCKS_WARN_ON((preempt_count() & PREEMPT_MASK) >=
				PREEMPT_MASK - 10);
#endif
	if (preempt_count() == val)
		trace_preempt_off(CALLER_ADDR0, get_parent_ip(CALLER_ADDR1));
}


void __kprobes sub_preempt_count(int val)
{
#ifdef CONFIG_DEBUG_PREEMPT
	/*
	 * Underflow?
	 */
	if (DEBUG_LOCKS_WARN_ON(val > preempt_count()))
		return;
	/*
	 * Is the spinlock portion underflowing?
	 */
	if (DEBUG_LOCKS_WARN_ON((val < PREEMPT_MASK) &&
			!(preempt_count() & PREEMPT_MASK)))
		return;
#endif

	if (preempt_count() == val)
		trace_preempt_on(CALLER_ADDR0, get_parent_ip(CALLER_ADDR1));
	preempt_count() -= val;
}

notrace unsigned int debug_smp_processor_id(void)
{
	unsigned long preempt_count = preempt_count();
	int this_cpu = raw_smp_processor_id();

	if (likely(preempt_count))
		goto out;

	if (irqs_disabled())
		goto out;

	/*
	 * Kernel threads bound to a single CPU can safely use
	 * smp_processor_id():
	 */
	if (cpumask_equal(&current->cpus_allowed, cpumask_of(this_cpu)))
		goto out;

	/*
	 * It is valid to assume CPU-locality during early bootup:
	 */
	if (system_state != SYSTEM_RUNNING)
		goto out;

	/*
	 * Avoid recursion:
	 */
	preempt_disable_notrace();

	if (!printk_ratelimit())
		goto out_enable;

	printk(KERN_ERR "BUG: using smp_processor_id() in preemptible [%08x] "
			"code: %s/%d\n",
			preempt_count() - 1, current->comm, current->pid);
	print_symbol("caller is %s\n", (long)__builtin_return_address(0));
	dump_stack();

out_enable:
	preempt_enable_no_resched_notrace();
out:
	return this_cpu;
}

int procswaps_init(void);
int ax8swap_reinit_tmpfs(void);

static int __init ax8swap_init(void)
{
	int ret = -1;
	printk(KERN_INFO AX_MODULE_NAME ": module " AX_MODULE_VER " for device " DEVICE_NAME " loaded\n");
  
	//check_pages();

	printk(KERN_ERR AX_MODULE_NAME ": Pointer to ax8swap_init %d\n", (int)&ax8swap_init);

	// our 'GetProcAddress' :D
	kallsyms_lookup_name_ax = (void*) OFS_KALLSYMS_LOOKUP_NAME;

	if(!hijack_functions(1))
		goto eof;

	if(!hijack_fields(1))
		goto eof;

	hijack_fields(0);

	printk(KERN_ERR AX_MODULE_NAME ": procswaps_init()\n");

	ret = procswaps_init();
	
	if(ret < 0)
	{
		printk(KERN_INFO AX_MODULE_NAME ": procswaps_init() failed\n");
		goto eof;
	}

	printk(KERN_ERR AX_MODULE_NAME ": hijack_functions(0);\n");

	hijack_functions(0);

	printk(KERN_ERR AX_MODULE_NAME ": ax8swap_reinit_tmpfs()\n");

	ax8swap_reinit_tmpfs();

	printk(KERN_ERR AX_MODULE_NAME ": bdi_init(swapper_space.backing_dev_info);\n");

	bdi_init(swapper_space.backing_dev_info);

eof:

	return ret;
}

module_init(ax8swap_init);

MODULE_AUTHOR ("AnDyX@xda-developers.com");
MODULE_DESCRIPTION ("Swap for " DEVICE_NAME);
MODULE_LICENSE("GPL");
