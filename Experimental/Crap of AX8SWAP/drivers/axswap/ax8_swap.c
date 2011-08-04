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


ax8swap_adjust_pte_type ax8swap_adjust_pte;
ax8swap___flush_dcache_page_type ax8swap___flush_dcache_page;
struct meminfo * ax8swap_meminfo;
ax8swap_get_vmalloc_info_type ax8swap_get_vmalloc_info;
int * ax8swap_vm_swappiness;
long * ax8swap_vm_total_pages;
int * ax8swap_sysctl_overcommit_memory;
int * ax8swap_sysctl_overcommit_ratio;
atomic_long_t * ax8swap_vm_committed_space;
ax8swap_munlock_vma_pages_range_type ax8swap_munlock_vma_pages_range;
struct mutex * ax8swap_shmem_swaplist_mutex;
struct list_head * ax8swap_shmem_swaplist;
ax8swap_shmem_truncate_address_only_type ax8swap_shmem_truncate_address_only;
ax8swap_vma_prio_tree_remove_type ax8swap_vma_prio_tree_remove;
ax8swap_user_shm_unlock_type ax8swap_user_shm_unlock;
ax8swap_cap_vm_enough_memory_type ax8swap_cap_vm_enough_memory;
ax8swap_exit_aio_type ax8swap_exit_aio;
ax8swap_set_mm_exe_file_type ax8swap_set_mm_exe_file;
ax8swap_user_shm_lock_type ax8swap_user_shm_lock;
int * axswap_page_cluster;
ax8swap_flush_cache_mm_type ax8swap_flush_cache_mm;
unsigned long *ax8swap_totalram_pages;
unsigned long *ax8swap_totalreserve_pages;
struct kmem_cache **ax8swap_vm_area_cachep;
ax8swap_flush_ptrace_access_type ax8swap_flush_ptrace_access;
unsigned long * ax8swap_highest_memmap_pfn;
ax8swap___clear_page_mlock_type ax8swap___clear_page_mlock;
ax8swap_vma_prio_tree_next_type ax8swap_vma_prio_tree_next;
ax8swap___pte_error_type ax8swap___pte_error;
ax8swap___pmd_error_type ax8swap___pmd_error;
ax8swap___pgd_error_type ax8swap___pgd_error;
ax8swap___flush_anon_page_type ax8swap___flush_anon_page;
ax8swap_v6wbi_flush_user_tlb_range_type ax8swap_v6wbi_flush_user_tlb_range;
struct prop_descriptor * ax8swap_vm_completions;
ax8swap_flush_cache_range_type ax8swap_flush_cache_range;
ax8swap_flush_cache_page_type ax8swap_flush_cache_page;
ax8swap_unlink_file_vma_type ax8swap_unlink_file_vma;

// for get proc address
typedef unsigned long (*kallsyms_lookup_name_type)(const char *name);
static kallsyms_lookup_name_type kallsyms_lookup_name_ax;

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
	{"_update_mmu_cache", 			&ax8swap_update_mmu_cache},
	{"flush_dcache_page",			&ax8swap_flush_dcache_page},
	{"show_mem", 				&ax8swap_show_mem},
	{"block_sync_page",			&ax8swap_block_sync_page},
	{"mark_buffer_dirty", 			&ax8swap_mark_buffer_dirty},
	{"__set_page_dirty_buffers",		&ax8swap___set_page_dirty_buffers},
	{"__set_page_dirty", 			&ax8swap___set_page_dirty},
	{"meminfo_proc_show", 			&ax8swap_meminfo_proc_show},
	{"page_cache_pipe_buf_steal", 		&ax8swap_page_cache_pipe_buf_steal},
	{"sys_mincore", 			&sys_ax8swap_mincore},
	{"sys_remap_file_pages", 		&sys_ax8swap_remap_file_pages},
	{"shmem_swp_entry", 			&ax8swap_shmem_swp_entry},
	{"shmem_swp_alloc", 			&ax8swap_shmem_swp_alloc},
	{"shmem_free_swp", 			&ax8swap_shmem_free_swp},
	{"shmem_truncate_range", 		&ax8swap_shmem_truncate_range},
	{"shmem_truncate",			&ax8swap_shmem_truncate},
	{"shmem_notify_change", 		&ax8swap_shmem_notify_change},
	{"shmem_delete_inode", 			&ax8swap_shmem_delete_inode},
	{"shmem_unuse", 			&ax8swap_shmem_unuse},
	{"shmem_writepage", 			&ax8swap_shmem_writepage},
	{"shmem_getpage", 			&ax8swap_shmem_getpage},
	{"shmem_fault", 			&ax8swap_shmem_fault},
	{"shmem_lock", 				&ax8swap_shmem_lock},
	{"shmem_free_blocks", 			&ax8swap_shmem_free_blocks},
	{"shmem_reserve_inode", 		&ax8swap_shmem_reserve_inode},
	{"shmem_free_inode", 			&ax8swap_shmem_free_inode},
	{"mmput", 				&ax8swap_mmput},
	{"__remove_from_page_cache", 		&ax8swap___remove_from_page_cache},
	{"remove_from_page_cache", 		&ax8swap_remove_from_page_cache},
	{"sync_page", 				&ax8swap_sync_page},
	{"handle_mm_fault", 			&ax8swap_handle_mm_fault},
	{"vmtruncate", 				&ax8swap_vmtruncate},
	{"unmap_mapping_range", 		&ax8swap_unmap_mapping_range},
	{"apply_to_page_range", 		&ax8swap_apply_to_page_range},
	{"remap_pfn_range",			&ax8swap_remap_pfn_range},
	{"vm_insert_mixed", 			&ax8swap_vm_insert_mixed},
	{"vm_insert_pfn", 			&ax8swap_vm_insert_pfn},
	{"vm_insert_page", 			&ax8swap_vm_insert_page},
	{"get_user_pages",			&ax8swap_get_user_pages},
	{"zap_vma_ptes", 			&ax8swap_zap_vma_ptes},
	{NULL, 				0},
};

static const struct cfg_value_map2 field_mapping_table[] = {
	{"adjust_pte", 			(void**) &ax8swap_adjust_pte},
	{"__flush_dcache_page", 	(void**) &ax8swap___flush_dcache_page},
	{"meminfo", 			(void**) &ax8swap_meminfo},
	{"get_vmalloc_info", 		(void**) &ax8swap_get_vmalloc_info},
	{"vm_swappiness", 		(void**) &ax8swap_vm_swappiness},
	{"vm_total_pages", 		(void**) &ax8swap_vm_total_pages},
	{"sysctl_overcommit_memory", 	(void**) &ax8swap_sysctl_overcommit_memory},
	{"sysctl_overcommit_ratio", 	(void**) &ax8swap_sysctl_overcommit_ratio},
	{"vm_committed_space", 		(void**) &ax8swap_vm_committed_space},
	{"munlock_vma_pages_range", 	(void**) &ax8swap_munlock_vma_pages_range},
	{"shmem_swaplist_mutex", 	(void**) &ax8swap_shmem_swaplist_mutex},
	{"shmem_swaplist", 		(void**) &ax8swap_shmem_swaplist},
	{"shmem_truncate", 		(void**) &ax8swap_shmem_truncate_address_only},
	{"vma_prio_tree_remove", 	(void**) &ax8swap_vma_prio_tree_remove},
	{"user_shm_unlock", 		(void**) &ax8swap_user_shm_unlock},
	{"cap_vm_enough_memory", 	(void**) &ax8swap_cap_vm_enough_memory},
	{"exit_aio", 			(void**) &ax8swap_exit_aio},
	{"set_mm_exe_file",		(void**) &ax8swap_set_mm_exe_file},
	{"user_shm_lock", 		(void**) &ax8swap_user_shm_lock},
	{"page_cluster", 		(void**) &axswap_page_cluster},
	{"flush_cache_mm", 		(void**) &ax8swap_flush_cache_mm},
	{"totalram_pages", 		(void**) &ax8swap_totalram_pages},
	{"totalreserve_pages", 		(void**) &ax8swap_totalreserve_pages},
	{"vm_area_cachep", 		(void**) &ax8swap_vm_area_cachep},
	{"flush_ptrace_access", 	(void**) &ax8swap_flush_ptrace_access},
	{"highest_memmap_pfn", 		(void**) &ax8swap_highest_memmap_pfn},
	{"__clear_page_mlock", 		(void**) &ax8swap___clear_page_mlock},
	{"vma_prio_tree_next", 		(void**) &ax8swap_vma_prio_tree_next},
	{"__pte_error", 		(void**) &ax8swap___pte_error},
	{"__pmd_error", 		(void**) &ax8swap___pmd_error},
	{"__pgd_error", 		(void**) &ax8swap___pgd_error},
	{"__flush_anon_page", 		(void**) &ax8swap___flush_anon_page},
	{"v6wbi_flush_user_tlb_range", 	(void**) &ax8swap_v6wbi_flush_user_tlb_range},
	{"vm_completions", 		(void**) &ax8swap_vm_completions},
	{"flush_cache_range", 		(void**) &ax8swap_flush_cache_range},
	{"flush_cache_page", 		(void**) &ax8swap_flush_cache_page},
	{"swap_unlink_file_vma", 	(void**) &ax8swap_unlink_file_vma},
	{NULL,				0},
};

static int hijack_functions(int check_only)
{	
	const struct cfg_value_map * t = func_mapping_table;
	int func;
	int ret = 1;

	while (t->name) {
		func = kallsyms_lookup_name_ax(t->name);
		if(check_only)
		{
			if(!func)
			{
				printk(KERN_ERR AX_MODULE_NAME ": Pointer to %s not found!!!\n", t->name);	
				ret = 0;
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
	int func;
	int ret = 1;

	while (t->name) {
		func = kallsyms_lookup_name_ax(t->name);
		if(check_only)
		{
			if(!func)
			{
				printk(KERN_ERR AX_MODULE_NAME ": Pointer to %s not found!!!\n", t->name);	
				ret = 0;
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

int procswaps_init(void);

static int __init ax8swap_init(void)
{
	int ret = -1;
	printk(KERN_INFO AX_MODULE_NAME ": module " AX_MODULE_VER " for device " DEVICE_NAME " loaded\n");
  
	// our 'GetProcAddress' :D
	kallsyms_lookup_name_ax = (void*) OFS_KALLSYMS_LOOKUP_NAME;

	if(!hijack_functions(1))
		goto eof;

	if(!hijack_fields(1))
		goto eof;

	//hijack_fields(0);

	//ret = procswaps_init();
	
	if(ret < 0)
	{
		printk(KERN_INFO AX_MODULE_NAME ": procswaps_init() failed\n");
		goto eof;
	}

	//hijack_functions(0);

	//bdi_init(swapper_space.backing_dev_info);

eof:

	return ret-100;
}

module_init(ax8swap_init);

MODULE_AUTHOR ("AnDyX@xda-developers.com");
MODULE_DESCRIPTION ("Swap for " DEVICE_NAME);
MODULE_LICENSE("GPL");
