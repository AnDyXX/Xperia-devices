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
