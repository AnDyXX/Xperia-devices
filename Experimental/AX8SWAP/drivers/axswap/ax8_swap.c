#include <linux/types.h>
#include <linux/kthread.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/swap.h>

#include "hijacked_types.h"


#define AX_MODULE_VER			"v001"
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

struct prop_descriptor * ax8swap_vm_completions;

ax8swap_adjust_pte_type ax8swap_adjust_pte;
ax8swap_putback_lru_page_type ax8swap_putback_lru_page;
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
	{"sys_mincore", 		&sys_ax8swap_mincore},
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
	{"pagevec_swap_free",		&ax8swap_pagevec_swap_free},
	{"__set_page_dirty", 		&ax8swap___set_page_dirty},
	{"__free_pages_ok",		&ax8swap___free_pages_ok},
	{"free_hot_cold_page",		&ax8swap_free_hot_cold_page},
	{"bad_page",			&ax8swap_bad_page},
	{NULL, 				0},
};

static const struct cfg_value_map2 field_mapping_table[] = {
	{"adjust_pte", 			(void**) &ax8swap_adjust_pte},
	{"vm_completions", 		(void**) &ax8swap_vm_completions},
	{"putback_lru_page", 		(void**) &ax8swap_putback_lru_page},
	{"shmem_swaplist_mutex", 	(void**) &ax8swap_shmem_swaplist_mutex},
	{"shmem_swaplist", 		(void**) &ax8swap_shmem_swaplist},
	{"bad_page", 			(void**) &ax8swap_bad_page},
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
		else
			if(func)
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
		}
		else
			if(func)
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

	hijack_fields(0);

	ret = procswaps_init();
	
	if(ret < 0)
	{
		printk(KERN_INFO AX_MODULE_NAME ": procswaps_init() failed\n");
		goto eof;
	}

	bdi_init(swapper_space.backing_dev_info);

eof:

	return ret;
}

module_init(ax8swap_init);

MODULE_AUTHOR ("AnDyX@xda-developers.com");
MODULE_DESCRIPTION ("Swap for " DEVICE_NAME);
MODULE_LICENSE("GPL");
