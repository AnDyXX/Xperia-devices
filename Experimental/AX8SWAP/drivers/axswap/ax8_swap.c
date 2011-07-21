#include <linux/types.h>
#include <linux/kthread.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>


#define CONFIG_SWAP
#include <linux/swap.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>

#include "hijacked_types.h"

static inline void __put_page(struct page *page)
{
	atomic_dec(&page->_count);
}


/************* hijacked function pointers **************/
int * ax8swap_page_cluster;
__lru_cache_add_type ax8swap___lru_cache_add;
release_pages_type ax8swap_release_pages;
page_add_anon_rmap_type ax8swap_page_add_anon_rmap;
shmem_unuse_type ax8swap_shmem_unuse;
lru_add_drain_type ax8swap_lru_add_drain;
page_address_in_vma_type ax8swap_page_address_in_vma;
pmd_clear_bad_type ax8swap_pmd_clear_bad;
cap_vm_enough_memory_type ax8swap_cap_vm_enough_memory;
activate_page_type ax8swap_activate_page;


/************* hijacked functions **************/
#include "ax8__swap.c"
#include "ax8__migrate.c"


#define AX_MODULE_VER			"v001"
#define AX_MODULE_NAME			"ax8swap"

#define DEVICE_NAME			"X8"
#define OFS_KALLSYMS_LOOKUP_NAME	0xC00B0654			// kallsyms_lookup_name

#ifdef CONFIG_PROC_FS__
extern const struct file_operations proc_swaps_operations;
#endif


struct cfg_value_map {
	const char* name;
	void * new_func;
};

static const struct cfg_value_map func_mapping_table[] = {
	{"migrate_page_move_mapping", 	&ax8swap_migrate_page_move_mapping },
	{"pagevec_swap_free", 		&ax8swap_pagevec_swap_free },
	{"__lru_cache_add", 		&ax8swap___lru_cache_add },
	{"release_pages", 		&ax8swap_release_pages },
	{"page_add_anon_rmap", 		&ax8swap_page_add_anon_rmap },
	{"shmem_unuse", 		&ax8swap_shmem_unuse },
	{"lru_add_drain", 		&ax8swap_lru_add_drain },
	{"page_address_in_vma", 	&ax8swap_page_address_in_vma },
	{"pmd_clear_bad", 		&ax8swap_pmd_clear_bad },
	{"cap_vm_enough_memory", 	&ax8swap_cap_vm_enough_memory },
	{"activate_page", 		&ax8swap_activate_page },
	{NULL, 0},
};

static struct cfg_value_map struct_mapping_table[] = {
	{"swapper_space", 	&ax8swap_swapper_space },
	{"page_cluster",  	&ax8swap_page_cluster },
	{NULL, 0},
};

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

static int hijack_functions(int check_only)
{	
	const struct cfg_value_map * t = func_mapping_table;
	int func;
	int ret = 1;

	while (t->name) {
		func = kallsyms_lookup_name_ax(t->name);
		if(check_only)
		{
			if(func)
				printk(KERN_ERR AX_MODULE_NAME ": %s found\n", t->name);	
			else
			{
				printk(KERN_ERR AX_MODULE_NAME ": %s not found!!!\n", t->name);	
				ret = 0;
			}
		}
		else
			if(func)
			{
				patch_to_jmp(func, t->new_func);
				printk(KERN_ERR AX_MODULE_NAME ": %s hijacked\n", t->name);	
			}
			else
				ret = 0;
		t++;
	}

	return ret;
}

static int hijack_structs(int check_only)
{	
	const struct cfg_value_map * t = struct_mapping_table;
	void * func;
	void * address;
	int ret = 1;

	while (t->name) {
		func = (void *)kallsyms_lookup_name_ax(t->name);
		if(check_only)
		{
			if(func)
				printk(KERN_ERR AX_MODULE_NAME ": %s found\n", t->name);	
			else
			{
				printk(KERN_ERR AX_MODULE_NAME ": %s not found!!!\n", t->name);	
				ret = 0;
			}
		}
		else
			if(func)
			{
				//&(t->new_func) = func;
				address = t->new_func;
				address =  func;
				printk(KERN_ERR AX_MODULE_NAME ": %s hijacked\n", t->name);	
			}
			else
				ret = 0;
		t++;
	}

	return ret;
}

static int __init ax8swap_init(void)
{
	printk(KERN_INFO AX_MODULE_NAME ": module " AX_MODULE_VER " loaded\n");
  
	// our 'GetProcAddress' :D
	kallsyms_lookup_name_ax = (void*) OFS_KALLSYMS_LOOKUP_NAME;

	if(hijack_functions(1) && hijack_structs(1))
	{

		ax8swap_swap_setup();
#ifdef CONFIG_PROC_FS__
		proc_create("swaps", 0, NULL, &proc_swaps_operations);
#endif
	}
	return -1;
}

module_init(ax8swap_init);

MODULE_AUTHOR ("AnDyX@xda-developers.com");
MODULE_DESCRIPTION ("Swap enabler for X8");
MODULE_LICENSE("GPL");
