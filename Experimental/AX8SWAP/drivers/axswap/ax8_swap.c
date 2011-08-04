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
