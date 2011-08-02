#include <linux/types.h>
#include <linux/kthread.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>

#include "hijacked_types.h"


#define AX_MODULE_VER			"v001"
#define AX_MODULE_NAME			"ax8swap"

#define DEVICE_NAME			"X8"
#define OFS_KALLSYMS_LOOKUP_NAME	0xC00B0654			// kallsyms_lookup_name

// for get proc address
typedef unsigned long (*kallsyms_lookup_name_type)(const char *name);
static kallsyms_lookup_name_type kallsyms_lookup_name_ax;

static int __init ax8swap_init(void)
{
	int ret = -1;
	printk(KERN_INFO AX_MODULE_NAME ": module " AX_MODULE_VER " loaded\n");
  
	// our 'GetProcAddress' :D
	kallsyms_lookup_name_ax = (void*) OFS_KALLSYMS_LOOKUP_NAME;

	//int procswaps_init(void)

	return ret;
}

module_init(ax8swap_init);

MODULE_AUTHOR ("AnDyX@xda-developers.com");
MODULE_DESCRIPTION ("Swap enabler for X8");
MODULE_LICENSE("GPL");
