#include <linux/types.h>
#include <linux/kthread.h>
#include <linux/device.h>
#include <linux/module.h>
//#include "swap.h"

#define AX_MODULE_VER			"v001"
#define AX_MODULE_NAME			"ax8swap"

#define DEVICE_NAME			"X8"
#define OFS_KALLSYMS_LOOKUP_NAME	0xC00B0654			// kallsyms_lookup_name

#ifdef CONFIG_PROC_FS
extern const struct file_operations proc_swaps_operations
#endif


static int __init dlt002_init(void)
{
#ifdef CONFIG_PROC_FS__
	proc_create("swaps", 0, NULL, &proc_swaps_operations);
#endif
	return -1;
}

module_init(ax8swap_init);


MODULE_LICENSE("GPL");
