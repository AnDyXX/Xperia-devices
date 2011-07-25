/*
 * Author: AnDyX <AnDyX at xda-developers>
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 *  This module contains code from kernel required to initialise netfilter.  
 */
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/module.h>
#include <net/net_namespace.h>

#define AX_MODULE_NAME 			"ax8netfilter"
#define AX_MODULE_VER			"v001"

#define DEVICE_NAME			"X8"
#define OFS_KALLSYMS_LOOKUP_NAME	0xC00B0654			// kallsyms_lookup_name

struct ax8netfilter_net init_ax8netfilter_net;
EXPORT_SYMBOL(init_ax8netfilter_net);


/* inits of netfilters */
int ipv4_netfilter_init(void);
int ipv6_netfilter_init(void);
void netfilter_init(void);

/********* Module methods *************/
// init module
static int __init ax8netfilter_init(void)
{
	int ret = -1;

	printk(KERN_INFO AX_MODULE_NAME ": module " AX_MODULE_VER " loaded\n");

	netfilter_init();
	ret = ipv4_netfilter_init();
	if( ret < 0 )
	{
		printk(KERN_INFO AX_MODULE_NAME ": ipv4_netfilter_init() failed\n");
		goto eof;
	}

	ret = ipv6_netfilter_init();
	if( ret < 0 )
	{
		printk(KERN_INFO AX_MODULE_NAME ": ipv6_netfilter_init() failed\n");
		goto eof;
	}

	eof:
	return ret;
}

module_init(ax8netfilter_init);

MODULE_AUTHOR("AnDyX@xda-developers.com");
MODULE_DESCRIPTION("Netfilter module for X8");
MODULE_LICENSE("GPL");
