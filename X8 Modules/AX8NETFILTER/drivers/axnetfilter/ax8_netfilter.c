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
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/module.h>
#include <net/net_namespace.h>
#include <linux/skbuff.h>
#include <net/arp.h>
#include <net/dst.h>

#include "ax8netfilter.h"

#define AX_MODULE_NAME 			"ax8netfilter"
#define AX_MODULE_VER			"v001"

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

struct ax8netfilter_net init_ax8netfilter_net;
EXPORT_SYMBOL(init_ax8netfilter_net);

// for get proc address
typedef unsigned long (*kallsyms_lookup_name_type)(const char *name);
static kallsyms_lookup_name_type kallsyms_lookup_name_ax;

//struct net_protocol *** ax8netfilter_inet_protos;
struct net_protocol ** ax8netfilter_inet_protos ____cacheline_aligned_in_smp; 

int * ax8netfilter_sysctl_ip_default_ttl;
int * ax8netfilter_sysctl_igmp_max_msf;

ax8netfilter_arp_processtype ax8netfilter_arp_process;
ax8netfilter_ip_finish_output2_type ax8netfilter_ip_finish_output2;
ax8netfilter_xfrm_output_type ax8netfilter_xfrm_output;
ax8netfilter_xfrm_output2_type ax8netfilter_xfrm_output2;
ax8netfilter_ip_forward_options_type ax8netfilter_ip_forward_options;
ax8netfilter_ip_call_ra_chain_type ax8netfilter_ip_call_ra_chain;
ax8netfilter_ip_rt_send_redirect_type ax8netfilter_ip_rt_send_redirect;
ax8netfilter_raw_local_deliver_type ax8netfilter_raw_local_deliver;
ax8netfilter_ip_options_fragment_type ax8netfilter_ip_options_fragment;
ax8netfilter_ip_options_get_from_user_type ax8netfilter_ip_options_get_from_user;
ax8netfilter_ip_mc_leave_group_type ax8netfilter_ip_mc_leave_group;
ax8netfilter_ip_mc_msfilter_type ax8netfilter_ip_mc_msfilter;
ax8netfilter_ip_mc_source_type ax8netfilter_ip_mc_source;
ax8netfilter_ip_ra_control_type ax8netfilter_ip_ra_control;
ax8netfilter_ip_options_undo_type ax8netfilter_ip_options_undo;
ax8netfilter_ip_mc_msfget_type ax8netfilter_ip_mc_msfget;
ax8netfilter_ip_mc_gsfget_type ax8netfilter_ip_mc_gsfget;
ax8netfilter_ip_local_error_type ax8netfilter_ip_local_error;
ax8netfilter_icmp_out_count_type ax8netfilter_icmp_out_count;
ax8netfilter_ip_cmsg_send_type ax8netfilter_ip_cmsg_send;
ax8netfilter_ip_append_data_type ax8netfilter_ip_append_data;
ax8netfilter_ip_push_pending_frames_type ax8netfilter_ip_push_pending_frames;
ax8netfilter_ip_flush_pending_frames_type ax8netfilter_ip_flush_pending_frames;
ax8netfilter_xfrm_replay_notify_type ax8netfilter_xfrm_replay_notify;
ax8netfilter_ip_options_compile_type ax8netfilter_ip_options_compile;
ax8netfilter_ip_options_rcv_srr_type ax8netfilter_ip_options_rcv_srr;


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

static const struct cfg_value_map func_mapping_table[] = {
	{"skb_release_head_state",	&ax8netfilter_skb_release_head_state},
	{"__copy_skb_header", 		&ax8netfilter___copy_skb_header},
	{"arp_xmit",			&ax8netfilter_arp_xmit},
	{"arp_rcv", 			&ax8netfilter_arp_rcv},
	{"ip_forward",			&ax8netfilter_ip_forward},
	{"ip_local_deliver", 		&ax8netfilter_ip_local_deliver},
	{"__ip_local_out", 		&ax8netfilter___ip_local_out},
	{"ip_mc_output",		&ax8netfilter_ip_mc_output},
	{"ip_output",			&ax8netfilter_ip_output},
	{"ip_fragment",			&ax8netfilter_ip_fragment},
	{"ip_setsockopt",		&ax8netfilter_ip_setsockopt},
	{"ip_getsockopt",		&ax8netfilter_ip_getsockopt},
	{"raw_sendmsg", 		&ax8netfilter_raw_sendmsg},
	{"raw_rcv",			&ax8netfilter_raw_rcv},
	{"xfrm4_transport_finish",	&ax8netfilter_xfrm4_transport_finish},
	{"xfrm_output_resume", 		&ax8netfilter_xfrm_output_resume},
	{"ip_rcv", 			&ax8netfilter_ip_rcv},
	{NULL, 				0},
};

struct cfg_value_map2 {
	const char* name;
	void ** new_func;
};

static const struct cfg_value_map2 field_mapping_table[] = {
	{"arp_process", 		(void**) &ax8netfilter_arp_process },
	{"ip_finish_output2", 		(void**) &ax8netfilter_ip_finish_output2},
	{"xfrm_output", 		(void**) &ax8netfilter_xfrm_output},
	{"xfrm_output2",		(void**) &ax8netfilter_xfrm_output2},
	{"inet_protos",			(void**) &ax8netfilter_inet_protos},
	{"ip_forward_options", 		(void**) &ax8netfilter_ip_forward_options},
	{"ip_call_ra_chain",    	(void**) &ax8netfilter_ip_call_ra_chain},
	{"ip_rt_send_redirect", 	(void**) &ax8netfilter_ip_rt_send_redirect},
	{"raw_local_deliver",   	(void**) &ax8netfilter_raw_local_deliver},
	{"ip_options_fragment", 	(void**) &ax8netfilter_ip_options_fragment},
	{"ip_options_get_from_user", 	(void**) &ax8netfilter_ip_options_get_from_user},
	{"ip_mc_leave_group", 		(void**) &ax8netfilter_ip_mc_leave_group},
	{"ip_mc_msfilter", 		(void**) &ax8netfilter_ip_mc_msfilter},
	{"ip_mc_source", 		(void**) &ax8netfilter_ip_mc_source},
	{"ip_ra_control", 		(void**) &ax8netfilter_ip_ra_control},
	{"ip_options_undo", 		(void**) &ax8netfilter_ip_options_undo},
	{"ip_mc_msfget", 		(void**) &ax8netfilter_ip_mc_msfget},
	{"ip_mc_gsfget", 		(void**) &ax8netfilter_ip_mc_gsfget},
	{"sysctl_ip_default_ttl", 	(void**) &ax8netfilter_sysctl_ip_default_ttl},
	{"ip_local_error", 		(void**) &ax8netfilter_ip_local_error},
	{"icmp_out_count", 		(void**) &ax8netfilter_icmp_out_count},
	{"ip_cmsg_send",	 	(void**) &ax8netfilter_ip_cmsg_send},
	{"ip_append_data", 		(void**) &ax8netfilter_ip_append_data},
	{"ip_push_pending_frames", 	(void**) &ax8netfilter_ip_push_pending_frames},
	{"ip_flush_pending_frames", 	(void**) &ax8netfilter_ip_flush_pending_frames},
	{"xfrm_replay_notify", 		(void**) &ax8netfilter_xfrm_replay_notify},
	{"sysctl_igmp_max_msf", 	(void**) &ax8netfilter_sysctl_igmp_max_msf},
	{"ip_options_compile", 		(void**) &ax8netfilter_ip_options_compile},
	{"ip_options_rcv_srr", 		(void**) &ax8netfilter_ip_options_rcv_srr},
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

/* inits of netfilters */
int ipv4_netfilter_init(void);
int ipv6_netfilter_init(void);
void netfilter_init(void);

/********* Module methods *************/
// init module
static int __init ax8netfilter_init(void)
{
	int ret = -1;
	//struct sk_buff aaa;
	//long a;


	//a = ((long)&aaa.nfct) - ((long)&aaa.cb);

	printk(KERN_INFO AX_MODULE_NAME ": module " AX_MODULE_VER " for " DEVICE_NAME " device loaded\n");


	//printk(KERN_INFO AX_MODULE_NAME ": place of nfct %d!!!\n", (int)a);

	// our 'GetProcAddress' :D
	kallsyms_lookup_name_ax = (void*) OFS_KALLSYMS_LOOKUP_NAME;

	if(!hijack_functions(1))
		goto eof;

	if(!hijack_fields(1))
		goto eof;

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
	
	hijack_fields(0);
	hijack_functions(0);


	eof:
	return ret;
}

module_init(ax8netfilter_init);

MODULE_AUTHOR("AnDyX@xda-developers.com");
MODULE_DESCRIPTION("Netfilter module for " DEVICE_NAME );
MODULE_LICENSE("GPL");
