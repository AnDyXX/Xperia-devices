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
#include <linux/skbuff.h>
#include <net/arp.h>
#include <net/dst.h>
#include <net/inet_connection_sock.h>
#include <net/xfrm.h>


#include "ax8netfilter.h"

#define AX_MODULE_NAME 			"ax8netfilter"
#define AX_MODULE_VER			"v001b"

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
	int required;
};

static const struct cfg_value_map func_mapping_table[] = {
	{"skb_release_data", 		&ax8netfilter_skb_release_data, 	0},
	{"skb_release_head_state" , 	&ax8netfilter_skb_release_head_state, 	1},
	{"__kfree_skb", 		&ax8netfilter___kfree_skb, 		1},
	{"kfree_skb", 			&ax8netfilter_kfree_skb, 		1},
	{"__copy_skb_header", 		&ax8netfilter___copy_skb_header, 	1},
	{"__skb_clone", 		&ax8netfilter___skb_clone, 		1},
	{"skb_morph", 			&ax8netfilter_skb_morph,		0},
	{"skb_clone", 			&ax8netfilter_skb_clone,		0},
	{"skb_copy", 			&ax8netfilter_skb_copy ,		0},
	{"pskb_copy", 			&ax8netfilter_pskb_copy, 		0},

	{"arp_rcv", 			&ax8netfilter_arp_rcv,			1},
	{"arp_solicit", 		&ax8netfilter_arp_solicit,		0},	
	{"arp_send", 			&ax8netfilter_arp_send,			1},

	{"ip_forward", 			&ax8netfilter_ip_forward,		1},

	{"ip_call_ra_chain",		&ax8netfilter_ip_call_ra_chain,		0},
	{"ip_local_deliver",		&ax8netfilter_ip_local_deliver,		1},
	{"ip_rcv", 			&ax8netfilter_ip_rcv,			1},

	{"__ip_local_out",		&ax8netfilter___ip_local_out,		1},
	{"ip_local_out",		&ax8netfilter_ip_local_out,		0},
	{"ip_build_and_send_pkt",	&ax8netfilter_ip_build_and_send_pkt,	0},
	{"ip_finish_output", 		&ax8netfilter_ip_finish_output,		1},
	{"ip_mc_output",		&ax8netfilter_ip_mc_output,		1},
	{"ip_output",			&ax8netfilter_ip_output,		1},
	{"ip_queue_xmit",		&ax8netfilter_ip_queue_xmit,		1},
	{"ip_fragment",			&ax8netfilter_ip_fragment,		1},
	{"ip_append_data",		&ax8netfilter_ip_append_data,		0},	
	{"ip_append_page", 		&ax8netfilter_ip_append_page,		0},
	{"ip_push_pending_frames", 	&ax8netfilter_ip_push_pending_frames,	0},
	{"ip_flush_pending_frames",	&ax8netfilter_ip_flush_pending_frames,	0},
	{"ip_send_reply",		&ax8netfilter_ip_send_reply,		0},

	{"ip_cmsg_recv",		&ax8netfilter_ip_cmsg_recv,		0},
	{"ip_cmsg_send",		&ax8netfilter_ip_cmsg_send,		0},
	{"ip_ra_control",		&ax8netfilter_ip_ra_control,		0},
	{"ip_icmp_error",		&ax8netfilter_ip_icmp_error,		0},

	{"ip_local_error", 		&ax8netfilter_ip_local_error,		0},
	{"ip_recv_error", 		&ax8netfilter_ip_recv_error,		0},
	{"ip_setsockopt",		&ax8netfilter_ip_setsockopt,		1},
	{"ip_getsockopt",		&ax8netfilter_ip_getsockopt ,		1},

	{"raw_rcv", 			&ax8netfilter_raw_rcv,			0},
	{"raw_sendmsg",			&ax8netfilter_raw_sendmsg,		0},
	{"raw_close",			&ax8netfilter_raw_close,		0},
	{"raw_destroy",			&ax8netfilter_raw_destroy,		0},
	{"raw_bind",			&ax8netfilter_raw_bind,			0},
	{"raw_recvmsg",			&ax8netfilter_raw_recvmsg,		0},

	{"xfrm4_transport_finish",	&ax8netfilter_xfrm4_transport_finish,	1},

	{"xfrm4_output",		&ax8netfilter_xfrm4_output,		1},

	{"xfrm_output_resume",		&ax8netfilter_xfrm_output_resume,	0},
	{"xfrm_output",			&ax8netfilter_xfrm_output,		0},

	{"ip_mc_inc_group",		&ax8netfilter_ip_mc_inc_group,		0},
	{"ip_mc_dec_group",		&ax8netfilter_ip_mc_dec_group,		0},


	{NULL, 0, 0},
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
			if(!func && t->required)
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

#define PATCH_FUNC(what, name, function) if((long) what == (long)kallsyms_lookup_name_ax(name))  what = function;

void patch_xfrm(void)
{
	struct xfrm_state_afinfo * xfrm4_state_afinfo;
	xfrm4_state_afinfo = (void*) kallsyms_lookup_name_ax("xfrm4_state_afinfo");
	if(xfrm4_state_afinfo)
	{
		PATCH_FUNC(xfrm4_state_afinfo->transport_finish, 	"xfrm4_transport_finish",	ax8netfilter_xfrm4_transport_finish)
		PATCH_FUNC(xfrm4_state_afinfo->output, 			"xfrm4_output",			ax8netfilter_xfrm4_output)
	}

	printk(KERN_INFO AX_MODULE_NAME ": XFRM structs patched.\n");
}

void patch_raw(void)
{
	struct proto *raw_prot;

	raw_prot = (void*) kallsyms_lookup_name_ax("raw_prot");
	if(raw_prot)
	{
		PATCH_FUNC(raw_prot->sendmsg, 	"raw_sendmsg", 	ax8netfilter_raw_sendmsg)
		PATCH_FUNC(raw_prot->close, 	"raw_close", 	ax8netfilter_raw_close)
		PATCH_FUNC(raw_prot->destroy, 	"raw_destroy", 	ax8netfilter_raw_destroy)
		PATCH_FUNC(raw_prot->bind, 	"raw_bind", 	ax8netfilter_raw_bind)
		PATCH_FUNC(raw_prot->recvmsg, 	"raw_recvmsg", 	ax8netfilter_raw_recvmsg)
	}

	printk(KERN_INFO AX_MODULE_NAME ": RAW structs patched.\n");
}

void patch_ip(void)
{
	struct packet_type * ip_packet_type;
	struct dst_ops * ipv4_dst_ops;
	struct inet_connection_sock_af_ops *ipv4_specific;
	
	ip_packet_type = (void*) kallsyms_lookup_name_ax("ip_packet_type");
	if(ip_packet_type)
	{
		ip_packet_type->func = ax8netfilter_ip_rcv;
	}

	ipv4_dst_ops = (void*) kallsyms_lookup_name_ax("ipv4_dst_ops");
	if(ipv4_dst_ops)
	{
		ipv4_dst_ops->local_out = ax8netfilter___ip_local_out;
	}

	ipv4_specific = (void*) kallsyms_lookup_name_ax("ipv4_specific");
	if(ipv4_specific)
	{
		ipv4_specific->queue_xmit = ax8netfilter_ip_queue_xmit;
		ipv4_specific->setsockopt = ax8netfilter_ip_setsockopt;
		ipv4_specific->getsockopt = ax8netfilter_ip_getsockopt;
	}

	printk(KERN_INFO AX_MODULE_NAME ": IP structs patched.\n");
}

void patch_arp(void)
{
	struct neigh_ops * arp_neigh_ops;
	struct packet_type* arp_packet_type;
	
	arp_neigh_ops = (void*) kallsyms_lookup_name_ax("arp_generic_ops");
	if(arp_neigh_ops)
	{
		arp_neigh_ops->solicit = ax8netfilter_arp_solicit;
	}

	arp_neigh_ops = (void*) kallsyms_lookup_name_ax("arp_hh_ops");
	if(arp_neigh_ops)
	{
		arp_neigh_ops->solicit = ax8netfilter_arp_solicit;
	}

	arp_neigh_ops = (void*) kallsyms_lookup_name_ax("arp_broken_ops");
	if(arp_neigh_ops)
	{
		arp_neigh_ops->solicit = ax8netfilter_arp_solicit;
	}

	arp_packet_type = (void*) kallsyms_lookup_name_ax("arp_packet_type");
	if(arp_packet_type)
	{
		arp_packet_type->func = ax8netfilter_arp_rcv;
	}

	printk(KERN_INFO AX_MODULE_NAME ": ARP structs patched.\n");
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
	{
		goto eof;
	}

	ax8netfilter_skbuff_head_cache = (void*) kallsyms_lookup_name_ax("skbuff_head_cache");
	if(!ax8netfilter_skbuff_head_cache)
	{
		printk(KERN_INFO AX_MODULE_NAME ": skbuff_head_cache missing!!!\n");
		goto eof;
	}

	ax8netfilter_skbuff_fclone_cache = (void*) kallsyms_lookup_name_ax("skbuff_fclone_cache");
	if(!ax8netfilter_skbuff_fclone_cache)
	{
		printk(KERN_INFO AX_MODULE_NAME ": skbuff_fclone_cache missing!!!\n");
		goto eof;
	}

	ax8netfilter_raw_v4_hashinfo = (void*) kallsyms_lookup_name_ax("raw_v4_hashinfo");
	if(!ax8netfilter_raw_v4_hashinfo)
	{
		printk(KERN_INFO AX_MODULE_NAME ": raw_v4_hashinfo missing!!!\n");
		goto eof;
	}

	ax8netfilter_ip_ra_chain = (void*) kallsyms_lookup_name_ax("ip_ra_chain");
	if(!ax8netfilter_ip_ra_chain)
	{
		printk(KERN_INFO AX_MODULE_NAME ": ip_ra_chain missing!!!\n");
		goto eof;
	}

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
	
	hijack_functions(0);

	//patch_arp();
	//patch_ip();
	//patch_raw();
	//patch_xfrm();

	eof:
	return ret;
}

module_init(ax8netfilter_init);

MODULE_AUTHOR("AnDyX@xda-developers.com");
MODULE_DESCRIPTION("Netfilter module for " DEVICE_NAME );
MODULE_LICENSE("GPL");
