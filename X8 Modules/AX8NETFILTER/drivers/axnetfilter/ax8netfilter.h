#ifndef __AX8NETFILTER_H__
#define __AX8NETFILTER_H__

#include <linux/inetdevice.h>
#include <net/inet_sock.h>
#include <net/ip.h>
#include <net/protocol.h>

extern const __u8 ax8netfilter_ip_tos2prio[16];

static inline char ax8netfilter_rt_tos2priority(u8 tos)
{
	return ax8netfilter_ip_tos2prio[IPTOS_TOS(tos)>>1];
}

void ax8netfilter_skb_release_head_state(struct sk_buff *skb);
void ax8netfilter___copy_skb_header(struct sk_buff *new, const struct sk_buff *old);

void ax8netfilter_arp_xmit(struct sk_buff *skb);
int ax8netfilter_arp_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt, struct net_device *orig_dev);
typedef int (*ax8netfilter_arp_processtype)(struct sk_buff *skb);
extern ax8netfilter_arp_processtype ax8netfilter_arp_process;


int ax8netfilter_ip_forward(struct sk_buff *skb);


int ax8netfilter_ip_local_deliver(struct sk_buff *skb);

int ax8netfilter___ip_local_out(struct sk_buff *skb);

typedef int (*ax8netfilter_ip_finish_output2_type)(struct sk_buff *skb);
extern ax8netfilter_ip_finish_output2_type ax8netfilter_ip_finish_output2;

int ax8netfilter_ip_mc_output(struct sk_buff *skb);
int ax8netfilter_ip_output(struct sk_buff *skb);
int ax8netfilter_ip_fragment(struct sk_buff *skb, int (*output)(struct sk_buff *));


int ax8netfilter_ip_setsockopt(struct sock *sk, int level,
		int optname, char __user *optval, int optlen);
int ax8netfilter_ip_getsockopt(struct sock *sk, int level,
		  int optname, char __user *optval, int __user *optlen);


int ax8netfilter_raw_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		       size_t len);
int ax8netfilter_raw_rcv(struct sock *sk, struct sk_buff *skb);

int ax8netfilter_xfrm4_transport_finish(struct sk_buff *skb, int async);

typedef int (*ax8netfilter_xfrm_output_type)(struct sk_buff *skb);
extern ax8netfilter_xfrm_output_type ax8netfilter_xfrm_output;


int ax8netfilter_xfrm_output_resume(struct sk_buff *skb, int err);
typedef int (*ax8netfilter_xfrm_output2_type)(struct sk_buff *skb);
extern ax8netfilter_xfrm_output2_type ax8netfilter_xfrm_output2;

extern struct net_protocol ** ax8netfilter_inet_protos;

typedef ip_forward_options(struct sk_buff *skb);

#endif
