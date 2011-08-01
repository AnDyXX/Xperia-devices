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

//extern struct net_protocol *** ax8netfilter_inet_protos;
extern struct net_protocol ** ax8netfilter_inet_protos ____cacheline_aligned_in_smp;  

typedef void (*ax8netfilter_ip_forward_options_type)(struct sk_buff *skb);
extern ax8netfilter_ip_forward_options_type ax8netfilter_ip_forward_options;

typedef void	(*ax8netfilter_ip_rt_send_redirect_type)(struct sk_buff *skb);
extern ax8netfilter_ip_rt_send_redirect_type ax8netfilter_ip_rt_send_redirect;

typedef int (*ax8netfilter_ip_call_ra_chain_type)(struct sk_buff *skb);
extern ax8netfilter_ip_call_ra_chain_type ax8netfilter_ip_call_ra_chain;

typedef int (*ax8netfilter_raw_local_deliver_type)(struct sk_buff *, int);
extern ax8netfilter_raw_local_deliver_type ax8netfilter_raw_local_deliver;

typedef void (*ax8netfilter_ip_options_fragment_type)(struct sk_buff *skb);
extern ax8netfilter_ip_options_fragment_type ax8netfilter_ip_options_fragment;

typedef int (*ax8netfilter_ip_options_get_from_user_type)(struct net *net, struct ip_options **optp,
				    unsigned char __user *data, int optlen);
extern ax8netfilter_ip_options_get_from_user_type ax8netfilter_ip_options_get_from_user;

typedef int (*ax8netfilter_ip_mc_leave_group_type)(struct sock *sk, struct ip_mreqn *imr);
extern ax8netfilter_ip_mc_leave_group_type ax8netfilter_ip_mc_leave_group;

typedef int (*ax8netfilter_ip_mc_msfilter_type)(struct sock *sk, struct ip_msfilter *msf,int ifindex);
extern ax8netfilter_ip_mc_msfilter_type ax8netfilter_ip_mc_msfilter;

typedef int (*ax8netfilter_ip_mc_source_type)(int add, int omode, struct sock *sk,
		struct ip_mreq_source *mreqs, int ifindex);
extern ax8netfilter_ip_mc_source_type ax8netfilter_ip_mc_source;

typedef int (*ax8netfilter_ip_ra_control_type)(struct sock *sk, unsigned char on, void (*destructor)(struct sock *));
extern ax8netfilter_ip_ra_control_type ax8netfilter_ip_ra_control;

typedef void (*ax8netfilter_ip_options_undo_type)(struct ip_options * opt);
extern ax8netfilter_ip_options_undo_type ax8netfilter_ip_options_undo;

typedef int (*ax8netfilter_ip_mc_msfget_type)(struct sock *sk, struct ip_msfilter *msf,
		struct ip_msfilter __user *optval, int __user *optlen);
extern ax8netfilter_ip_mc_msfget_type ax8netfilter_ip_mc_msfget;

typedef int (*ax8netfilter_ip_mc_gsfget_type)(struct sock *sk, struct group_filter *gsf,
		struct group_filter __user *optval, int __user *optlen);
extern ax8netfilter_ip_mc_gsfget_type ax8netfilter_ip_mc_gsfget;

extern int * ax8netfilter_sysctl_ip_default_ttl;

typedef void	(*ax8netfilter_ip_local_error_type)(struct sock *sk, int err, __be32 daddr, __be16 dport,
			       u32 info);
extern ax8netfilter_ip_local_error_type ax8netfilter_ip_local_error;

typedef void	(*ax8netfilter_icmp_out_count_type)(struct net *net, unsigned char type);
extern ax8netfilter_icmp_out_count_type ax8netfilter_icmp_out_count;

typedef int	(*ax8netfilter_ip_cmsg_send_type)(struct net *net,
			     struct msghdr *msg, struct ipcm_cookie *ipc);
extern ax8netfilter_ip_cmsg_send_type ax8netfilter_ip_cmsg_send;

typedef int	(*ax8netfilter_ip_append_data_type)(struct sock *sk,
				       int getfrag(void *from, char *to, int offset, int len,
						   int odd, struct sk_buff *skb),
				void *from, int len, int protolen,
				struct ipcm_cookie *ipc,
				struct rtable **rt,
				unsigned int flags);
extern ax8netfilter_ip_append_data_type ax8netfilter_ip_append_data;

typedef int		(*ax8netfilter_ip_push_pending_frames_type)(struct sock *sk);
extern ax8netfilter_ip_push_pending_frames_type ax8netfilter_ip_push_pending_frames;

typedef void		(*ax8netfilter_ip_flush_pending_frames_type)(struct sock *sk);
extern ax8netfilter_ip_flush_pending_frames_type ax8netfilter_ip_flush_pending_frames;

typedef void (*ax8netfilter_xfrm_replay_notify_type)(struct xfrm_state *x, int event);
extern ax8netfilter_xfrm_replay_notify_type ax8netfilter_xfrm_replay_notify;

extern int * ax8netfilter_sysctl_igmp_max_msf;

int ax8netfilter_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);

typedef int (*ax8netfilter_ip_options_compile_type)(struct net *net,
			      struct ip_options *opt, struct sk_buff *skb);

extern ax8netfilter_ip_options_compile_type ax8netfilter_ip_options_compile;

typedef int (*ax8netfilter_ip_options_rcv_srr_type)(struct sk_buff *skb);
extern ax8netfilter_ip_options_rcv_srr_type ax8netfilter_ip_options_rcv_srr;

#endif
