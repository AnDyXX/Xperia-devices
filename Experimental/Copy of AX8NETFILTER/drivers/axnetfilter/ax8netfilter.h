#ifndef __AX8NETFILTER_H__
#define __AX8NETFILTER_H__

#include <linux/inetdevice.h>
#include <net/inet_sock.h>
#include <net/ip.h>

extern struct kmem_cache ** ax8netfilter_skbuff_head_cache __read_mostly;
extern struct kmem_cache ** ax8netfilter_skbuff_fclone_cache __read_mostly;

//from skbuff.c
void ax8netfilter_skb_release_data(struct sk_buff *skb);
void ax8netfilter_skb_release_head_state(struct sk_buff *skb);
void ax8netfilter___kfree_skb(struct sk_buff *skb);
void ax8netfilter_kfree_skb(struct sk_buff *skb);
void ax8netfilter___copy_skb_header(struct sk_buff *new, const struct sk_buff *old);
struct sk_buff *ax8netfilter___skb_clone(struct sk_buff *n, struct sk_buff *skb);
struct sk_buff *ax8netfilter_skb_morph(struct sk_buff *dst, struct sk_buff *src);
struct sk_buff *ax8netfilter_skb_clone(struct sk_buff *skb, gfp_t gfp_mask);
struct sk_buff *ax8netfilter_skb_copy(const struct sk_buff *skb, gfp_t gfp_mask);
struct sk_buff *ax8netfilter_pskb_copy(struct sk_buff *skb, gfp_t gfp_mask);

//from ipv4_arp.c
int ax8netfilter_arp_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt, struct net_device *orig_dev);
void ax8netfilter_arp_solicit(struct neighbour *neigh, struct sk_buff *skb);
void ax8netfilter_arp_send(int type, int ptype, __be32 dest_ip,
	      struct net_device *dev, __be32 src_ip,
	      const unsigned char *dest_hw, const unsigned char *src_hw,
	      const unsigned char *target_hw);

//from ipv4_ip_forward.c
int ax8netfilter_ip_forward(struct sk_buff *skb);

//from ipv4_ip_input.c
int ax8netfilter_ip_call_ra_chain(struct sk_buff *skb);
int ax8netfilter_ip_local_deliver(struct sk_buff *skb);
int ax8netfilter_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);

extern struct ip_ra_chain **ax8netfilter_ip_ra_chain; 


//from ipv4_ip_output.c
int ax8netfilter___ip_local_out(struct sk_buff *skb);
int ax8netfilter_ip_local_out(struct sk_buff *skb);
int ax8netfilter_ip_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
			  __be32 saddr, __be32 daddr, struct ip_options *opt);
int ax8netfilter_ip_finish_output(struct sk_buff *skb);
int ax8netfilter_ip_mc_output(struct sk_buff *skb);
int ax8netfilter_ip_output(struct sk_buff *skb);
int ax8netfilter_ip_queue_xmit(struct sk_buff *skb, int ipfragok);
int ax8netfilter_ip_fragment(struct sk_buff *skb, int (*output)(struct sk_buff *));
int ax8netfilter_ip_append_data(struct sock *sk,
		   int getfrag(void *from, char *to, int offset, int len,
			       int odd, struct sk_buff *skb),
		   void *from, int length, int transhdrlen,
		   struct ipcm_cookie *ipc, struct rtable **rtp,
		   unsigned int flags);
ssize_t	ax8netfilter_ip_append_page(struct sock *sk, struct page *page,
		       int offset, size_t size, int flags);
int ax8netfilter_ip_push_pending_frames(struct sock *sk);
void ax8netfilter_ip_flush_pending_frames(struct sock *sk);
void ax8netfilter_ip_send_reply(struct sock *sk, struct sk_buff *skb, struct ip_reply_arg *arg,
		   unsigned int len);

//from ipv4_sockglue.c

void ax8netfilter_ip_cmsg_recv(struct msghdr *msg, struct sk_buff *skb);
int ax8netfilter_ip_cmsg_send(struct net *net, struct msghdr *msg, struct ipcm_cookie *ipc);
int ax8netfilter_ip_ra_control(struct sock *sk, unsigned char on, void (*destructor)(struct sock *));
void ax8netfilter_ip_icmp_error(struct sock *sk, struct sk_buff *skb, int err,
		   __be16 port, u32 info, u8 *payload);
void ax8netfilter_ip_local_error(struct sock *sk, int err, __be32 daddr, __be16 port, u32 info);
int ax8netfilter_ip_recv_error(struct sock *sk, struct msghdr *msg, int len);
int ax8netfilter_ip_setsockopt(struct sock *sk, int level,
		int optname, char __user *optval, int optlen);
int ax8netfilter_ip_getsockopt(struct sock *sk, int level,
		  int optname, char __user *optval, int __user *optlen);

//from ipv4_raw.c
extern struct raw_hashinfo * ax8netfilter_raw_v4_hashinfo;
int ax8netfilter_raw_rcv(struct sock *sk, struct sk_buff *skb);
int ax8netfilter_raw_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		       size_t len);
void ax8netfilter_raw_close(struct sock *sk, long timeout);
void ax8netfilter_raw_destroy(struct sock *sk);
int ax8netfilter_raw_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int ax8netfilter_raw_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		       size_t len, int noblock, int flags, int *addr_len);

//from ipv4_xfrm4_input
int ax8netfilter_xfrm4_transport_finish(struct sk_buff *skb, int async);

//from ipv4_xfrm4_output
int ax8netfilter_xfrm4_output(struct sk_buff *skb);

//from xfrm_xfrm_output.c
int ax8netfilter_xfrm_output_resume(struct sk_buff *skb, int err);
int ax8netfilter_xfrm_output(struct sk_buff *skb);

//from ipv4_igmp
void ax8netfilter_ip_mc_inc_group(struct in_device *in_dev, __be32 addr);
void ax8netfilter_ip_mc_dec_group(struct in_device *in_dev, __be32 addr);
#endif
