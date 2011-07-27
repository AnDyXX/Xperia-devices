#ifndef __AX8NETFILTER_H__
#define __AX8NETFILTER_H__

#include <linux/inetdevice.h>
#include <net/inet_sock.h>

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


//from ipv4_ip_output.c
int ax8netfilter___ip_local_out(struct sk_buff *skb);
int ax8netfilter_ip_local_out(struct sk_buff *skb);
int ax8netfilter_ip_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
			  __be32 saddr, __be32 daddr, struct ip_options *opt);
int ax8netfilter_ip_finish_output(struct sk_buff *skb);

#endif
