/*
 *	Linux NET3:	Internet Gateway Management Protocol  [IGMP]
 *
 *	Authors:
 *		Alan Cox <Alan.Cox@linux.org>	
 *
 *	WARNING:
 *		This is a 'preliminary' implementation... on your own head
 *	be it.
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */
 
 
#include <asm/segment.h>
#include <asm/system.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/config.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include "ip.h"
#include "protocol.h"
#include "route.h"
#include <linux/skbuff.h>
#include "sock.h"
#include <linux/igmp.h>

#ifdef CONFIG_IP_MULTICAST


/*
 *	Timer management
 */
 
/*当一个主机首次发送IGMP报告（当第一个进程加入一个多
 * 播组）时，并不保证该报告被可靠接收（因为使用的是IP交付服务）。下一个报告将在间隔
 * 一段时间后发送。这个时间间隔由主机在0-10秒的范围内随机选择。其次，当一个主机收到
 * 一个从路由器发出的查询后，并不立即响应，而是经过一定的时间间隔后才发出一些响应。
 * 因为多播路由器并不关心有多少主机属于该组，而只关心该组是否还至少拥有一个主机。
 * 这意味着如果一个主机在等待发送报告的过程中，却收到了发自其他主机的相同报告，则该
 * 主机的响应就可以不必发送了。igmp_stop_timer函数被两个函数调用：igmp_timer_expire，
 * igmp_heard_report。igmp_heard_report函数在接收到同组其他主机发送的IGMP报告报文时
 * 被调用，依据以上的设计思想，此时可以不发送报文。所以停止定时器。igmp_timer_expire
 * 则表示定时器正常到期，此时发送一个IGMP报告报文，在发送报告报文的同时，也停止定时
 * 器。本版本并未实现IGMP报告报文的主动通知，而是响应一个IGMP查询报文时，才发送IGMP
 * 报告报文，在发送时，如上所述，将延迟一段0-10秒的随机时间，如果在这段时间内接收到
 * 相同子网内其他主机的IGMP报告报文，则中断定时器延迟，取消发送。否则定时器正常到期，
 * 发送一个IGMP报告报文，这通常是延迟时间最短的主机发送的第一个IGMP报告报文
 *
 * */ 
static void igmp_stop_timer(struct ip_mc_list *im)
{
	del_timer(&im->timer);
	im->tm_running=0;
}

static int random(void)
{
	static unsigned long seed=152L;
	seed=seed*69069L+1;
	return seed^jiffies;
}

/*
 * igmp_start_timer函数被igmp_heard_query函数调用，当接收到路由器发送的IGMP查询报文
 * 时，设置一个0-10秒内随机延迟时间的定时器，在定时器到期后，发送一个IMGP报告报文。
 * 注意这个定时器是作为ip_mc_list结构中一个字段存在的。这个定时器的初始化是在
 * igmp_init_timer函数中完成的
 * */
static void igmp_start_timer(struct ip_mc_list *im)
{
	int tv;
	if(im->tm_running)
		return;
	tv=random()%(10*HZ);		/* Pick a number any number 8) */
	im->timer.expires=tv;
	im->tm_running=1;
	add_timer(&im->timer);
}
 
/*
 *	Send an IGMP report.
 *	igmp_send_report函数完成发送一个IMGP报告报文的功能。经过本书前文中对TCP，UDP，ICMP
 *	等协议的介绍，相信读者对于发送一个数据包时所需要进行的工作进行很了解了：主要是完
 *	成对各协议首部的创建。用户数据的封装简单的说就是将数据从用户缓冲区复制到指定的内
 *	核缓冲区中。虽然如同ICMP协议一样，一般我们也将IGMP协议认为是网络层协议，但实现上
 *	IGMP报文中传输是封装在IP报文之中的，所以协议首部的创建包括MAC，IP，IGMP首部。对
 *	于MAC, IP首部通过ip_build_header函数完成（这个函数在介绍ICMP，TCP，UDP协议时已经
 *	多次遇到），所以创建首部的工作主要针对IGMP首部。由于IGMP首部格式简单，长度固定，
 *	所以这个工作一目了然。值得注意的是在调用ip_build_header函数传入的多播IP地址（多
 *	播MAC地址根据多播IP地址构建)
 */

#define MAX_IGMP_SIZE (sizeof(struct igmphdr)+sizeof(struct iphdr)+64)

static void igmp_send_report(struct device *dev, unsigned long address, int type)
{
	struct sk_buff *skb=alloc_skb(MAX_IGMP_SIZE, GFP_ATOMIC);
	int tmp;
	struct igmphdr *igh;
	
	if(skb==NULL)
		return;
	tmp=ip_build_header(skb, INADDR_ANY, address, &dev, IPPROTO_IGMP, NULL,
				skb->mem_len, 0, 1);
	if(tmp<0)
	{
		kfree_skb(skb, FREE_WRITE);
		return;
	}
	igh=(struct igmphdr *)(skb->data+tmp);
	skb->len=tmp+sizeof(*igh);
	igh->csum=0;
	igh->unused=0;
	igh->type=type;
	igh->group=address;
	igh->csum=ip_compute_csum((void *)igh,sizeof(*igh));
	ip_queue_xmit(NULL,dev,skb,1);
}


static void igmp_timer_expire(unsigned long data)
{
	struct ip_mc_list *im=(struct ip_mc_list *)data;
	igmp_stop_timer(im);
	igmp_send_report(im->interface, im->multiaddr, IGMP_HOST_MEMBERSHIP_REPORT);
}

static void igmp_init_timer(struct ip_mc_list *im)
{
	im->tm_running=0;
	init_timer(&im->timer);
	im->timer.data=(unsigned long)im;
	im->timer.function=&igmp_timer_expire;
}
	


/*
 *igmp_heard_report函数以及igmp_heard_query函数顾名思义是在分别接收到IGMP报告报文
 和IGMP查询报文时被调用。对于IGMP报告报文的情况，由于路由器并不关心哪台主机加入到
 那个多播组，而只关心是否有主机在某个多播组中，所以对于一个加入某个多播组的主机而
 言，如果其他主机已经发送这个多播组的报告报文，那么本机就不需要再发送这样的报告报
 文，igmp_heard_report函数完成的工作即是如此，但接收到一个有其他主机发送的IGMP报
 告报文时，其检查本机中是否也设置了发送针对同一多播组的IGMP报告报文定时器，如果有，
 则停止该定时器。注意函数实现中是对多播IP地址的检查，是对device结构中ip_mc_list
 指向的多播IP地址列表的遍历。对于IGMP查询报文，如果本机有任何加入除了全主机多播组
 之外的其他多播组，则必须将此多播组报告给路由器，此时设置一个定时器，在延迟0-10秒
 的随机时间后，发送这样一个报告报文，igmp_heared_query函数完成的工作即如此。对
 于全主机多播组是无须进行报告的，因为默认的凡是支持多播的主机，默认的都要进入该多
 播组
 * */
static void igmp_heard_report(struct device *dev, unsigned long address)
{
	struct ip_mc_list *im;
	for(im=dev->ip_mc_list;im!=NULL;im=im->next)
		if(im->multiaddr==address)
			igmp_stop_timer(im);
}

static void igmp_heard_query(struct device *dev)
{
	struct ip_mc_list *im;
	for(im=dev->ip_mc_list;im!=NULL;im=im->next)
		if(!im->tm_running && im->multiaddr!=IGMP_ALL_HOSTS)
			igmp_start_timer(im);
}

/*
 *	Map a multicast IP onto multicast MAC for type ethernet.
 *	ip_mc_map函数完成多播IP地址到多播MAC地址之间的映射。参数addr表示多播IP地址，由此
 *	映射而成的MAC地址被填充到buf参数中而返回。
 */
 
static void ip_mc_map(unsigned long addr, char *buf)
{
	addr=ntohl(addr);
	buf[0]=0x01;
	buf[1]=0x00;
	buf[2]=0x5e;
	buf[5]=addr&0xFF;
	addr>>=8;
	buf[4]=addr&0xFF;
	addr>>=8;
	buf[3]=addr&0x7F;
}

/*
 *	Add a filter to a device
 *	到对于多播地址的维护是分为三个不同方面进
 *	行的。设备本身维护MAC地址列表，因为对于一个具体的网络设备而言，其对于数据报接受
 *	与否的判断根据相关寄存器设置的情况而定，对于多播的支持，一般是对MAC地址位做异或
 *	之类的计算后通过设置寄存器相关位完成。总之，对于网络接收设备而言，无法直接使用多
 *	播IP地址，必须将多播IP地址转换为MAC地址后方可为网络设备所使用，从而完成第一道多
 *	播数据报的过滤防线。ip_mc_filter_add和ip_mc_filter_del函数即完成从相应IP多播地址
 *	到MAC地址的添加和删除工作。当新添加一个IP多播地址时，需要调用ip_mc_filter_add函
 *	数将该多播地址转换为MAC地址，并重新设置网络设备硬件寄存器，从而加入对此类多播数
 *	据报的接收。当删除一个多播地址时，ip_mc_filter_del函数被调用，重新设置网络设备，
 *	过滤掉对应多播数据报的接收。这两个函数实现上首先调用ip_mc_map函数完成从多播IP地
 *	址到MAC的映射，然后以此MAC地址调用相关函数对设备本身的多播MAC地址列表进行操作，
 *	并同时重新设置硬件寄存器（要使新的操作有效，一般还需要从软件上重启网络设备）。此
 *	处相关函数dev_mc_add, dev_mc_delete函数定义在dev_mcast.c中
 */
 
void ip_mc_filter_add(struct device *dev, unsigned long addr)
{
	char buf[6];
	if(dev->type!=ARPHRD_ETHER)
		return;	/* Only do ethernet now */
	ip_mc_map(addr,buf);	
	dev_mc_add(dev,buf,ETH_ALEN,0);
}

/*
 *	Remove a filter from a device
 */
 
void ip_mc_filter_del(struct device *dev, unsigned long addr)
{
	char buf[6];
	if(dev->type!=ARPHRD_ETHER)
		return;	/* Only do ethernet now */
	ip_mc_map(addr,buf);	
	dev_mc_delete(dev,buf,ETH_ALEN,0);
}


/*
 *igmp_group_added和igmp_group_dropped函数即负责多播组地址添加和删除。首先一个新添
 加的多播组有ip_mc_list结构表示，对于组添加的情况，我们需要对表示这个组的
 ip_mc_list结构中相关字段进行初始化，最主要的就是对定时器的初始化工作，
 igmp_init_timer函数上文中已经介绍，该函数将定时器到期执行函数设置为
 igmp_timer_expire，igmp_timer_expire函数负责发送一个IGMP报告报文。无论是新添加一
 个组，还是退出一个组，此处都立刻发送一个IGMP报告报文，通知路由器相关变化。在前文
 对IGMP协议的介绍中，我们提到对于新加入的一个组的情况，我们一般需要发送一个IGMP
 报告报文，而对于退出一个组，则无须发送IGMP报告报文，路由器在发送IGMP查询报文后如
 果没有收到对应组的报告报文，自然会删除对该IP多播组的维护。但是此处在退出一个组后，
 调用了igmp_send_report立刻发送一个IGMP报告报文，这也并非错误。二者都可。
 函数最后各自调用ip_mc_filter_del和ip_mc_filter_add函数更改设备MAC多播地址列表反
 映新的变化。最后需要提及的是，igmp_group_added和igmp_group_dropped函数实现上虽然
 负责加入和退出一个组的工作，但这两个函数并非是在上层加入和退出一个组时，直接被调
 用的函数，因为从实现中可以看出这两个函数只涉及到设备维护的MAC地址列表的操作（通
 过对ip_mc_filter_del和ip_mc_filter_add函数的调用），但并没有涉及驱动程序和套接字
 维护的多播IP地址的操作，所以他们只是作为一个多播组被添加和删除时的一部分实现，换
 句话说，还有更上层的函数调用它们
 * */
static void igmp_group_dropped(struct ip_mc_list *im)
{
	del_timer(&im->timer);
	igmp_send_report(im->interface, im->multiaddr, IGMP_HOST_LEAVE_MESSAGE);
	ip_mc_filter_del(im->interface, im->multiaddr);
/*	printk("Left group %lX\n",im->multiaddr);*/
}

static void igmp_group_added(struct ip_mc_list *im)
{
	igmp_init_timer(im);
	igmp_send_report(im->interface, im->multiaddr, IGMP_HOST_MEMBERSHIP_REPORT);
	ip_mc_filter_add(im->interface, im->multiaddr);
/*	printk("Joined group %lX\n",im->multiaddr);*/
}

int igmp_rcv(struct sk_buff *skb, struct device *dev, struct options *opt,
	unsigned long daddr, unsigned short len, unsigned long saddr, int redo,
	struct inet_protocol *protocol)
{
	/* This basically follows the spec line by line -- see RFC1112 */
	struct igmphdr *igh=(struct igmphdr *)skb->h.raw;
	
	/*对TTL字段的检查，对于多播数据报，TTL值必须设置为1*/
	if(skb->ip_hdr->ttl!=1 || ip_compute_csum((void *)igh,sizeof(*igh)))
	{
		kfree_skb(skb, FREE_READ);
		return 0;
	}
	
	if(igh->type==IGMP_HOST_MEMBERSHIP_QUERY && daddr==IGMP_ALL_HOSTS)
		igmp_heard_query(dev);
	if(igh->type==IGMP_HOST_MEMBERSHIP_REPORT && daddr==igh->group)
		igmp_heard_report(dev,igh->group);
	kfree_skb(skb, FREE_READ);
	return 0;
}

/*
 *	Multicast list managers
 */
 
 
/*
 *	A socket has joined a multicast group on device dev.
 *	们刚刚介绍igmp_group_dropped, igmp_group_added函数并指出这两个函数被更上层的
 *	函数调用完成多播组的加入和退出工作。“更上层”这个词有些不准确，从前文中涉及内核
 *	对多播支持的三个方面来看，应该说，igmp_group_dropped, igmp_group_added函数负责了
 *	网络设备维护的MAC多播地址列表，而驱动程序IP多播地址列表以及套接字对应的多播地址
 *	列表并未涉及，这就表明还有其他函数负责这些列表的维护。对于驱动程序IP多播地址列表
 *	的维护即由如下ip_mc_inc_group和ip_mc_dec_group函数负责
 */
  
static void ip_mc_inc_group(struct device *dev, unsigned long addr)
{
	struct ip_mc_list *i;
	for(i=dev->ip_mc_list;i!=NULL;i=i->next)
	{
		if(i->multiaddr==addr)
		{
			i->users++;
			return;
		}
	}
	i=(struct ip_mc_list *)kmalloc(sizeof(*i), GFP_KERNEL);
	if(!i)
		return;
	i->users=1;
	i->interface=dev;
	i->multiaddr=addr;
	i->next=dev->ip_mc_list;
	igmp_group_added(i);
	dev->ip_mc_list=i;
}

/*
 *	A socket has left a multicast group on device dev
 */
	
static void ip_mc_dec_group(struct device *dev, unsigned long addr)
{
	struct ip_mc_list **i;
	for(i=&(dev->ip_mc_list);(*i)!=NULL;i=&(*i)->next)
	{
		if((*i)->multiaddr==addr)
		{
			if(--((*i)->users))
				return;
			else
			{
				struct ip_mc_list *tmp= *i;
				igmp_group_dropped(tmp);
				*i=(*i)->next;
				kfree_s(tmp,sizeof(*tmp));
			}
		}
	}
}

/*
 *	Device going down: Clean up.
 *	ip_mc_drop_device函数处理一个网络设备停止工作的情况，此时需要释放用于维护多播地
 *	址的内存空间，不过这个函数仅仅释放了对应驱动程序的IP多播地址列表，没有释放对应网
 *	络设备MAC多播地址列表，对此我们可以这样理解：对应套接字的多播地址列表在套接字关
 *	闭时会自行得到处理，对应网络设备的多播地址列表网络设备本身（即device结构被释放时）
 *	也会得到处理；对应驱动程序多播地址列表原则上讲这个列表应该完全有驱动程序本身负
 *	责，对于网络设备应该不可见，为了降低驱动程序复杂性或者是内核对多播处理的一致性，
 *	这个对应驱动程序的多播地址列表现在放在了device结构中，用个简单的例子就是，一个我
 *	朋友的不属于我的东西寄存在我这儿，现在我要走了，我自己的东西当然我自己会处理好（我
 *	自己带走），但这个寄存的朋友的东西我不能带走，在离开之前，我就必须处理掉。此处的
 *	思想类似如此
 */
 
void ip_mc_drop_device(struct device *dev)
{
	struct ip_mc_list *i;
	struct ip_mc_list *j;
	for(i=dev->ip_mc_list;i!=NULL;i=j)
	{
		j=i->next;
		kfree_s(i,sizeof(*i));
	}
	dev->ip_mc_list=NULL;
}

/*
 *	Device going up. Make sure it is in all hosts
 *	ip_mc_allhost函数在接口启动工作时被调用，用于自动添加全多播组地址（224.0.0.1）。
 *	IGMP_ALL_HOSTS常量定义为224.0.0.1，注意这个多播组地址不与任何套接字绑定，
 *	所以此处只对涉及到驱动程序多播地址列表和网络设备多播地址列表，没有套接字多播地址
 *	列表的操作
 */
 
void ip_mc_allhost(struct device *dev)
{
	struct ip_mc_list *i;
	for(i=dev->ip_mc_list;i!=NULL;i=i->next)
		if(i->multiaddr==IGMP_ALL_HOSTS)
			return;
	i=(struct ip_mc_list *)kmalloc(sizeof(*i), GFP_KERNEL);
	if(!i)
		return;
	i->users=1;
	i->interface=dev;
	i->multiaddr=IGMP_ALL_HOSTS;
	i->next=dev->ip_mc_list;
	dev->ip_mc_list=i;
	ip_mc_filter_add(i->interface, i->multiaddr);

}	
 
/*
 *	Join a socket to a group
 *	如前文所述，驱动程序使用ip_mc_list结构表示IP多播地址，ip_mc_inc_group和
 *	ip_mc_dec_group函数即完成对一个表示新多播地址对应的ip_mc_list结构的创建工作，当
 *	然首先我们必须检查当前地址列表中是否已经有这样一个相同的组地址存在，如果存在，则
 *	简单增加用户使用计数即可。因为驱动程序在这方面如同路由器一样，并不关心究竟有多少
 *	上层套接字加入了这个多播组，维护用户计数的首要目的是防止该ip_mc_list结构被提前释
 *	放，从而造成非法内存访问之类的系统错误。驱动程序维护的多播地址列表有device结构
 *	ip_mc_list字段指向，如果当前没有对应的多播地址，则创建一个新的ip_mc_list结构，并
 *	加入到由device结构ip_mc_list字段(注意此处不要混淆，device结构中对驱动程序维护的
 *	IP地址列表的指针名称正好与表示一个多播地址的结构名称相同)指向的地址列表中,为了
 *	增加软件处理效率，这个新的ip_mc_list结构被加入到列表的首部。在完成对应驱动程序的
 *	IP多播地址列表的操作后，各自调用igmp_group_added和igmp_group_dropped函数完成对应
 *	设备的MAC多播地址列表的操作。那么对于一个多播（组）地址的加入和退出现在只剩下对
 *	应套接字多播地址列表的操作了，这个操作定义在ip_mc_join_group和ip_mc_leave_group
 *	函数中
 */
 
int ip_mc_join_group(struct sock *sk , struct device *dev, unsigned long addr)
{
	int unused= -1;
	int i;
	if(!MULTICAST(addr))
		return -EINVAL;
	if(!(dev->flags&IFF_MULTICAST))
		return -EADDRNOTAVAIL;
	if(sk->ip_mc_list==NULL)
	{
		if((sk->ip_mc_list=(struct ip_mc_socklist *)kmalloc(sizeof(*sk->ip_mc_list), GFP_KERNEL))==NULL)
			return -ENOMEM;
		memset(sk->ip_mc_list,'\0',sizeof(*sk->ip_mc_list));
	}
	for(i=0;i<IP_MAX_MEMBERSHIPS;i++)
	{
		if(sk->ip_mc_list->multiaddr[i]==addr && sk->ip_mc_list->multidev[i]==dev)
			return -EADDRINUSE;
		if(sk->ip_mc_list->multidev[i]==NULL)
			unused=i;
	}
	
	if(unused==-1)
		return -ENOBUFS;
	sk->ip_mc_list->multiaddr[unused]=addr;
	sk->ip_mc_list->multidev[unused]=dev;
	ip_mc_inc_group(dev,addr);
	return 0;
}

/*
 *	Ask a socket to leave a group.
 */
 
int ip_mc_leave_group(struct sock *sk, struct device *dev, unsigned long addr)
{
	int i;
	if(!MULTICAST(addr))
		return -EINVAL;
	if(!(dev->flags&IFF_MULTICAST))
		return -EADDRNOTAVAIL;
	if(sk->ip_mc_list==NULL)
		return -EADDRNOTAVAIL;
		
	for(i=0;i<IP_MAX_MEMBERSHIPS;i++)
	{
		if(sk->ip_mc_list->multiaddr[i]==addr && sk->ip_mc_list->multidev[i]==dev)
		{
			sk->ip_mc_list->multidev[i]=NULL;
			ip_mc_dec_group(dev,addr);
			return 0;
		}
	}
	return -EADDRNOTAVAIL;
}

/*
 *	A socket is closing.
 *	ip_mc_drop_socket函数处理一个使用多播的套接字被关闭时对多播地址列表的处理。492
 *	行检查该套接字是否使用了多播，如果没有，则直接返回。否则遍历套接字对应多播地址列
 *	表，对每个多播地址对应的各层结构进行释放
 */
 
void ip_mc_drop_socket(struct sock *sk)
{
	int i;
	
	if(sk->ip_mc_list==NULL)
		return;
		
	for(i=0;i<IP_MAX_MEMBERSHIPS;i++)
	{
		if(sk->ip_mc_list->multidev[i])
		{
			ip_mc_dec_group(sk->ip_mc_list->multidev[i], sk->ip_mc_list->multiaddr[i]);
			sk->ip_mc_list->multidev[i]=NULL;
		}
	}
	kfree_s(sk->ip_mc_list,sizeof(*sk->ip_mc_list));
	sk->ip_mc_list=NULL;
}

#endif
