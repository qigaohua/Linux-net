/*
 *	Linux NET3:	Multicast List maintenance. 
 *
 *	Authors:
 *		Tim Kordas <tjk@nostromo.eeap.cwru.edu> 
 *		Richard Underwood <richard@wuzz.demon.co.uk>
 *
 *	Stir fried together from the IP multicast and CAP patches above
 *		Alan Cox <Alan.Cox@linux.org>	
 *
 *	Fixes:
 *		Alan Cox	:	Update the device on a real delete
 *					rather than any time but...
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */
 
#include <asm/segment.h>
#include <asm/system.h>
#include <asm/bitops.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include "ip.h"
#include "route.h"
#include <linux/skbuff.h>
#include "sock.h"
#include "arp.h"


/*
 *	Device multicast list maintenance. This knows about such little matters as promiscuous mode and
 *	converting from the list to the array the drivers use. At least until I fix the drivers up.
 *
 *	This is used both by IP and by the user level maintenance functions. Unlike BSD we maintain a usage count
 *	on a given multicast address so that a casual user application can add/delete multicasts used by protocols
 *	without doing damage to the protocols when it deletes the entries. It also helps IP as it tracks overlapping
 *	maps.
 */
 

/*
 *	Update the multicast list into the physical NIC controller.
 */
 
void dev_mc_upload(struct device *dev)
{
	struct dev_mc_list *dmi;
	char *data, *tmp;

	/* Don't do anything till we up the interface
	   [dev_open will call this function so the list will
	    stay sane] */
	    
	if(!(dev->flags&IFF_UP))
		return;
		
		
	/* Devices with no set multicast don't get set */
	/*
	 *如果驱动程序没有提供相应的多播地址设置函数，则简单返回，因为这个新的多播地址设置
	 生效必须由驱动程序配合才能实现，如果驱动程序没有提供这个功能，那么从底层上就不支
	 持多播地址的变动性。
	 * */
	if(dev->set_multicast_list==NULL)
		return;
	/* Promiscuous is promiscuous - so no filter needed 
	 *对于混杂模式，网络设备接受所有的数据包，无需进行数据包过滤设置。
	 * */
	if(dev->flags&IFF_PROMISC)
	{
		dev->set_multicast_list(dev, -1, NULL);
		return;
	}
	
	/*
	 device结构中set_multicast_list指针指向的函数第二个参数表示多播地址个数，第三个参
	 数表示具体的多播地址，这些地址紧密排列，set_multicast_list指向的函数将根据第二个
	 参数指定的多播地址的个数，依次对第三个参数指向的地址列表进行处理。如果第二个参数
	 为0，则表示当前不使用多播，换句话说，网络设备将被设置成为丢弃所有多播数据包（根
	 本不对多播数据包进行接收）
	 * */
	if(dev->mc_count==0)
	{
		dev->set_multicast_list(dev,0,NULL);
		return;
	}
	
	data=kmalloc(dev->mc_count*dev->addr_len, GFP_KERNEL);
	if(data==NULL)
	{
		printk("Unable to get memory to set multicast list on %s\n",dev->name);
		return;
	}
	/*成对新的多播列表的处理，代码实现很简单，因为复杂的工作都被屏蔽在由
	 * set_multicast_list指向的函数中了，如上文所述，这个函数将有网络设备驱动程序提供。
	 * 实现的工作是根据具体硬件对多播地址的设置方式，对每个MAC多播地址进行硬件指定的计
	 * 算（一般计算得到一个比特位用于设置硬件寄存器中对应比特位），并配置多播相关寄存器，
	 * 完成对新的设置的响应，这个过程中需要暂时停止网络设备的工作，在配置完成后，重新启
	 * 动，从而使新的设置生效。具体的情况网络接收设备相关
	 * */
	for(tmp = data, dmi=dev->mc_list;dmi!=NULL;dmi=dmi->next)
	{
		memcpy(tmp,dmi->dmi_addr, dmi->dmi_addrlen);
		tmp+=dev->addr_len;
	}
	dev->set_multicast_list(dev,dev->mc_count,data);
	kfree(data);
}
  
/*
 *	Delete a device level multicast
 */
 
void dev_mc_delete(struct device *dev, void *addr, int alen, int all)
{
	struct dev_mc_list **dmi;
	for(dmi=&dev->mc_list;*dmi!=NULL;dmi=&(*dmi)->next)
	{
		if(memcmp((*dmi)->dmi_addr,addr,(*dmi)->dmi_addrlen)==0 && alen==(*dmi)->dmi_addrlen)
		{
			struct dev_mc_list *tmp= *dmi;
			if(--(*dmi)->dmi_users && !all)
				return;
			*dmi=(*dmi)->next;
			dev->mc_count--;
			kfree_s(tmp,sizeof(*tmp));
			dev_mc_upload(dev);
			return;
		}
	}
}

/*
 *	Add a device level multicast
 */
 
/*
 *参数dev表示对应的网络设备，addr表示MAC多播地址，alen表示MAC地址长度，newonly参数
 在调用时被简单设置为0，该参数表示的意义根据下文代码实现的意义来看，表示如果存在
 相同地址，是否增加已有地址的使用计数，还是不进行任何操作，换句话说，newonly表示
 只有加入的多播地址是一个全新的地址时，才进行响应的操作。由于dev_mc_add函数被调用
 的目的就是对新加入的多播地址进行设备层的添加，所以下面的代码主要就是操作device
 结构中mc_list字段指向多播MAC地址链表，诚如前文中对IGMP协议的说明，设备维护多播MAC
 地址列表中每个元素都是一个dev_mc_list结构
 *
 * */
void dev_mc_add(struct device *dev, void *addr, int alen, int newonly)
{
	struct dev_mc_list *dmi;
	for(dmi=dev->mc_list;dmi!=NULL;dmi=dmi->next)
	{
		if(memcmp(dmi->dmi_addr,addr,dmi->dmi_addrlen)==0 && dmi->dmi_addrlen==alen)
		{
			if(!newonly)
				dmi->dmi_users++;
			return;
		}
	}
	dmi=(struct dev_mc_list *)kmalloc(sizeof(*dmi),GFP_KERNEL);
	if(dmi==NULL)
		return;	/* GFP_KERNEL so can't happen anyway */
	memcpy(dmi->dmi_addr, addr, alen);
	dmi->dmi_addrlen=alen;
	dmi->next=dev->mc_list;
	dmi->dmi_users=1;
	dev->mc_list=dmi;
	dev->mc_count++;
	dev_mc_upload(dev);
	/*
	 * 118-126行代码对device结构中mc_list字段指向的多播地址列表进行查询，检查是否有相同
	 * 的多播地址已经加入到列表中，如果存在，则根据newonly参数的设置，决定是仅仅增加已
	 * 有地址的使用计数，还是不进行任何操作的返回。
	 * 代码执行到127行，表示这是一个全新的多播地址，此时分配一个新的dev_mc_list结构，插
	 * 入到有mc_list指向的列表首部，最后调用dev_mc_upload函数重新启动设备，从而使新加入
	 * 的多播地址生效
	 * */
}

/*
 *	Discard multicast list when a device is downed
 *	该函数完成的功能是对device结构
 *	中mc_list字段指向的列表中所有地址进行释放，这个函数在关闭一个设备时被调用，具体
 *	的是在dev_close函数（dev.c）中被调用。
 */

void dev_mc_discard(struct device *dev)
{
	while(dev->mc_list!=NULL)
	{
		struct dev_mc_list *tmp=dev->mc_list;
		dev->mc_list=dev->mc_list->next;
		kfree_s(tmp,sizeof(*tmp));
	}
	dev->mc_count=0;
}

