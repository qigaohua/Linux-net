#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>

#define   MUL_ADDR  "224.0.0.100"
#define   MUL_PORT  8888
#define   WAIT_TIME 5


int main(int argc, char **argv)
{
	int s;
	struct sockaddr_in caddr;
	struct ip_mreq mreq;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("socket error");
		exit(-1);
	}

	memset(&caddr, 0, sizeof(caddr));
	caddr.sin_family = AF_INET;
	caddr.sin_addr.s_addr = htonl(INADDR_ANY);
	caddr.sin_port = htons(MUL_PORT);

	if ((bind(s, (struct sockaddr*)&caddr, sizeof(caddr))) == -1)
	{
		perror("bind error");
		exit(-1);
	}

	unsigned char ttl=255;
	setsockopt(s,IPPROTO_IP,IP_MULTICAST_TTL,&ttl,sizeof(ttl));

    /*设置回环许可*/
/*	    int loop = 1;

	   int	err = setsockopt(s,IPPROTO_IP, IP_MULTICAST_LOOP,&loop, sizeof(loop));
		if(err < 0)
		{
			perror("setsockopt():IP_MULTICAST_LOOP");
			return -3;
		}

*/
	mreq.imr_multiaddr.s_addr = inet_addr(MUL_ADDR);
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	if ((setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) < 0) 
	{
		perror("setsockopt error");
		exit(-1);
	}
	
	int times;
	int recvlen;
	char recvbuff[64];
	for (times = 0; times < 5; times++)
	{
		memset(recvbuff, 0, sizeof(recvbuff));

		recvlen = recvfrom(s, recvbuff, sizeof(recvbuff), 0, NULL, 0);
		if (recvlen < 0)
		{
			perror("recvfrom error");
			exit(-1);
		}
		
		printf("recv from server message: %s\n", recvbuff);
	}

	if ((setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq))) < 0) 
	{
		perror("setsockopt error");
		exit(-1);
	}

	close(s);
	return 0;
}
