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
#define   MUL_PORT   8888
#define   WAIT_TIME 5

const char buf[64] = "this is test";
int main(int argc, char **argv)
{
	int s;
	struct sockaddr_in saddr;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (-1 == s) {
		perror("socket error");
		exit(-1);
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = inet_addr(MUL_ADDR);
	saddr.sin_port = htons(MUL_PORT);

	while (1)
	{
		int n;
		n = sendto(s, buf, strlen(buf), 0, (struct sockaddr*)&saddr, sizeof(saddr));
		if (n < 0) {
			perror("sendto error");
			exit(-1);
		}

		sleep(WAIT_TIME);
	}

	close(s);
	return 0;
}

