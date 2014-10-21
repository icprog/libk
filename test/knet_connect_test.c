#include <stdio.h>
#include "../src/k.h"
#ifdef _WIN32
#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif

#define MAX_FD	8000

int
main()
{
	int i = 0;
	int c = 0;
	char ip[16] = "";
	int port = 0;
	int fds[MAX_FD] = {0};
	scanf("%s", ip);
	scanf("%d", &port);
	getchar();
	ksock_init();
	for (i = 0; i < MAX_FD; ++i)
	{
		int fd = ksock_init_fd();
		if (0 == ksock_connect(fd, ip, port))
		{
			printf("%d\n", i);
		}
		else
		{
			k_sleep(500);
		}
		fds[i] = fd;
		k_sleep(10);
	}
	getchar();
	for(i = 0; i < MAX_FD; ++i)
	{
		ksock_close(fds[i]);
		k_sleep(10);
	}
	getchar();
	return 0;
}
