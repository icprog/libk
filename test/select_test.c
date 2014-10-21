#include "../src/k.h"

#ifdef _WIN32
//#pragma comment(lib, "k.lib")
#include "vld.h"
#endif

int
main()
{
	int fd = 0;
	int i = 0;
	int ret = 0;


	fd_set readfds;
	fd_set writefds;
	fd_set errfds;
	struct timeval t;
	t.tv_sec = 1;
	t.tv_usec = 1000;

	ksock_init();
	fd = ksock_init_fd();

	ksock_set_non_blocking(fd);

	if (0 != ksock_connect(fd, "127.0.0.1", 8737))
	{
		//getchar();
		//return 1;
	}
	ksock_set_alive(fd);

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&errfds);
	FD_SET(fd, &readfds);
	FD_SET(fd, &writefds);
	FD_SET(fd, &errfds);
	ret = select(0, &readfds, &writefds, &errfds, NULL);
	if (0 >= ret)
	{
		printf("select :%d\n", k_errno());
		//return 1;
	}
	for (i = 0; i < readfds.fd_count; ++i)
	{
		int fd = readfds.fd_array[i];
		printf("can read:%d", fd);
	}
	for (i = 0; i < writefds.fd_count; ++i)
	{
		int fd = writefds.fd_array[i];
		printf("can write:%d", fd);
	}
	for (i = 0; i < errfds.fd_count; ++i)
	{
		int fd = errfds.fd_array[i];
		printf("errfd:%d", fd);
	}
	getchar();
	return 0;
}