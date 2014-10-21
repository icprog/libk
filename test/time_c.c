#include "../src/k.h"

#ifdef _WIN32
#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif

int
main()
{
	int fd = 0;

	int size = 0;

	kbuffer_t buf = NULL;

	void *data = NULL;

	time_t now = 0;

	char nowStr[64] = {0};

	ksock_init();

	fd = ksock_init_fd();

	kbuffer_init(&buf, NULL);

	ksock_connect(fd, "127.0.0.1", 37);

	do 
	{
		size = kbuffer_read_fd(buf, fd);
	} while (0 == size);
	
	data = kbuffer_read(buf, &size);

	kbuffer_shift(buf, size);

	now = *(time_t *)data;

	printf("now:%d\n", (int)now);

	strcpy(nowStr, ctime(&now));

	size = strlen(nowStr);

	if (nowStr[size - 1] == 10)
	{
		nowStr[size - 1] = '\0';
	}

	printf("time:%s\n", nowStr);

	kbuffer_uninit(buf);

	getchar();
	return 0;
}