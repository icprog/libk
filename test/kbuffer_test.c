#include "../src/k.h"

#ifdef _WIN32
#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif

int
main()
{
#ifdef LINUX
	mtrace();
#endif
	char * buf = "asdas";
	int len = 1024;
	void * p = NULL;
	kbuffer_t buff;
	kbuffer_init(&buff, NULL);

	kbuffer_write(buff, buf, 1024);

	printf("readable:%d\n", kbuffer_readable(buff));

	p = kbuffer_read(buff, &len);

	printf("readable:%d\n", kbuffer_readable(buff));

	kbuffer_shift(buff, len);

	printf("readable:%d\n", kbuffer_readable(buff));

	kbuffer_write(buff, buf, strlen(buf));

	kbuffer_uninit(buff);

	return 0;
}
