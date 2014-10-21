#include "../src/k.h"

#ifdef _WIN32
#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif

void
exit_cb(void *arg)
{
	int a = *(int *)arg;
	printf("exit_cb a : %d\n", a);
}

int
main()
{
	int a = 102;
	void *arg = (void *)&a;

#ifdef LINUX
	mtrace();
#endif

	k_demon();
	printf("kdemon_test is running\n");
	getchar();
	printf("kdemon_test after getchar\n");
	k_demon_wait(exit_cb, arg);
	printf("kdemon_test after wait\n");
	return 0;
}
 
