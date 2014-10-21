#include "../src/k.h"

#ifdef _WIN32
#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif

static void
time_cb(ktimer_t timer, int time, int count, void *data)
{

	printf("time:%d, count:%d, data:0x%x\n", time, count, (uint)data);
}

int
main()
{
#ifdef LINUX
	mtrace();
#endif

	ktimer_node_t node = NULL;
	ktimer_node_t sec_node = NULL;
	ktimer_t timer = NULL;
	int i = 0;

	//create core file
	k_core_dump();

	//start memory check
	kmem_check_start();



	ktimer_init(&timer, 2, NULL);

	ktimer_start(timer);
	k_sleep(1000);
	ktimer_node_init(&node, 16 * 1000, time_cb, 8, NULL);
	ktimer_node_init(&sec_node, 3 * 1000, time_cb, 13, NULL);
	ktimer_add(timer, node);
	k_sleep(2000);
	ktimer_add(timer, sec_node);
	
	getchar();

	ktimer_remove(timer, sec_node);

	getchar();
	ktimer_uninit(timer);

	getchar();
	//check if any memory leak
	kmem_check_leak();
	getchar();
	//stop memory check
	kmem_check_stop();
	getchar();

	return 0;
}
