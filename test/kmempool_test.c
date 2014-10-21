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

	int i = 0;
	char * ptrs[20];
	kmem_pool_t pool = NULL;

	//create core file
	k_core_dump();

	//start memory check
	kmem_check_start();

	kmempool_init(&pool, 4096);

	for (i = 0; i < 20; ++i)
	{
		ptrs[i] = kmempool_alloc(pool, 1000);
		printf("alloc:0x%x\n", (int)ptrs[i]);
	}
	
	for (i = 0; i < 20; ++i)
	{
		printf("free:0x%x\n", (int)ptrs[i]);
		kmempool_free(pool, ptrs[i]);
	}

	kmempool_uninit(pool);

	getchar();
	//check if any memory leak
	kmem_check_leak();
	getchar();
	//stop memory check
	kmem_check_stop();
	getchar();

	return 0;
}