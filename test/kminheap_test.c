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

	kminheap_t minheap = NULL;
	kminheap_node_t node = NULL;
	kminheap_node_t tmpnode = NULL;
	int i = 0;

	//create core file
	//k_core_dump();

	//start memory check
	//kmem_check_start();


	kminheap_init(&minheap, 10, NULL);

	for (i = 10; i > 0; i--)
	{
		kminheap_node_init(&node, i, NULL, NULL);
		kminheap_add(minheap, node);
		if (i == 4)
		{
			tmpnode = node;
		}
	}

	kminheap_remove(minheap, tmpnode);
	do 
	{
		kminheap_node_t tnode = kminheap_pop(minheap);
		if (NULL == tnode)
		{
			break;
		}
		printf("key:%d\n", tnode->key);
		kminheap_node_uninit(tnode);
	} while (1);

	kminheap_uninit(minheap);

	getchar();
	//check if any memory leak
	//kmem_check_leak();
	//getchar();
	//stop memory check
	//kmem_check_stop();
	//getchar();

	return 0;
}