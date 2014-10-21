#include "../src/k.h"

#ifdef _WIN32
#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif

static int 
cmp_test(void *left_key, void *right_key)
{
	int left = (int)left_key;
	int right = (int)right_key;
	if (left < right)
	{
		return -1;
	}
	else if (left > right)
	{
		return 1;
	}
	else 
	{
		assert (left == right);
		return 0;
	}
}

static int
foreach_cb(void *key, void *val, void *p)
{
	printf("key:%d, val:%d\n", (int)key, (int)val);
	return 0;
}

int
main()
{
#ifdef LINUX
	mtrace();
#endif
	int i = 0;
	krbtree_t tree;

	k_core_dump();
	kmem_check_start();

	krbtree_init(&tree, cmp_test, NULL);

	for(i=0; i<5000; i++) 
	{
		//int x = rand() % 10000;
		int y = rand() % 10000;
		printf("Inserting %d -> %d\n\n", i, y);
		krbtree_insert(tree, (void*)i, (void*)y);
		assert((int)krbtree_find(tree, (void*)i) == y);
	}
	for(i=0; i<60000; i++) 
	{
		//int x = rand() % 10000;
		printf("Deleting key %d\n\n", i);
		krbtree_erase(tree, (void*)i);
	}

	krbtree_insert(tree, (void *)1, (void *)10);
	krbtree_insert(tree, (void *)2, (void *)10);
	krbtree_insert(tree, (void *)3, (void *)10);
	printf("find key:%d, val:%d\n", 1, (int)krbtree_find(tree, (void *)1));
	krbtree_insert(tree, (void *)1, (void *)11);
	printf("find key:%d, val:%d\n", 1, (int)krbtree_find(tree, (void *)1));
	krbtree_erase(tree, (void *)1);
	printf("find key:%d, val:%d\n", 1, (int)krbtree_find(tree, (void *)1));

	krbtree_foreach(tree, foreach_cb, NULL);

	krbtree_clear(tree);

	krbtree_uninit(tree);

	getchar();
	kmem_check_leak();
	kmem_check_stop();
	printf("Okay\n");
	getchar();
	return 0;
}