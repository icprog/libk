#include "../src/k.h"

#ifdef _WIN32
#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif

static int
foreach_print(khashmap_t map, void *key, void *value, void *p)
{
	printf("key:%d, value:%d\n", (int)key, (int)value);
	return 0;
}

static int
cmp(void *key1, void *key2)
{
	return strcmp((char *)key1, (char *)key2);
}

int
main()
{
#ifdef LINUX
	mtrace();
#endif

	khashmap_t map = NULL;
	int i = 0;
	int cap = 0;
	int insert = 0;
	scanf("%d,%d", &cap, &insert);

	//create core file
	k_core_dump();

	//start memory check
	kmem_check_start();


	khashmap_init(&map, cap, 0, NULL);

	//khashmap_set_hash(map, khash_default_hash_str);

	//khashmap_set_cmp(map, cmp);

	for (i = 0; i < insert; i++)
	{
		if (0 != khashmap_insert(map, (void *)i, (void *)(100 * i)))
		{
			printf("insert error\n");
		}
	}

	khashmap_foreach(map, foreach_print, NULL);
	printf("conflict:%d\n", khashmap_conflict(map));

	khashmap_uninit(map);

	getchar();
	//check if any memory leak
	kmem_check_leak();
	getchar();
	//stop memory check
	kmem_check_stop();
	getchar();

	return 0;
}
