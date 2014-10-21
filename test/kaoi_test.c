#include "../src/k.h"

#ifdef _WIN32
#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif

#define MAX_OBJS	10240
#define RADIUS		100
#define MAP_WIDTH	1000
#define MAP_HEIGHT	600

void KAoi_cb(kaoi_map_t map, kaoi_obj_t watcher, kaoi_obj_t marker, int status)
{

}

int
main()
{
#ifdef LINUX
	mtrace();
#endif

	int i = 0;
	int m_obj_index = 0;
	kaoi_map_t m_aoi_map = NULL;
	

	//create core file
	k_core_dump();

	//start memory check
	//kmem_check_start();

	kaoi_map_init(&m_aoi_map, MAP_WIDTH, MAP_HEIGHT, NULL);

	for (i = 0; i < 100; i++)
	{
		int x = rand() % MAP_WIDTH;
		int y = rand() % MAP_HEIGHT;

		kaoi_obj_t obj = NULL;
		kaoi_obj_init(&obj, x, y, KAOI_WATCHER & KAOI_MARKER, RADIUS, NULL);
		obj->id = m_obj_index;
		obj->target_x = 0;
		obj->target_y = 0;
		//m_aoi_objs[m_obj_index++] = obj;
		kaoi_add_obj(m_aoi_map, obj);
	}

	while (1)
	{
		kaoi_tick(m_aoi_map, KAoi_cb);
	}

	getchar();

	kaoi_map_uninit(m_aoi_map);

	getchar();
	//check if any memory leak
	//kmem_check_leak();
	getchar();
	//stop memory check
	//kmem_check_stop();
	getchar();

	return 0;
}