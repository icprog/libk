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

	kvalist_t valist1 = NULL;

	kvalist_t valist2 = NULL;

	int ival = 0;
	float fval = 0.0;
	char *sval = "";
	int count = 0;

	char *data = NULL;
	int len = 0;

	//create core file
	//k_core_dump();

	//start memory check
	//kmem_check_start();

	kvalist_init(&valist1, NULL);

	kvalist_init(&valist2, NULL);

	do
	{
		kvalist_push_int(valist1, 5);
		kvalist_push_float(valist1, (float)2.312);
		kvalist_push_string(valist1, "i am a string");

		kvalist_set_int(valist1, 0, 10);
		kvalist_set_string(valist1, 2, "i am too");

		len = kvalist_data_len(valist1);
		data = kalloc(NULL, len);

		kvalist_serial(valist1, data);

		kvalist_clear(valist1);

		kvalist_deserial(valist2, data, len);

		kvalist_clear(valist2);

		kfree(NULL, data);

		k_sleep(200);
	}
	while (1);


	kvalist_uninit(valist1);

	kvalist_uninit(valist2);

	getchar();
	//check if any memory leak
	//kmem_check_leak();
	getchar();
	//stop memory check
	kmem_check_stop();
	getchar();

	return 0;
}