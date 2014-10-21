#include "../src/k.h"

#ifdef _WIN32
#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif

void echo_connected_cb(ktcp_t tcp, ktcp_session_t session)
{
	time_t now = 0;
	time(&now);
	printf("now:%d\n", (int)now);
	ktcp_send(tcp, session, &now, sizeof(time_t));
}

int
main()
{

#ifdef LINUX
	mtrace();
#endif

	//create core file
	k_core_dump();

	//start memory check
	kmem_check_start();

	{
		ktcp_t time_server = NULL;
		ktcp_init(&time_server, 4, NULL);
		ktcp_set_cb(time_server, KCB_CONNECTED, echo_connected_cb);
		ktcp_start(time_server);
		ktcp_listen(time_server, 37);

		getchar();
		ktcp_uninit(time_server);
	}


	getchar();
	//check if any memory leak
	kmem_check_leak();
	getchar();
	//stop memory check
	kmem_check_stop();
	getchar();
	return 0;
}