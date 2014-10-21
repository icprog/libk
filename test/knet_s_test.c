#include "../src/k.h"

#ifdef _WIN32
#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif

void 
echo_connected_cb(knet_t server, ksession_t session, kvalist_t args)
{
	printf("client connect:%d\n", session->tcp_sess->fd);
}

void 
echo_disconnected_cb(knet_t server, ksession_t session, kvalist_t args)
{
	printf("client disconnect:%d\n", session->tcp_sess->fd);
}

void 
echo_read_cb(knet_t server, ksession_t session, kvalist_t args)
{
	//kvalist_dump(args);
	kvalist_append(session->msg, args);
	knet_send(server, session);
}

void
test_echo_server()
{
	//echo server
	knet_t server = NULL;

	knet_init(&server, 2, NULL);

	knet_set_cb(server, KCB_CONNECTED, echo_connected_cb);

	knet_set_cb(server, KCB_DISCONNECTED, echo_disconnected_cb);

	knet_set_cb(server, KCB_READ, echo_read_cb);

	knet_run_server(server, 8737);
	
	knet_run_server(server, 8989);

	getchar();

	knet_uninit(server);
}



int
main()
{

#ifdef LINUX
	mtrace();
#endif

	//create core file
	//k_core_dump();

	//start memory check
	//kmem_check_start();

	test_echo_server();
	//test_file_server();

	getchar();
	//check if any memory leak
	//kmem_check_leak();
	getchar();
	//stop memory check
	//kmem_check_stop();
	getchar();
	return 0;
}

