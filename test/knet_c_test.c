#include "../src/k.h"

#ifdef _WIN32
#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif

static ksession_t client_sess = NULL;

void 
echo_connected_cb(knet_t server, ksession_t session, kvalist_t args)
{
	printf("client connect:%d\n", session->tcp_sess->fd);
	client_sess = session;
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
	knet_send(server, session);
}

void
test_echo_server()
{
	int i = 0;

	//echo server
	knet_t server = NULL;

	knet_init(&server, 1, NULL);

	knet_set_cb(server, KCB_CONNECTED, echo_connected_cb);

	knet_set_cb(server, KCB_DISCONNECTED, echo_disconnected_cb);

	knet_set_cb(server, KCB_READ, echo_read_cb);

	for (i = 0; i < 1; ++i)
	{
		knet_connect(server, 0, "127.0.0.1", 8737);
	}
	k_sleep(100);
	do
	{
		//char c = getchar();
		kvalist_push_int(client_sess->msg, 1000);
		kvalist_push_string(client_sess->msg, "a string");
		kvalist_push_float(client_sess->msg, (float)2.323);
		if (0 != knet_send(server, client_sess))
		{
			break;
		}
		//if (c == 'q')
		//{
		//	break;
		//}
		if (10 == ++i)
		{
			break;
		}
		k_sleep(10);
	}while(1);
	getchar();
	knet_close(server, client_sess);
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
	kmem_check_start();

	test_echo_server();
	//test_file_server();

	getchar();
	//check if any memory leak
	kmem_check_leak();
	getchar();
	//stop memory check
	kmem_check_stop();
	getchar();
	return 0;
}

