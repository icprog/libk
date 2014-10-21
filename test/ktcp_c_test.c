#include "../src/k.h"

#ifdef _WIN32
#pragma comment(lib, "k.lib")
#include "vld.h"
#endif

static ktcp_session_t client_sess = NULL;

void 
client_connected_cb(ktcp_t client, ktcp_session_t session)
{
	printf("client connect:%d\n", session->fd);
	client_sess = session;
}

void 
client_disconnected_cb(ktcp_t client, ktcp_session_t session)
{
	printf("client disconnect:%d\n", session->fd);
}

void 
client_read_cb(ktcp_t client, ktcp_session_t session)
{

}

void
test_echo_client()
{
	int i = 0;

	//echo server
	ktcp_t client = NULL;

	ktcp_init(&client, 1, NULL);

	ktcp_set_cb(client, KCB_CONNECTED, client_connected_cb);

	ktcp_set_cb(client, KCB_DISCONNECTED, client_disconnected_cb);

	ktcp_set_cb(client, KCB_READ, client_read_cb);

	ktcp_start(client);

	for (i = 0; i < 1; ++i)
	{
		ktcp_connect(client, 0, "127.0.0.1", 8737);
	}
	k_sleep(2000);
	do
	{
		//char c = getchar();
		char * str = "i am a string";
		if (0 != ktcp_send(client, client_sess, str, strlen(str) + 1))
		{
			break;
		}
		//if (c == 'q')
		//{
		//	break;
		//}
		if (++i == 10)
		{
			break;
		}
		k_sleep(2000);
	}while(1);
	getchar();
	ktcp_uninit(client);
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

	test_echo_client();

	getchar();
	//check if any memory leak
	//kmem_check_leak();
	getchar();
	//stop memory check
	//kmem_check_stop();
	getchar();
	return 0;
}

