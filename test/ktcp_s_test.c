#include "../src/k.h"

#ifdef _WIN32
//#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif

void 
server_connected_cb(ktcp_t server, ktcp_session_t session)
{
	printf("client connect:%d\n", session->fd);
}

void 
server_disconnected_cb(ktcp_t server, ktcp_session_t session)
{
	printf("client disconnect:%d\n", session->fd);
}

void 
server_read_cb(ktcp_t server, ktcp_session_t session)
{
	int len = kbuffer_readable(session->recv_buffer);
	char *p = kbuffer_read(session->recv_buffer, &len);
	//printf("tcp read:%s\n", p);
	ktcp_send(server, session, p, len);
	kbuffer_shift(session->recv_buffer, len);
}

void
test_echo_server()
{
	//echo server
	ktcp_t server = NULL;

	ktcp_init(&server, 2, NULL);

	ktcp_set_cb(server, KCB_CONNECTED, server_connected_cb);

	ktcp_set_cb(server, KCB_DISCONNECTED, server_disconnected_cb);

	ktcp_set_cb(server, KCB_READ, server_read_cb);

	ktcp_start(server);

	ktcp_listen(server, 8737);

	getchar();

	ktcp_uninit(server);
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

