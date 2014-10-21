#include "../src/k.h"

#ifdef _WIN32
#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif

void test_http_server();

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

	//test_http_server();

	getchar();
	//check if any memory leak
	kmem_check_leak();
	getchar();
	//stop memory check
	kmem_check_stop();
	getchar();
	return 0;
}

static void
print_tree(void *key, void *val)
{
	printf("key:%s, val:%s\n", (char *)key, (char *)val);
}
/*
int
khttp_server_request(khttp_request_t req, khttp_response_t res)
{
	if (0 != res->conn->http_errno)
	{
		khttp_response_error(res, res->conn->http_errno);
		return 0;
	}
	krbtree_foreach(req->heads, print_tree);

	krbtree_foreach(req->params, print_tree);

	printf("req->file:%s, method:%d\n", req->file, req->method);

	if (req->file[strlen(req->file) - 1] == '/')
	{
		strcat(req->file, "index.html");
	}
	if (0 != khttp_response_file(res, req->file))
	{
		khttp_response_error(res, 404);
	}

	return 0;
}

void 
test_http_server()
{
	khttp_server_t server = NULL;
	khttp_server_init(&server);
	khttp_server_set_request_cb(server, khttp_server_request);
	khttp_server_start(server, 8989, "/");

	getchar();
	khttp_server_uninit(server);
}
*/