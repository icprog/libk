#include "../src/k.h"
#include "p2p.h"

#ifdef _WIN32
#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif

static krbtree_t msgmap = NULL;

static kmem_pool_t mp = NULL;

static ksession_t client_sess = NULL;

static ksession_t p2p_sess = NULL;

static knet_t p2p_client = NULL;

static int localport = 0;

static int peerport = 0;

static char peerip[IP_SIZE] = "";

static int establish = 0;

static void
on_userlist(knet_t client, ksession_t session, kvalist_t args)
{
	int i = 0;
	int count = kvalist_count(args);
	printf("user list:\n");
	for (i = 0; i < count; i += 3)
	{
		int fd = kvalist_pop_int(args);
		char *ip = kvalist_pop_string(args);
		int port = kvalist_pop_int(args);
		printf("fd:%d ip:%s port:%d\n", fd, ip, port);
		strcpy(peerip, ip);
		peerport = port;
		kfree(session->tcp_sess->mp, ip);
	}
}


static void
on_applyp2p(knet_t client, ksession_t session, kvalist_t args)
{
	int trycount = 0;
	int fd = kvalist_pop_int(args);
	char *ip = kvalist_pop_string(args);
	int port = kvalist_pop_int(args);
	
	printf("apply p2p to ip:%s, port:%d\n", ip, port);
	if (1 == establish)
	{
		return;
	}
	if (0 == knet_connect(client, localport, ip, port))
	{
		return;
	}
	kfree(session->tcp_sess->mp, ip);
	if (0 == establish)
	{
		knet_run_server(client, session->tcp_sess->localport);
		kvalist_push_int(session->msg, CLIENT_P2P_OK);
		kvalist_push_int(session->msg, fd);
		knet_send(client, session);
	}
}

static void
on_selfaddr(knet_t client, ksession_t session, kvalist_t args)
{
	char *ip = kvalist_pop_string(args);
	int port = kvalist_pop_int(args);

	printf("self addr ip:%s, port:%d\n", ip, port);
	localport = port;
	kfree(session->tcp_sess->mp, ip);
}

static void
on_p2p_ok(knet_t client, ksession_t session, kvalist_t args)
{
	int trycount = 0;
	do 
	{
		if (1 == establish)
		{
			break;
		}
		if (0 == knet_connect(client, localport, peerip, peerport))
		{
			break;
		}
		printf("knet_connect failed to ip%s port:%d, try more ...\n", peerip, peerport);
	} while (++trycount < 3);
}

static void
p2p_reg_msg()
{
	REG_MSG(SERVER_USERLIST,	on_userlist)
	REG_MSG(SERVER_APPLY_P2P,	on_applyp2p)
	REG_MSG(SERVER_SELF_ADDR,	on_selfaddr)
	REG_MSG(SERVER_P2P_OK,		on_p2p_ok)
}

void
p2p_do_action()
{
	do 
	{
		int msg = 0;
		ksession_t sess = NULL;
		scanf("%d", &msg);
		if (0 == msg)
		{
			break;
		}
		if (NULL == p2p_sess)
		{
			sess = client_sess;
		}
		else
		{
			sess = p2p_sess;
		}
		kvalist_push_int(sess->msg, msg);
		switch (msg)
		{
		case CLIENT_LOCAL_ADDR:
			{
				kvalist_push_string(client_sess->msg, client_sess->tcp_sess->localip);
				kvalist_push_int(client_sess->msg, client_sess->tcp_sess->localport);
			}
			break;
		case CLIENT_QUERY_USERLIST:
			break;
		case CLIENT_APPLY_P2P:
			{
				int fd = 0;
				scanf("%d", &fd);
				knet_run_server(p2p_client, sess->tcp_sess->localport);
				kvalist_push_int(sess->msg, fd);
			}
			break;
		default:
			break;
		}
		knet_send(p2p_client, sess);
	} while (1);
}

static void 
p2p_connected_cb(knet_t client, ksession_t session, kvalist_t args)
{
	if (NULL == client_sess)
	{
		client_sess = session;
		printf("connect to p2p server ok\n");
	}
	else
	{
		knet_close(client, client_sess);
		p2p_sess = session;
		printf("p2p established\n");
		establish = 1;
		kvalist_push_int(p2p_sess->msg, 1010);
		knet_send(client, p2p_sess);
	}
}

static void 
p2p_disconnected_cb(knet_t client, ksession_t session, kvalist_t args)
{

}

static void 
p2p_read_cb(knet_t client, ksession_t session, kvalist_t args)
{
	int msg = kvalist_pop_int(args);
	knet_cb cb = (knet_cb)krbtree_find(msgmap, (void *)msg);
	if (cb)
	{
		cb(client, session, args);
	}
	else
	{
		printf("no cb for msg:%d\n", msg);
	}
}

static void
p2p_client_start()
{
	char ip[16] = "";
	knet_init(&p2p_client, 1, mp);
	knet_set_cb(p2p_client, KCB_CONNECTED, p2p_connected_cb);
	knet_set_cb(p2p_client, KCB_DISCONNECTED, p2p_disconnected_cb);
	knet_set_cb(p2p_client, KCB_READ, p2p_read_cb);

	p2p_reg_msg();

	scanf("%s", ip);
	knet_connect(p2p_client, 0, ip, 8737);

	p2p_do_action();

	if (p2p_sess)
	{
		knet_close(p2p_client, p2p_sess);
	}
	else
	{
		knet_close(p2p_client, client_sess);
	}	
	getchar();
	knet_uninit(p2p_client);
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

	kmempool_init(&mp, MEM_POOL_SIZE);

	krbtree_init(&msgmap, NULL, mp);

	p2p_client_start();

	krbtree_uninit(msgmap);

	kmempool_uninit(mp);

	getchar();
	//check if any memory leak
	kmem_check_leak();
	getchar();
	//stop memory check
	kmem_check_stop();
	getchar();
	return 0;
}