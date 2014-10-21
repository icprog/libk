#include "../src/k.h"
#include "p2p.h"

#ifdef _WIN32
#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif

typedef struct user_info user_info, *user_info_t;

struct user_info 
{
	int fd;
	char ip[IP_SIZE];
	int port;
	char localip[IP_SIZE];
	int localport;
	ksession_t sess;
};

static krbtree_t msgmap = NULL;

static krbtree_t usermap = NULL;

static kmem_pool_t mp = NULL;

static kthread_mutex_t usermaplock;

static int 
foreach_user(void *key, void *value, void *p)
{
	ksession_t sess = (ksession_t)p;
	user_info_t user = (user_info_t)value;
	if (sess->tcp_sess->fd == user->fd)
	{
		return 0;
	}
	kvalist_push_int(sess->msg, user->fd);
	kvalist_push_string(sess->msg, user->ip);
	kvalist_push_int(sess->msg, user->port);
	return 0;
}


static void
on_query_userlist(knet_t server, ksession_t session, kvalist_t args)
{
	kvalist_push_int(session->msg, SERVER_USERLIST);
	krbtree_foreach(usermap, foreach_user, session);
	knet_send(server, session);
}

static void
on_apply_p2p(knet_t server, ksession_t session, kvalist_t args)
{
	int targetfd = kvalist_pop_int(args);
	user_info_t target = krbtree_find(usermap, (void *)targetfd);
	if (NULL == target)
	{
		return;
	}
	printf("apply p2p to fd:%d\n", targetfd);
	kvalist_push_int(target->sess->msg, SERVER_APPLY_P2P);
	kvalist_push_int(target->sess->msg, session->tcp_sess->fd);
	kvalist_push_string(target->sess->msg, session->tcp_sess->peerip);
	kvalist_push_int(target->sess->msg, session->tcp_sess->peerport);
	knet_send(server, target->sess);
}

static void
on_local_addr(knet_t server, ksession_t session, kvalist_t args)
{
	char *ip = kvalist_pop_string(args);
	int port = kvalist_pop_int(args);
	user_info_t user = kalloc_t(session->tcp_sess->mp, user_info);
	if (NULL == user)
	{
		return;
	}
	user->fd = session->tcp_sess->fd;
	user->port = session->tcp_sess->peerport;
	strcpy(user->ip, session->tcp_sess->peerip);
	user->localport = port;
	strcpy(user->localip, ip);
	user->sess = session;
	kfree(session->tcp_sess->mp, ip);
	kthread_mutex_lock(&usermaplock);
	if (0 != krbtree_insert(usermap, (void *)user->fd, (void *)user))
	{
		printf("add user failed, fd:%d, ip:%s, port:%d\n", user->fd, user->ip, user->port);
		kfree(session->tcp_sess->mp, user);
		kthread_mutex_unlock(&usermaplock);
		return;
	}
	kthread_mutex_unlock(&usermaplock);
	printf("add user ok, fd:%d, ip:%s, port:%d\n", user->fd, user->ip, user->port);
	kvalist_push_int(session->msg, SERVER_SELF_ADDR);
	kvalist_push_string(session->msg, user->ip);
	kvalist_push_int(session->msg, user->port);
	knet_send(server, session);
}

static void
on_p2p_ok(knet_t server, ksession_t session, kvalist_t args)
{
	int fd = kvalist_pop_int(args);
	user_info_t user = (user_info_t)krbtree_find(usermap, (void *)fd);
	if (NULL == user)
	{
		return;
	}

	kvalist_push_int(user->sess->msg, SERVER_P2P_OK);
	knet_send(server, user->sess);
}

static void
p2p_reg_msg()
{
	REG_MSG(CLIENT_QUERY_USERLIST,	on_query_userlist)
	REG_MSG(CLIENT_APPLY_P2P,		on_apply_p2p)
	REG_MSG(CLIENT_LOCAL_ADDR,		on_local_addr)
	REG_MSG(CLIENT_P2P_OK,			on_p2p_ok)
}

static void 
p2p_connected_cb(knet_t server, ksession_t session, kvalist_t args)
{
	
}

static void 
p2p_disconnected_cb(knet_t server, ksession_t session, kvalist_t args)
{
	user_info_t user = NULL;
	kthread_mutex_lock(&usermaplock);
	user = (user_info_t)krbtree_find(usermap, (void *)session->tcp_sess->fd);
	if (NULL == user)
	{
		kthread_mutex_unlock(&usermaplock);
		printf("can not find user, fd:%d, ip:%s, port%d\n", session->tcp_sess->fd, session->tcp_sess->peerip, session->tcp_sess->peerport);
		return;
	}
	if (0 != krbtree_erase(usermap, (void *)session->tcp_sess->fd))
	{
		printf("erase user failed, fd:%d, ip%s, port%d\n", user->fd, user->ip, user->port);
	}
	else
	{
		printf("erase user ok, fd:%d, ip%s, port%d\n", user->fd, user->ip, user->port);
	}
	kthread_mutex_unlock(&usermaplock);
	kfree(session->tcp_sess->mp, user);
}

static void 
p2p_read_cb(knet_t server, ksession_t session, kvalist_t args)
{
	int msg = kvalist_pop_int(args);
	knet_cb cb = (knet_cb)krbtree_find(msgmap, (void *)msg);
	if (cb)
	{
		cb(server, session, args);
	}
	else
	{
		printf("no cb for msg:%d\n", msg);
	}
}

static void
p2p_server()
{
	knet_t p2p_server = NULL;
	knet_init(&p2p_server, 2, mp);
	knet_set_cb(p2p_server, KCB_CONNECTED, p2p_connected_cb);
	knet_set_cb(p2p_server, KCB_DISCONNECTED, p2p_disconnected_cb);
	knet_set_cb(p2p_server, KCB_READ, p2p_read_cb);

	p2p_reg_msg();

	knet_run_server(p2p_server, 8737);
	//knet_run_server(p2p_server, 8738);

	getchar();
	knet_uninit(p2p_server);
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

	krbtree_init(&usermap, NULL, mp);

	kthread_mutex_init(&usermaplock, NULL);

	p2p_server();

	kthread_mutex_destroy(&usermaplock);

	krbtree_uninit(usermap);

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