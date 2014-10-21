/******************************************************************/
/*
File:   k.h

Author: KevinZhou

Email:  kaiwen387@gmail.com

Date:   2012/02/26 14:44:35

Descript: epoll on linux and select on windows net event, memory leak check, thread safe list, buffer manager for net module,
core dump file,


already read readable    writeable
|__________|_________|____________________|
0		   rindex    windex				  size


export MALLOC_TRACE=kmalloc.log for mtrace

valgrind --tool=memcheck --leak-check=full --show-reachable=yes --log-file=1.txt ./ktest

*/
/******************************************************************/

#ifndef _LIBK_H
#define _LIBK_H


typedef unsigned int uint;
typedef unsigned char uchar;

enum data_type
{
	type_unknown = 0,
	type_int = 2,
	type_float = 3,
	type_string = 4,
};

#ifndef _WIN32
#define LINUX
#endif

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define K_BUFFER_SIZE	1024			/*default kbuffer_t size*/
#define IP_SIZE			16
#define K_TIMER_SIZE	128				/*default timer queue size*/
#define K_HASHMAP_SIZE	1024
#define K_HASHMAP_LOAD	75
#define K_TIMER_THR		4				/*default timer queue thread num*/
#define MEM_POOL_SIZE	4096
#define K_VALIST_SIZE	16
#define K_SOCK_MAXERR	5
#define K_SOCK_SENDBUF	32 * 1024
#define K_SOCK_IDLE		5 * 60
#define K_SOCK_INTVAL	5
#define K_SOCK_CNT		3
#define K_MAX_IO		10240

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef LINUX

#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <sys/errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <mcheck.h>

#define K_EINTR		EINTR
#define K_EAGAIN	EAGAIN
#define K_TIMEOUT	ETIMEDOUT
#define K_SHUT_RD	SHUT_RD
#define K_SHUT_WR	SHUT_WR
#define K_SHUT_RDWR	SHUT_RDWR

#define K_EXPORT

//katomic.h
#define katomic_get(v)		__sync_val_compare_and_swap(&v, 0, 0)
#define katomic_add(v,x)	__sync_add_and_fetch(&v, x)
#define katomic_inc(v)		katomic_add(v, 1)
#define katomic_dec(v)		katomic_add(v, -1)
#define katomic_set(v,x)	__sync_lock_test_and_set(&v, x)


//kthread
#define k_sleep(x)						usleep(x * 1000)
#define kthread_self					pthread_self
#define kthread_create					pthread_create
#define KTHREAD_CALL

typedef pthread_t						kthread_t;
typedef pthread_attr_t					kthread_attr_t;
typedef void *							kthread_result_t;
typedef pthread_mutex_t					kthread_mutex_t;
typedef pthread_cond_t					kthread_cond_t;
typedef pthread_rwlock_t				kthread_rwlock_t;
typedef kthread_result_t				(KTHREAD_CALL * kthread_func_t)(void * args);

#define kthread_attr_init(a)			pthread_attr_init(a)
#define kthread_attr_setdetachstate		pthread_attr_setdetachstate
#define KTHREAD_CREATE_DETACHED			PTHREAD_CREATE_DETACHED

#define kthread_join(tid,a)				pthread_join(tid,a)

#define kthread_mutex_init(m,a)			pthread_mutex_init(m,a)
#define kthread_mutex_destroy(m)		pthread_mutex_destroy(m)
#define kthread_mutex_lock(m)			pthread_mutex_lock(m)
#define kthread_mutex_unlock(m)			pthread_mutex_unlock(m)

#define kthread_cond_init(c,a)			pthread_cond_init(c,a)
#define kthread_cond_destroy(c)			pthread_cond_destroy(c)
#define kthread_cond_wait(c,m)			pthread_cond_wait(c,m)
#define kthread_cond_signal(c)			pthread_cond_signal(c)
#define kthread_cond_broadcast(c)		pthread_cond_broadcast(c)

#define kthread_rwlock_init(rd,a)		pthread_rwlock_init(rd,a)
#define kthread_rwlock_destroy(rd)		pthread_rwlock_destroy(rd)
#define kthread_rwlock_rdlock(rd)		pthread_rwlock_rdlock(rd)
#define kthread_rwlock_wrlock(rd)		pthread_rwlock_wrlock(rd)
#define kthread_rwlock_unlock(rd)		pthread_rwlock_unlock(rd)


K_EXPORT int kthread_cond_timedwait(kthread_cond_t * cond, kthread_mutex_t * mutex, int timeout);


#else
#ifdef _WIN32

#include <WinSock2.h>
#include <direct.h>
#include <process.h>
#include <crtdbg.h>
#include <psapi.h>
#include <Dbghelp.h>
#include <tchar.h>
#include <crtdbg.h>
#include <Windows.h>
#include <MSTCPiP.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment( lib, "DbgHelp" )
#pragma comment( lib, "psapi.lib" )

typedef int socklen_t;

#define K_EINTR		WSAEINTR
#define K_EAGAIN	WSAEWOULDBLOCK
#define K_TIMEOUT	WAIT_TIMEOUT
#define K_SHUT_RD	0x00
#define K_SHUT_WR	0x01
#define K_SHUT_RDWR	0x02

#ifndef K_EXPORT
#define K_EXPORT	_declspec(dllexport)
#endif


//katomic.h
#define katomic_get(v)		InterlockedCompareExchange(&v, 0, 0)
#define katomic_add(v,x)	InterlockedExchangeAdd(&v, x)
#define katomic_inc(v)		InterlockedIncrement(&v)
#define katomic_dec(v)		InterlockedDecrement(&v)
#define katomic_set(v,x)	InterlockedExchange(&v, x)


//kthread
#define inline						_inline

#define k_sleep(x)					Sleep(x)
#define KTHREAD_CALL				__stdcall
#define KTHREAD_CREATE_DETACHED		1

typedef unsigned					kthread_t;
typedef DWORD						kthread_attr_t;
typedef unsigned					kthread_result_t;
typedef HANDLE						kthread_mutex_t;
typedef HANDLE						kthread_cond_t;
typedef HANDLE						kthread_rwlock_t;
typedef kthread_result_t			(KTHREAD_CALL * kthread_func_t)(void * args);


K_EXPORT int kthread_mutex_init(kthread_mutex_t * mutex, void * attr);

K_EXPORT int kthread_mutex_destroy(kthread_mutex_t * mutex);

K_EXPORT int kthread_mutex_lock(kthread_mutex_t * mutex);

K_EXPORT int kthread_mutex_unlock(kthread_mutex_t * mutex);

K_EXPORT int kthread_cond_init(kthread_cond_t * cond, void * attr);

K_EXPORT int kthread_cond_destroy(kthread_cond_t * cond);

K_EXPORT int kthread_cond_wait(kthread_cond_t * cond, kthread_mutex_t * mutex);

K_EXPORT int kthread_cond_timedwait(kthread_cond_t * cond, kthread_mutex_t * mutex, int timeout);

K_EXPORT int kthread_cond_signal(kthread_cond_t * cond);

K_EXPORT int kthread_cond_broadcast(kthread_cond_t * cond);

K_EXPORT int kthread_rwlock_init(kthread_rwlock_t rwlock, void * attr);

K_EXPORT int kthread_rwlock_destroy(kthread_rwlock_t rwlock);

K_EXPORT int kthread_rwlock_rdlock(kthread_rwlock_t rwlock);

K_EXPORT int kthread_rwlock_wrlock(kthread_rwlock_t rwlock);

K_EXPORT int kthread_rwlock_unlock(kthread_rwlock_t rwlock);

K_EXPORT int kthread_join(kthread_t tid, kthread_attr_t * attr);

K_EXPORT kthread_t kthread_self();

K_EXPORT int kthread_attr_init(kthread_attr_t * attr);

K_EXPORT int kthread_attr_setdetachstate(kthread_attr_t * attr, int detachstate);

K_EXPORT int kthread_create(kthread_t * thread, kthread_attr_t * attr, kthread_func_t myfunc, void * args);

#endif

#endif




//kmempool

typedef struct kmem_pool kmem_pool, *kmem_pool_t;


K_EXPORT int kmempool_init(kmem_pool_t *ppool, uint size);

K_EXPORT int kmempool_uninit(kmem_pool_t pool);

K_EXPORT void *kmempool_alloc(kmem_pool_t pool, uint size);

K_EXPORT void *kmempool_realloc(kmem_pool_t pool, void *old, uint oldsize, uint size);

K_EXPORT int kmempool_free(kmem_pool_t pool, void *data);


//kutil.h

#define k_malloc(x)					k_real_alloc(0, x, __FILE__, __LINE__, "")
#define k_malloc_t(x)				k_real_alloc(0, sizeof(x), __FILE__, __LINE__, #x)
#define k_realloc(old,x)			k_real_alloc(old, x, __FILE__, __LINE__, "")
#define k_free(x)					{k_real_free(x, 1);x = NULL;}

#define kalloc(mp,x)				kmalloc_wrap(mp, x, __FILE__, __LINE__, "");
#define kalloc_t(mp,x)				kmalloc_wrap(mp, sizeof(x), __FILE__, __LINE__, #x);
#define krealloc(mp, old, oldx, x)	krealloc_wrap(mp, old, oldx, x, __FILE__, __LINE__, "");
#define kfree(mp, x)				{kfree_wrap(mp, x);x = NULL;}

K_EXPORT void *kmalloc_wrap(kmem_pool_t mp, uint size, char * file, int line, char * name);

K_EXPORT void *krealloc_wrap(kmem_pool_t mp, void *old, uint oldsize, uint size, char * file, int line, char * name);

K_EXPORT void kfree_wrap(kmem_pool_t mp, void *p);


K_EXPORT void *k_real_alloc(void * p, int size, char * file, int line, char * name);

K_EXPORT void k_real_free(void *p, int isreal);

//start memory check
K_EXPORT void kmem_check_start();

//stop memory check
K_EXPORT void kmem_check_stop();

//check the memory alloc and not free
K_EXPORT void kmem_check_leak();

typedef struct klist_node klist_node, *klist_node_t;

struct klist_node
{
	void *data;				/*user data*/
	klist_node_t next;		/*node next in list*/
};

typedef struct klist klist, *klist_t;

typedef int (* klist_foreach_cb)(void *data, void *p);

struct klist
{
	klist_node_t head;
	klist_node_t tail;
	kmem_pool_t mp;
	int size;
};

K_EXPORT int klist_init(klist_t *plist, kmem_pool_t mp);

K_EXPORT int klist_uninit(klist_t list);

K_EXPORT int klist_push(klist_t list, void *data);

K_EXPORT void * klist_pop(klist_t list);

K_EXPORT void * klist_front(klist_t list);

K_EXPORT int klist_find(klist_t list, void *data);

K_EXPORT int klist_size(klist_t list);

K_EXPORT int klist_erase(klist_t list, void *data);

K_EXPORT int klist_clear(klist_t list);

K_EXPORT void klist_foreach(klist_t list, klist_foreach_cb cb, void *p);


//define list

#define kdlist_node(node)\
	struct node * next;\
	struct node * prev;

#define kdlist(node,list)\
	struct d_list\
	{\
		struct node * head;\
		struct node * tail;\
	};\
	struct d_list list;


#define kdlist_init(list)\
	do \
	{\
		list.head = NULL;\
		list.tail = NULL;\
	} while (0);


#define kdlist_push(list,node)\
	do \
	{\
		if (list.head == NULL)\
		{\
			list.head = list.tail = node;\
		}\
		else\
		{\
			list.tail->next = node;\
			node->prev = list.tail;\
			list.tail = node;\
		}\
	} while (0);


#define kdlist_pop(list,pnode)\
	do \
	{\
		if (NULL == list.head)\
		{\
			*pnode = NULL;\
			break;\
		}\
		*pnode = list.head;\
		list.head = list.head->next;\
		if (NULL == list.head)\
		{\
			list.tail = list.head = NULL;\
		}\
		(*pnode)->prev = NULL;\
		(*pnode)->next = NULL;\
	} while (0);


#define kdlist_front(list,pnode)\
	do \
	{\
		if (NULL == list.head)\
		{\
			*pnode = NULL;\
			break;\
		}\
		*pnode = list.head;\
	} while (0);


#define kdlist_erase(list,node)\
	do \
	{\
		if (node->prev)\
		{\
			node->prev->next = node->next;\
		}\
		else\
		{\
			list.head = node->next;\
		}\
		if (node->next)\
		{\
			node->next->prev = node->prev;\
		}\
		else\
		{\
			list.tail = node->prev;\
		}\
		node->prev = NULL;\
		node->next = NULL;\
	}\
	while (0);

#define kdlist_find(list,node,in,pout)\
	do \
	{\
		struct node * tmp = NULL;\
		for (tmp = list.head; tmp; tmp = tmp->next)\
		{\
			if (tmp == in)\
			{\
				*pout = tmp;\
			}\
		}\
	}\
	while (0);

#define kdlist_clear(list)\
	do \
	{\
		list.head = list.tail = NULL;\
	}\
	while (0);

#define kdlist_foreach(list,node,cb,data)\
	do \
	{\
		struct node * tmp = NULL;\
		for (tmp = list.head; tmp; tmp = tmp->next)\
		{\
			if (0 != cb(tmp, data))\
			{\
				break;\
			}\
		}\
	}\
	while (0);


//error

K_EXPORT int k_errno();

K_EXPORT char * k_strerr();

K_EXPORT int k_chbindir();

//create core file when dump
K_EXPORT int k_core_dump();

//demonize
K_EXPORT int k_demon();

typedef void (*kexit_cb)(void *);

//demonize wait
K_EXPORT int k_demon_wait(kexit_cb cb, void *arg);

//knet
K_EXPORT int ksock_from_addr(struct sockaddr_in addr_in, char *ip, int *pport);

K_EXPORT int ksock_to_addr(struct sockaddr_in *addr_in, char *ip, int port);

K_EXPORT int ksock_init();

K_EXPORT int ksock_set_non_blocking(int fd);

K_EXPORT int ksock_set_close_onexec(int fd);

K_EXPORT int ksock_shutdown(int fd, int how);

K_EXPORT int ksock_close(int fd);

K_EXPORT int ksock_set_reuse(int fd);

K_EXPORT int ksock_set_sendbuf(int fd, int buff);

K_EXPORT int ksock_set_alive(int fd, int idle, int intval, int cnt);

K_EXPORT int ksock_ioctl(int fd, int op, int *out);

K_EXPORT int ksock_init_fd();

K_EXPORT int ksock_bind(int fd, int port);

K_EXPORT int ksock_listen_at(int fd, int port);

K_EXPORT int ksock_accept(int fd, char *ip, int *pport);

K_EXPORT int ksock_connect(int fd, char * ip, int port);

//half blocking list, when push, lock head, and pop lock tail
typedef struct khb_list khb_list, *khb_list_t;

struct khb_list
{
	klist_node_t head;
	klist_node_t tail;

	kmem_pool_t mp;

	kthread_mutex_t head_mtx;		/*mutex lock when push*/
	kthread_mutex_t tail_mtx;		/*mutex lock when pop*/
	kthread_cond_t list_cond;		/*when empty when for list_cond, and signal after push*/

};


K_EXPORT int khb_list_init(khb_list_t *plist, kmem_pool_t mp);

K_EXPORT int khb_list_uninit(khb_list_t list);

K_EXPORT int khb_list_push(khb_list_t list, void *data);

K_EXPORT void * khb_list_pop(khb_list_t list);

K_EXPORT void khb_list_broadcast(khb_list_t list);


typedef void (* ktask_cb)(void * args);

typedef struct ktask ktask, *ktask_t;

struct ktask
{
	ktask_cb cb;		/*task func for call*/
	void * args;		/*task func args*/
	ktask_t next;
	kmem_pool_t mp;
};

K_EXPORT int ktask_init(ktask_t * ptask, ktask_cb cb, void * args, kmem_pool_t mp);

K_EXPORT int ktask_uninit(ktask_t task);


//kthreadpool.h

typedef struct kthreadpool kthreadpool, *kthreadpool_t;


K_EXPORT int kthreadpool_init(kthreadpool_t * pthreadpool, int threadnum, kmem_pool_t mp);

K_EXPORT int kthreadpool_set_data(kthreadpool_t threadpool, void * data);

K_EXPORT void *kthreadpool_get_data(kthreadpool_t threadpool);

K_EXPORT int kthreadpool_start(kthreadpool_t threadpool);

K_EXPORT int kthreadpool_isrunning(kthreadpool_t threadpool);

K_EXPORT int kthreadpool_run(kthreadpool_t, ktask_cb cb, void * args);

K_EXPORT int kthreadpool_uninit(kthreadpool_t threadpool);




//kev.h

#define FD_MAX		102400		/*max fds handle for*/
#define EV_MAX		4			/*max events per fd*/

enum k_ev_enum
{
	K_EV_READ		=	0x001,
	K_EV_WRITE		=	0x004,

};


typedef struct kev kev, *kev_t;

typedef struct kevloop kevloop, *kevloop_t;

typedef struct kevent kevent, *kevent_t;

typedef void (* kevloop_cb)(kevloop_t evloop, kev_t ev);


//kev
K_EXPORT int kev_init(kev_t *pev, int fd, int event, kevloop_cb cb, kmem_pool_t mp);

K_EXPORT int kev_set_data(kev_t ev, void * data);

K_EXPORT void *kev_get_data(kev_t ev);

K_EXPORT int kev_uninit(kev_t ev);


//kevent
K_EXPORT int kevent_init(kevent_t *pevent, int threadnum);

K_EXPORT int kevent_set_data(kevent_t event, void * data);

K_EXPORT kevloop_t kevent_fetch_loop(kevent_t event);

K_EXPORT int kevent_watch(kevloop_t evloop, kev_t ev);

K_EXPORT int kevent_ignore(kevloop_t evloop, kev_t ev);

K_EXPORT int kevent_start(kevent_t event);

K_EXPORT int kevent_uninit(kevent_t event);


//kbuffer
typedef struct kbuffer kbuffer, *kbuffer_t;


K_EXPORT int kbuffer_init(kbuffer_t *pbuffer, kmem_pool_t mp);

K_EXPORT int kbuffer_uninit(kbuffer_t buffer);

K_EXPORT int kbuffer_readable(kbuffer_t buffer);

K_EXPORT void * kbuffer_read(kbuffer_t buffer, int *psize);

K_EXPORT void kbuffer_shift(kbuffer_t buffer, int size);

K_EXPORT int kbuffer_write(kbuffer_t buffer, void *data, int size);

K_EXPORT int kbuffer_read_fd(kbuffer_t buffer, int fd);

K_EXPORT int kbuffer_write_fd(kbuffer_t buffer, int fd);


//ktcp

enum
{
	KCB_CONNECTED,
	KCB_DISCONNECTED,
	KCB_READ,
};

typedef struct ktcp_session ktcp_session, *ktcp_session_t;

typedef struct ktcp ktcp, *ktcp_t;

typedef void (* ktcp_cb)(ktcp_t tcp, ktcp_session_t session);


struct ktcp_session
{
	int fd;
	kbuffer_t send_buffer;
	kbuffer_t recv_buffer;

	char localip[IP_SIZE];
	int localport;

	char peerip[IP_SIZE];
	int peerport;

	int err;					/*error times*/
	kthread_mutex_t send_lock;

	kmem_pool_t mp;
	void *data;					/*user data*/
};


//ktcp
K_EXPORT int ktcp_init(ktcp_t * ptcp, int threadnum, kmem_pool_t mp);

K_EXPORT int ktcp_connect(ktcp_t tcp, int selfport, char *ip, int port);

K_EXPORT int ktcp_start(ktcp_t tcp);

K_EXPORT int ktcp_listen(ktcp_t tcp, int port);

K_EXPORT int ktcp_close_session(ktcp_t tcp, ktcp_session_t session);

K_EXPORT int ktcp_set_data(ktcp_t tcp, void *data);

K_EXPORT void *ktcp_get_data(ktcp_t tcp);

K_EXPORT int ktcp_set_cb(ktcp_t tcp, int cb_type, ktcp_cb cb);

K_EXPORT int ktcp_send(ktcp_t tcp, ktcp_session_t session, void * data, int len);

K_EXPORT int ktcp_uninit(ktcp_t tcp);



//krbtree

typedef struct krbtree krbtree, *krbtree_t;

typedef int (*krbtree_cmp)(void *left_key, void *right_key);

typedef int (*krbtree_foreach_cb)(void *key, void *value, void *p);


K_EXPORT int krbtree_init(krbtree_t *ptree, krbtree_cmp cmp, kmem_pool_t mp);

K_EXPORT void *krbtree_find(krbtree_t tree, void *key);

K_EXPORT int krbtree_insert(krbtree_t tree, void *key, void *value);

K_EXPORT int krbtree_erase(krbtree_t tree, void *key);

K_EXPORT int krbtree_foreach(krbtree_t tree, krbtree_foreach_cb cb, void *p);

K_EXPORT int krbtree_clear(krbtree_t tree);

K_EXPORT int krbtree_uninit(krbtree_t tree);


//kminheap

typedef struct kminheap kminheap, *kminheap_t;

typedef struct kminheap_node kminheap_node, *kminheap_node_t;

typedef int (* kminheap_foreach_cb)(kminheap_t minheap, kminheap_node_t node, void *p);

struct kminheap_node
{
	int key;
	void *value;
	kmem_pool_t mp;
	int pos;
};

K_EXPORT int kminheap_node_init(kminheap_node_t *pnode, int key, void *value, kmem_pool_t mp);

K_EXPORT int kminheap_node_uninit(kminheap_node_t node);


K_EXPORT int kminheap_init(kminheap_t *pminheap, uint size, kmem_pool_t mp);

K_EXPORT int kminheap_uninit(kminheap_t minheap);

K_EXPORT int kminheap_set_data(kminheap_t minheap, void *data);

K_EXPORT void * kminheap_get_data(kminheap_t minheap);

K_EXPORT int kminheap_add(kminheap_t minheap, kminheap_node_t node);

K_EXPORT int kminheap_remove(kminheap_t minheap, kminheap_node_t node);

K_EXPORT int kminheap_find(kminheap_t minheap, kminheap_node_t node);

K_EXPORT int kminheap_foreach(kminheap_t minheap, kminheap_foreach_cb cb, void *p);

K_EXPORT kminheap_node_t kminheap_top(kminheap_t minheap);

K_EXPORT kminheap_node_t kminheap_pop(kminheap_t minheap);

K_EXPORT kminheap_node_t kminheap_next(kminheap_t minheap, kminheap_node_t node);



//ktimer

typedef struct ktimer ktimer, *ktimer_t;

typedef struct ktimer_node ktimer_node, *ktimer_node_t;

typedef void (* ktimer_cb)(ktimer_t timer, int time, int count, void *data);

typedef int (* ktimer_foreach_cb)(ktimer_t timer, ktimer_node_t node, void *p);


K_EXPORT int ktimer_node_init(ktimer_node_t *pnode, int time, ktimer_cb cb, int count, kmem_pool_t mp);

K_EXPORT int ktimer_node_uninit(ktimer_node_t node);

K_EXPORT int ktimer_node_set_data(ktimer_node_t node, void *data);

K_EXPORT void *ktimer_node_get_data(ktimer_node_t node);


K_EXPORT int ktimer_init(ktimer_t *ptimer, int thr_num, kmem_pool_t mp);

K_EXPORT int ktimer_uninit(ktimer_t timer);

K_EXPORT int ktimer_isrunning(ktimer_t timer);

K_EXPORT int ktimer_set_data(ktimer_t timer, void *data);

K_EXPORT void *ktimer_get_data(ktimer_t timer);

K_EXPORT int ktimer_add(ktimer_t timer, ktimer_node_t node);

K_EXPORT int ktimer_remove(ktimer_t timer, ktimer_node_t node);

K_EXPORT int ktimer_find(ktimer_t timer, ktimer_cb cb);

K_EXPORT int ktimer_foreach(ktimer_t timer, ktimer_foreach_cb cb, void *p);

K_EXPORT int ktimer_start(ktimer_t timer);


//kvalist

typedef struct kvalist kvalist, *kvalist_t;


K_EXPORT int kvalist_init(kvalist_t *pvalist, kmem_pool_t mp);

K_EXPORT int kvalist_uninit(kvalist_t valist);

K_EXPORT int kvalist_count(kvalist_t valist);

K_EXPORT int kvalist_clear(kvalist_t valist);

K_EXPORT uchar kvalist_type(kvalist_t valist, uint index);

K_EXPORT int kvalist_push_int(kvalist_t valist, int val);

K_EXPORT int kvalist_push_float(kvalist_t valist, float val);

K_EXPORT int kvalist_push_string(kvalist_t valist, char *val);

K_EXPORT int kvalist_pop_int(kvalist_t valist);

K_EXPORT float kvalist_pop_float(kvalist_t valist);

K_EXPORT char * kvalist_pop_string(kvalist_t valist);

K_EXPORT int kvalist_set_int(kvalist_t valist, uint index, int val);

K_EXPORT int kvalist_set_float(kvalist_t valist, uint index, float val);

K_EXPORT int kvalist_set_string(kvalist_t valist, uint index, char *val);

K_EXPORT int kvalist_append(kvalist_t valist, kvalist_t appendlist);

K_EXPORT int kvalist_data_len(kvalist_t valist);

K_EXPORT int kvalist_serial(kvalist_t valist, char *data);

K_EXPORT int kvalist_deserial(kvalist_t valist, char *data, uint len);

K_EXPORT int kvalist_dump(kvalist_t valist);

//khashmap


typedef struct khashmap khashmap, *khashmap_t;

typedef int (* khash_cb)(void *key, int size);

typedef int (* khash_cmp_cb)(void *key1, void *key2);

typedef int (* khashmap_foreach_cb)(khashmap_t map, void *key, void *value, void *p);

int khash_default_hash_str(void *key, int size);


K_EXPORT int khashmap_init(khashmap_t *pmap, uint capacity, uint loadfactor, kmem_pool_t mp);

K_EXPORT int khashmap_uninit(khashmap_t map);

K_EXPORT int khashmap_set_hash(khashmap_t map, khash_cb cb);

K_EXPORT int khashmap_set_cmp(khashmap_t map, khash_cmp_cb cb);

K_EXPORT int khashmap_set_data(khashmap_t map, void *data);

K_EXPORT void *khashmap_get_data(khashmap_t map);

K_EXPORT int khashmap_insert(khashmap_t map, void *key, void *value);

K_EXPORT void *khashmap_find(khashmap_t map, void *key);

K_EXPORT int khashmap_set_value(khashmap_t map, void *key, void *value);

K_EXPORT int khashmap_erase(khashmap_t map, void *key);

K_EXPORT int khashmap_size(khashmap_t map);

K_EXPORT int khashmap_foreach(khashmap_t map, khashmap_foreach_cb cb, void *p);

K_EXPORT int khashmap_conflict(khashmap_t map);



//quick sort
K_EXPORT void k_quicksort(int data[], int n);




//quadtree

#define KQUAD_SUBS 4
#define KQBOX_OVERLAP_MAX 0.4
#define KQBOX_OVERLAP_MIN 0.02

#define KQTREE_DEPTH_MAX 8
#define KQTREE_DEPTH_MIN 4

#define KQUADRANT_BITS 3

enum
{
	NE = 0,
	NW = 1,
	SW = 2,
	SE = 3,
};

typedef struct kquad_box kquad_box, *kquad_box_t;

typedef struct kquad_node kquad_node, *kquad_node_t;

typedef struct kquad_tree kquad_tree, *kquad_tree_t;

typedef int (* kquadtree_foreach_cb)(kquad_node_t node, void *p);

struct kquad_box
{
	int xmin;
	int ymin;
	int xmax;
	int ymax;

	kmem_pool_t mp;
	void *data;			/*user data*/
};

K_EXPORT int kquad_box_init(kquad_box_t *pbox, int xmin, int ymin, int xmax, int ymax, kmem_pool_t mp);

K_EXPORT int kquad_box_uninit(kquad_box_t box);

K_EXPORT int kquad_box_set_data(kquad_box_t box, void *data);

K_EXPORT void *kquad_box_get_data(kquad_box_t box);

K_EXPORT int kquadtree_init(kquad_tree_t *ptree, kquad_box_t box, int depth, float overlap, kmem_pool_t mp);

K_EXPORT void kquadtree_search(kquad_tree_t tree, kquad_box_t search_box, klist_t ret_list);

K_EXPORT int kquadtree_insert(kquad_tree_t tree, kquad_box_t box);

K_EXPORT int kquadtree_erase(kquad_tree_t tree, kquad_box_t box);

K_EXPORT int kquadtree_foreach(kquad_tree_t tree, kquadtree_foreach_cb cb, void *p);

K_EXPORT int kquadtree_clear(kquad_tree_t tree);

K_EXPORT int kquadtree_uninit(kquad_tree_t tree);



//kcrosslist

typedef struct kcross_node kcross_node, *kcross_node_t;

typedef struct kcrosslist kcrosslist, *kcrosslist_t;


K_EXPORT int kcrosslist_init(kcrosslist_t *plist, kmem_pool_t mp);

K_EXPORT int kcrosslist_uninit(kcrosslist_t list);

K_EXPORT int kcrosslist_insert(kcrosslist_t list, int x, int y, void *data);

K_EXPORT int kcrosslist_erase(kcrosslist_t list, int x, int y);

K_EXPORT int kcrosslist_size(kcrosslist_t list);

K_EXPORT int kcrosslist_search(kcrosslist_t list, int x, int y, klist_t ret_list);

K_EXPORT int kcrosslist_clear(kcrosslist_t list);

//kaoi

#define KAOI_MAX_VIS	1000	/*max visible obj per obj*/

enum kaoi_obj_type
{
	KAOI_WATCHER	=	1,
	KAOI_MARKER		=	2,
};

enum kaoi_obj_status
{
	KAOI_LEAVE		=	1,
	KAOI_ENTER		=	2,
	KAOI_STAY		=	3,
	KAOI_DROP		=	4,
};

typedef struct kaoi_obj kaoi_obj, *kaoi_obj_t;

typedef struct kaoi_map kaoi_map, *kaoi_map_t;

typedef void (* kaoi_cb)(kaoi_map_t map, kaoi_obj_t watcher, kaoi_obj_t marker, int status);

struct kaoi_obj
{
	int id;
	int x;
	int y;
	int type;
	int radius;

	int target_x;
	int target_y;

	khashmap_t vis_map;
	klist_t ret_list;

	kquad_box_t box;

	kmem_pool_t mp;
	void *data;			/*user data*/
};

struct kaoi_map
{
	int map_w;
	int map_h;

	kquad_box_t tree_box;
	kquad_tree_t tree;

	klist_t obj_list;

	kthread_mutex_t aoi_lock;

	kmem_pool_t mp;
	void *data;			/*user data*/
};

K_EXPORT int kaoi_obj_init(kaoi_obj_t *pobj, int x, int y, int type, int radius, kmem_pool_t mp);

K_EXPORT int kaoi_obj_uninit(kaoi_obj_t obj);


K_EXPORT int kaoi_map_init(kaoi_map_t *pmap, int map_w, int map_h, kmem_pool_t mp);

K_EXPORT int kaoi_map_uninit(kaoi_map_t map);

K_EXPORT int kaoi_map_set_data(kaoi_map_t map, void *data);

K_EXPORT void *kaoi_map_get_data(kaoi_map_t map);

K_EXPORT int kaoi_add_obj(kaoi_map_t map, kaoi_obj_t obj);

K_EXPORT int kaoi_remove_obj(kaoi_map_t map, kaoi_obj_t obj);

K_EXPORT int kaoi_move_obj(kaoi_map_t map, kaoi_obj_t obj, int x, int y);

K_EXPORT int kaoi_obj_around(kaoi_map_t map, kaoi_obj_t obj, klist_t obj_list);

K_EXPORT int kaoi_tick(kaoi_map_t map, kaoi_cb cb);



//kserver

typedef struct knet knet, *knet_t;

typedef struct ksession ksession, *ksession_t;

typedef void (*knet_cb)(knet_t net, ksession_t session, kvalist_t args);

struct ksession
{
	ktcp_session_t tcp_sess;
	kvalist_t msg;
	kvalist_t args;
};

struct knet
{
	ktcp_t tcp;

	knet_cb read_cb;
	knet_cb connected_cb;
	knet_cb disconnected_cb;

	kmem_pool_t mp;

	void *data;			/*user data*/

};

K_EXPORT int knet_init(knet_t *pnet, int thr, kmem_pool_t mp);

K_EXPORT int knet_uninit(knet_t net);

K_EXPORT int knet_set_cb(knet_t net, int cb_type, knet_cb cb);

K_EXPORT int knet_run_server(knet_t net, int port);

K_EXPORT int knet_send(knet_t net, ksession_t session);

K_EXPORT int knet_connect(knet_t net, int selfport, char *ip, int port);

K_EXPORT int knet_close(knet_t net, ksession_t session);


#ifdef __cplusplus
};
#endif


#endif
