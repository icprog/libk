#include "../src/k.h"

#define MSG_SIZE	4096

#ifdef _WIN32
#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif

static int total = 0;
static float avg = 0.0;
static ktcp_t t = NULL;
static ktcp_session_t sess = NULL;
static ktimer_t timer = NULL;
static ktimer_node_t node = NULL;
static char msg[MSG_SIZE] = {0};

static void
on_connected(ktcp_t t, ktcp_session_t s)
{
        printf("client connected\n");
	sess = s;
	ktcp_send(t, s, msg, MSG_SIZE);
	ktimer_add(timer, node);
}


static void
on_disconnected(ktcp_t t, ktcp_session_t s)
{
        printf("client disconnected\n");
	avg = total / 8;
}


static void
on_read(ktcp_t t, ktcp_session_t s)
{
	int len = kbuffer_readable(s->recv_buffer);
	char * p = kbuffer_read(s->recv_buffer, &len);
	total += len;
	ktcp_send(t, s, p, len);
	kbuffer_shift(s->recv_buffer, len);
	
}

static void
time_cb(ktimer_t timer, int time, int count, void *data)
{
	ktcp_close_session(t, sess);
}

int 
main()
{
	int i = 0;
	ktcp_init(&t, 1, NULL);
	ktcp_set_cb(t, KCB_CONNECTED, on_connected);
	ktcp_set_cb(t, KCB_DISCONNECTED, on_disconnected);
	ktcp_set_cb(t, KCB_READ, on_read);

	for (i = 0; i < MSG_SIZE; i++)
	{
		msg[i] = rand() % 100;
	}

	ktimer_init(&timer, 1, NULL);
	ktimer_node_init(&node, 8000, time_cb, 1, NULL);
	ktimer_start(timer);

	ktcp_start(t);
	ktcp_connect(t, 0, "127.0.0.1", 8737);

	getchar();
	ktcp_uninit(t);
	ktimer_uninit(timer);
	
	printf("avg:%f\n", avg);
	
	getchar();
	return 0;
}
