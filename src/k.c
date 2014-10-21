
#include "k.h"


static kexit_cb g_exit_cb = NULL;
static void *g_exit_arg = NULL;

#ifdef LINUX

int k_errno()
{
	return errno;
}

char *
k_strerr()
{
	return strerror(errno);
}

int
k_chbindir()
{
	char dirbuf[256] = {0};
	int c = readlink("/proc/self/exe", dirbuf, 256);
	if (0 >= c)
	{
		return 1;
	}
	int index = c - 1;
	while(dirbuf[index] != '/' && 0 != index)
	{
		dirbuf[index --] = '\0';
	}
	if(dirbuf[index] != '/')
	{
		return 1;
	}
	if (0 != index)
	{
		dirbuf[index] = '\0';
	}
	return chdir(dirbuf);
}

static void
k_core_handler(int signnum)
{
	char buf[1024]	=	{0};
	char cmd[1024]	=	{0};
	FILE * fh		=	NULL;
	sprintf(buf, "/proc/%d/cmdline", getpid());
	if(!(fh = fopen(buf, "r")))
		exit(0);
	if(!fgets(buf, sizeof(buf), fh))
		exit(0);
	fclose(fh);
	if(buf[strlen(buf) - 1] == '\n')
		buf[strlen(buf) - 1] = '\0';
	sprintf(cmd, "gdb %s %d", buf, getpid());
	system(cmd);
	signal(signnum, SIG_DFL);
}

int
k_core_dump()
{
	k_chbindir();
	struct rlimit r;
	r.rlim_cur = r.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_CORE, &r);
	getrlimit(RLIMIT_NPROC, &r);

	struct sigaction sat;
	sat.sa_flags = SA_RESETHAND;
	sat.sa_handler = k_core_handler;
	sigemptyset(&sat.sa_mask);
	sigaction(8,&sat,NULL);
	sigaction(11,&sat,NULL);

	const char * cmd	=	"echo \"core-%e-%p-%s-%t\" > /proc/sys/kernel/core_pattern";
	system(cmd);
	return 0;
}

static void
k_demon_handler(int signnum)
{
	if (SIGTERM == signnum)
	{
		printf("SIGTERM\n");
		if (g_exit_cb)
		{
			g_exit_cb(g_exit_arg);
		}
		signal(signnum, SIG_DFL);
		exit(0);
	}
}

int
k_demon()
{
	pid_t pid, sid = 0;
	struct sigaction sat;
	sat.sa_flags = SA_RESETHAND;
	sat.sa_handler = k_demon_handler;
	sigemptyset(&sat.sa_mask);
	sigaction(SIGTERM,&sat,NULL);
	pid = fork();
	if (0 > pid)
	{
		printf("fork %d\n", errno);
		exit(1);
	}
	if (0 < pid)
	{
		exit(0);
	}
	umask(0);
	sid = setsid();
	if (0 > sid)
	{
		printf("setsid %d\n", errno);
		exit(1);
	}
	close(STDIN_FILENO);
	close(STDERR_FILENO);
	return 0;
}

int
k_demon_wait(kexit_cb cb, void *arg)
{
	pthread_barrier_t barrier;
	g_exit_cb = cb;
	g_exit_arg = arg;
	pthread_barrier_init(&barrier, NULL, 2);
	pthread_barrier_wait(&barrier);
	pthread_barrier_destroy(&barrier);
	return 0;
}

//knet
int
ksock_init()
{
	struct sigaction sa;
	struct rlimit r;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, 0);

	r.rlim_cur = r.rlim_max = K_MAX_IO;
	setrlimit(RLIMIT_NOFILE, &r);
	getrlimit(RLIMIT_NOFILE, &r);
	return 0;
}

int
ksock_set_non_blocking(int fd)
{
	int opts = fcntl(fd, F_GETFL);
	if (-1 == opts)
	{
		return 1;
	}
	opts |= O_NONBLOCK;
	opts = fcntl(fd, F_SETFL, opts);
	return opts;
}

int
ksock_set_close_onexec(int fd)
{
	int opts = fcntl(fd, F_GETFL);
	if (-1 == opts)
	{
		return 1;
	}
	opts |= FD_CLOEXEC;
	opts = fcntl(fd, F_SETFL, opts);
	return opts;
}

int
ksock_shutdown(int fd, int how)
{
	if (0 != shutdown(fd, how))
	{
		//printf("shutdown :%s\n", k_strerr());
		return 1;
	}
	return 0;
}

int
ksock_close(int fd)
{
	int ret = 0;
	do 
	{
		ret = close(fd);
	} while ((-1 == ret) && (errno == EINTR));
	return ret;
}

int
ksock_ioctl(int fd, int op, int *out)
{
	if (0 != ioctl(fd, op, out))
	{
		printf("ioctl :%s\n", k_strerr());
		return 1;
	}
	return 0;
}

int
kthread_cond_timedwait(kthread_cond_t * cond, kthread_mutex_t * mutex, int timeout)
{
	struct timeval now;
	struct timespec timeOver;
	gettimeofday(&now,NULL);
	int sec				=	timeout / 1000;
	int msec			=	timeout % 1000;
	int temp_nsec		=	now.tv_usec * 1000 + msec * 1000 * 1000;
	timeOver.tv_sec		=	now.tv_sec + sec + temp_nsec / (1000 * 1000 * 1000);
	timeOver.tv_nsec	=	temp_nsec % (1000 * 1000 * 1000);
	return pthread_cond_timedwait(cond, mutex, &timeOver);
}

#else
#ifdef _WIN32

int k_errno()
{
	return GetLastError();
}

char *
k_strerr()
{
	//LPVOID lpMsgBuf;
	//FormatMessage(
	//	FORMAT_MESSAGE_ALLOCATE_BUFFER | 
	//	FORMAT_MESSAGE_FROM_SYSTEM |
	//	FORMAT_MESSAGE_IGNORE_INSERTS,
	//	NULL,
	//	GetLastError(),
	//	MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
	//	(LPTSTR) &lpMsgBuf,
	//	0,
	//	NULL   
	//	); 
	//printf("%s", lpMsgBuf);
	//LocalFree(lpMsgBuf);
	return "";
}

int
k_chbindir()
{
	char dirbuf[_MAX_PATH] = {0};
	_getcwd(dirbuf, _MAX_PATH);
	return _chdir(dirbuf);
}

static HANDLE
create_dump_file(int code)
{
	char fileBuf[MAX_PATH]	=	{0};
	char fileName[MAX_PATH]	=	{0};
	time_t curTime;
	GetModuleBaseName(GetCurrentProcess(), NULL, fileName, MAX_PATH);
	time(&curTime);
	sprintf_s(fileBuf,  MAX_PATH, "Core-%s-%d-%x-%d.dmp", fileName, GetCurrentProcessId(), code, curTime);

	return CreateFile(fileBuf, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

static void
dump_mini(HANDLE hFile, PEXCEPTION_POINTERS excpInfo)
{
	if (NULL == excpInfo)
	{
		__try
		{
			RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
		}
		__except(dump_mini(hFile, GetExceptionInformation()), EXCEPTION_CONTINUE_EXECUTION)
		{
		}
	}
	else
	{
		MINIDUMP_EXCEPTION_INFORMATION eInfo;
		eInfo.ThreadId = GetCurrentThreadId();
		eInfo.ExceptionPointers = excpInfo;
		eInfo.ClientPointers = TRUE;
		MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpNormal, excpInfo ? &eInfo : NULL, NULL, NULL);
	}
	CloseHandle( hFile );
}

static LONG WINAPI
k_core_handler(struct _EXCEPTION_POINTERS * ExceptionInfo)
{
	STACKFRAME sf;
	DWORD machineType	=	IMAGE_FILE_MACHINE_I386;
	HANDLE hProcess		=	GetCurrentProcess();
	HANDLE hThread		=	GetCurrentThread();
	HANDLE hCon	=	GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO conInfo;
	HANDLE hFile		=	create_dump_file(ExceptionInfo->ExceptionRecord->ExceptionCode);
	MINIDUMP_EXCEPTION_INFORMATION loExceptionInfo;
	loExceptionInfo.ExceptionPointers	=	ExceptionInfo;
	loExceptionInfo.ThreadId			=	GetCurrentThreadId();
	loExceptionInfo.ClientPointers		=	TRUE;
	MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpNormal, &loExceptionInfo, NULL, NULL);
	CloseHandle(hFile);
	printf("unhandle exception\n");
	SymInitialize(GetCurrentProcess(), NULL, TRUE);
	memset(&sf, 0, sizeof(STACKFRAME));

	sf.AddrPC.Offset	=	ExceptionInfo->ContextRecord->Eip;
	sf.AddrPC.Mode		=	AddrModeFlat;
	sf.AddrStack.Offset	=	ExceptionInfo->ContextRecord->Esp;
	sf.AddrStack.Mode	=	AddrModeFlat;
	sf.AddrFrame.Offset	=	ExceptionInfo->ContextRecord->Ebp;
	sf.AddrFrame.Mode	=	AddrModeFlat;

	GetConsoleScreenBufferInfo(hCon, &conInfo);
	SetConsoleTextAttribute(hCon, FOREGROUND_RED | FOREGROUND_INTENSITY);

	for( ; ; )
	{
		BYTE symbolBuffer[ sizeof( SYMBOL_INFO ) + 1024 ];
		PSYMBOL_INFO pSymbol	=	( PSYMBOL_INFO ) symbolBuffer;
		DWORD64 symDisplacement	=	0;
		IMAGEHLP_LINE lineInfo	=	{ sizeof(IMAGEHLP_LINE) };
		DWORD dwLineDisplacement;

		if(!StackWalk(machineType, hProcess, hThread, &sf, ExceptionInfo->ContextRecord, 0, SymFunctionTableAccess, SymGetModuleBase, 0))
		{
			break;
		}

		if(0 == sf.AddrFrame.Offset)
		{
			break;
		}
		pSymbol->SizeOfStruct	=	sizeof(symbolBuffer);
		pSymbol->MaxNameLen		=	1024;
		if( SymFromAddr(hProcess, sf.AddrPC.Offset, 0, pSymbol))
		{
			printf("Function : %s\n", pSymbol->Name);
		}

		if(SymGetLineFromAddr(hProcess, sf.AddrPC.Offset, &dwLineDisplacement, &lineInfo))
		{
			printf("[%s][%d]\n", lineInfo.FileName, lineInfo.LineNumber);
		}
	}
	SetConsoleTextAttribute(hCon, conInfo.wAttributes);
	SymCleanup(GetCurrentProcess());
	getchar();
	return EXCEPTION_EXECUTE_HANDLER;
}

int
k_core_dump()
{
	k_chbindir();
	SetUnhandledExceptionFilter(k_core_handler);
	return 0;
}

int
k_demon()
{

	return 0;
}

int
k_demon_wait(kexit_cb cb, void *arg)
{
	g_exit_cb = cb;
	g_exit_arg = arg;
	return 0;
}

int
ksock_init()
{
	WSADATA wsaData;
	if (0 != WSAStartup(0x0202, &wsaData))
	{
		printf("WSAStartup :%d\n", k_errno());
		return 1;
	}
	return 0;
}

int
ksock_set_non_blocking(int fd)
{
	unsigned long on = 1;
	return ioctlsocket(fd, FIONBIO, (unsigned long *)&on);
}

int
ksock_set_close_onexec(int fd)
{
	return 0;
}

int
ksock_shutdown(int fd, int how)
{
	if (0 != shutdown(fd, how))
	{
		//printf("shutdown :%d\n", k_errno());
		return 1;
	}
	return 0;
}

int
ksock_close(int fd)
{
	closesocket(fd);
	return 0;
}


int
ksock_ioctl(int fd, int op, int *out)
{
	if (0 != ioctlsocket(fd, op, out))
	{
		printf("ioctlsocket :%d\n", k_errno());
		return 1;
	}
	return 0;
}

int
kthread_mutex_init(kthread_mutex_t * mutex, void * attr)
{
	*mutex = CreateMutex(NULL, FALSE, NULL);
	return NULL == *mutex ? GetLastError() : 0;
}

int
kthread_mutex_destroy(kthread_mutex_t * mutex)
{
	int ret = CloseHandle(*mutex);
	return 0 == ret ? GetLastError() : 0;
}

int
kthread_mutex_lock(kthread_mutex_t * mutex)
{
	int ret = WaitForSingleObject(*mutex, INFINITE);
	return WAIT_OBJECT_0 == ret ? 0 : GetLastError();
}

int
kthread_mutex_unlock(kthread_mutex_t * mutex)
{
	int ret = ReleaseMutex(*mutex);
	return 0 != ret ? 0 : GetLastError();
}

int
kthread_cond_init(kthread_cond_t * cond, void * attr)
{
	*cond = CreateEvent(NULL, TRUE, FALSE, NULL);
	return NULL == *cond ? GetLastError() : 0;
}

int
kthread_cond_destroy(kthread_cond_t * cond)
{
	int ret = CloseHandle(*cond);
	return 0 == ret ? GetLastError() : 0;
}

int
kthread_cond_wait(kthread_cond_t * cond, kthread_mutex_t * mutex)
{
	int ret = 0;
	kthread_mutex_unlock(mutex);
	ret	= WaitForSingleObject(*cond, INFINITE);
	ResetEvent(*cond);
	kthread_mutex_lock( mutex );
	return WAIT_OBJECT_0 == ret ? 0 : GetLastError();
}

int
kthread_cond_timedwait(kthread_cond_t * cond, kthread_mutex_t * mutex, int timeout)
{
	int ret = 0;
	kthread_mutex_unlock(mutex);
	ret	= WaitForSingleObject(*cond, timeout);
	ResetEvent(*cond);
	kthread_mutex_lock( mutex );
	return ret;
}

int
kthread_cond_signal(kthread_cond_t * cond)
{
	int ret = SetEvent(*cond);
	return 0 == ret ? GetLastError() : 0;
}

int
kthread_cond_broadcast(kthread_cond_t * cond)
{
	int ret = PulseEvent(*cond);
	return 0 == ret ? GetLastError() : 0;
}

int 
kthread_rwlock_init(kthread_rwlock_t rwlock, void * attr)
{
	return kthread_mutex_init(rwlock, attr);
}

int 
kthread_rwlock_destroy(kthread_rwlock_t rwlock)
{
	return kthread_mutex_destroy(rwlock);
}

int 
kthread_rwlock_rdlock(kthread_rwlock_t rwlock)
{
	return kthread_mutex_lock(rwlock);
}

int 
kthread_rwlock_wrlock(kthread_rwlock_t rwlock)
{
	return kthread_mutex_lock(rwlock);
}

int 
kthread_rwlock_unlock(kthread_rwlock_t rwlock)
{
	return kthread_mutex_unlock(rwlock);
}

int
kthread_join(kthread_t tid, kthread_attr_t * attr)
{
	HANDLE h = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	return (int)WaitForSingleObject(h, INFINITE);
}

kthread_t
kthread_self()
{
	return GetCurrentThreadId();
}

int
kthread_attr_init(kthread_attr_t * attr)
{
	*attr = 0;
	return 0;
}

int
kthread_attr_setdetachstate(kthread_attr_t * attr, int detachstate)
{
	*attr |= detachstate;
	return 0;
}

int
kthread_create(kthread_t * thread, kthread_attr_t * attr, kthread_func_t threadfun, void * args)
{
	HANDLE h = (HANDLE)_beginthreadex(NULL, 0, threadfun, args, 0, thread);
	return h > 0 ? 0 : GetLastError();
}

#endif

#endif


/************************************************************************/
/*				kmem                                                    */
/************************************************************************/

typedef struct kmem_node kmem_node, *kmem_node_t;

struct kmem_node
{
	void *data;
	int size;
	char * file;
	int line;
	char * name;
	kmem_node_t next;
};

typedef struct kmem_list kmem_list, *kmem_list_t;
struct kmem_list
{
	kmem_node_t head;
	kmem_node_t tail;

	kthread_mutex_t mtx;
};

typedef void (*kmem_for_each_cb)(void *data);

static int
kmem_list_init(kmem_list_t *plist)
{
	(*plist) = malloc(sizeof(kmem_list));
	if (NULL == (*plist))
	{
		return 1;
	}
	(*plist)->head = (*plist)->tail = NULL;
	kthread_mutex_init(&(*plist)->mtx, NULL);
	return 0;
}

static int
kmem_list_uninit(kmem_list_t list)
{
	kthread_mutex_destroy(&list->mtx);
	free(list);
	return 0;
}

static int
kmem_list_push(kmem_list_t list, void *node)
{
	kthread_mutex_lock(&list->mtx);
	if (NULL == list->head)
	{
		list->head = list->tail = node;
	}
	else
	{
		list->tail->next = node;
		list->tail = node;
	}
	kthread_mutex_unlock(&list->mtx);
	return 0;
}

static int
kmem_list_erase(kmem_list_t list, void *p)
{
	kmem_node_t node = NULL;
	kmem_node_t tmp = NULL;
	kthread_mutex_lock(&list->mtx);
	node = list->head;
	if (NULL == node)
	{
		kthread_mutex_unlock(&list->mtx);
		return 1;
	}
	if (node->data == p)
	{
		list->head = node->next;
		if (NULL == list->head)
		{
			list->tail = list->head = NULL;
		}
		free(node);
		kthread_mutex_unlock(&list->mtx);
		return 0;
	}
	while (node->next)
	{
		tmp = node->next;
		if (tmp->data == p)
		{
			node->next = tmp->next;
			if (NULL == node->next)
			{
				list->tail = node;
			}
			free(tmp);
			kthread_mutex_unlock(&list->mtx);
			return 0;
		}
		node = node->next;
	}
	kthread_mutex_unlock(&list->mtx);
	return 1;
}

static void
kmem_list_for_each(kmem_list_t list, kmem_for_each_cb cb)
{
	kmem_node_t node = NULL;
	kthread_mutex_lock(&list->mtx);
	node = list->head;
	while (node)
	{
		cb(node);
		node = node->next;
	}
	kthread_mutex_unlock(&list->mtx);
}

static kmem_list_t mem_list;

void *
k_real_alloc(void * p, int size, char * file, int line, char * name)
{
	void *newp = NULL;
	kmem_node_t node = NULL;
	if (0 >= size)
	{
		return NULL;
	}
	newp = realloc(p, size);
	if (NULL == newp)
	{
		return NULL;
	}
	if (NULL == p)
	{
		memset(newp, 0, size);
	}
	if (mem_list)
	{
		if (NULL != p)
		{
			k_real_free(p, 0);
		}
		node = malloc(sizeof(kmem_node));
		if (NULL == node)
		{
			free(newp);
			return NULL;
		}
		node->data = newp;
		node->size = size;
		node->file = file;
		node->line = line;
		node->name = name;
		node->next = NULL;
		if (0 != kmem_list_push(mem_list, node))
		{
			printf("kmem_list_push 0x%x\n", (uint)newp);
			free(newp);
			free(node);
			return NULL;
		}
	}
	//	printf("%s alloc:0x%x, size:%d, file:%s, line:%d\n", name, (uint)newp, size, file, line);
	return newp;
}


void *
kmalloc_wrap(kmem_pool_t mp, uint size, char * file, int line, char * name)
{
	void *p = NULL;
	if (NULL != mp)
	{
		p = kmempool_alloc(mp, size);
	}
	else
	{
		p = k_real_alloc(0, size, file, line, name);
	}
	if (NULL == p)
	{
		printf("kmalloc_wrap mp:%d, size:%d, file:%s, line:%d, name:%s\n", (int)mp, size, file, line, name);
	}
	return p;
}

void *
krealloc_wrap(kmem_pool_t mp, void *old, uint oldsize, uint size, char * file, int line, char * name)
{
	void *p = NULL;
	if (NULL != mp)
	{
		p = kmempool_realloc(mp, old, oldsize, size);
	}
	else
	{
		p = k_real_alloc(old, size, file, line, name);
	}
	if (NULL == p)
	{
		printf("krealloc_wrap mp:%d, size:%d, file:%s, line:%d, name:%s\n", (int)mp, size, file, line, name);
	}
	return p;
}

void 
kfree_wrap(kmem_pool_t mp, void *p)
{
	if (NULL != mp)
	{
		kmempool_free(mp, p);
	} 
	else
	{
		k_real_free(p, 1);
	}
}


void
k_real_free(void *p, int isreal)
{
	if (NULL == p)
	{
		return;
	}
	if (mem_list)
	{
		if (0 != kmem_list_erase(mem_list, p))
		{
			printf("kmem_list_erase :0x%x\n", (uint)p);
		}
	}
	//printf("free:0x%x\n", (uint)p);
	if (1 == isreal)
	{
		free(p);
	}
}

void
kmem_check_start()
{
	if (0 != kmem_list_init(&mem_list))
	{
		printf("kmem_list_init failed!\n");
	}
	printf("kmem_check_start\n");
}

void
kmem_check_stop()
{
	kmem_list_uninit(mem_list);
	printf("kmem_check_stop\n");
}

static void
kmem_print_leak(void *data)
{
	kmem_node_t node = (kmem_node_t)data;
	if (NULL == node)
	{
		return;
	}
	printf("memory:0x%x size:%d name:%s file:%s line:%d\n", (int)node->data, node->size, node->name, node->file, node->line);
}


void
kmem_check_leak()
{
	printf("start check leak\n");
	kmem_list_for_each(mem_list, kmem_print_leak);
	printf("end check leak\n");
}



/************************************************************************/
/*				kblist                                                  */
/************************************************************************/

int
klist_push(klist_t list, void *data)
{
	klist_node_t node = NULL;
	if (NULL == list || NULL == data)
	{
		return 1;
	}
	node = kalloc_t(list->mp, klist_node);
	if (NULL == node)
	{
		return 1;
	}
	node->data = data;
	node->next = NULL;
	if (NULL == list->tail)
	{
		list->head = list->tail = node;
	}
	else
	{
		list->tail->next = node;
		list->tail = node;
	}
	list->size ++;
	return 0;
}

void *
klist_pop(klist_t list)
{
	void *data = NULL;
	klist_node_t node = NULL;
	if (NULL == list)
	{
		return NULL;
	}
	if (NULL == list->head)
	{
		return NULL;
	}
	node = list->head;
	list->head = node->next;
	list->size --;
	data = node->data;
	kfree(list->mp, node);
	return data;
}

void * 
klist_front(klist_t list)
{
	return list->head->data;
}

int
klist_find(klist_t list, void *data)
{
	klist_node_t node = NULL;
	node = list->head;
	while (node)
	{
		if (node->data == data)
		{
			return 0;
		}
		node = node->next;
	}
	return 1;
}

int 
klist_size(klist_t list)
{
	return list->size;
}

int
klist_erase(klist_t list, void *data)
{
	klist_node_t node = NULL;
	node = list->head;
	if (NULL == node)
	{
		return 1;
	}
	if (node->data == data)
	{
		list->head = node->next;
		if (NULL == list->head)
		{
			list->tail = list->head;
		}
		kfree(list->mp, node);
		list->size --;
		return 0;
	}
	while (node->next)
	{
		if (node->next->data == data)
		{
			klist_node_t tmpnode = node->next;
			node->next = tmpnode->next;
			kfree(list->mp, tmpnode);
			list->size --;
			return 0;
		}
		node = node->next;
	}
	return 1;
}

int 
klist_clear(klist_t list)
{
	klist_node_t node = NULL;
	klist_node_t tmp_node = NULL;
	node = list->head;
	while (node)
	{
		tmp_node = node->next;
		kfree(list->mp, node);
		node = tmp_node;
	}
	list->head = list->tail = NULL;
	list->size = 0;
	return 0;
}

void
klist_foreach(klist_t list, klist_foreach_cb cb, void *p)
{
	klist_node_t node = NULL;
	node = list->head;
	while (node)
	{
		if (0 != cb(node->data, p))
		{
			break;
		}
		node = node->next;
	}
}

int
klist_init(klist_t *plist, kmem_pool_t mp)
{
	(*plist) = kalloc_t(mp, klist);
	if (NULL == (*plist))
	{
		return 1;
	}
	(*plist)->head = (*plist)->tail = NULL;
	(*plist)->mp = mp;
	(*plist)->size = 0;
	return 0;
}

int
klist_uninit(klist_t list)
{
	klist_clear(list);
	kfree(list->mp, list);
	return 0;
}


//khb_list
/************************************************************************/
/*				khblist                                                 */
/************************************************************************/

int
khb_list_init(khb_list_t *plist, kmem_pool_t mp)
{
	(*plist) = kalloc_t(mp, khb_list);
	if (NULL == (*plist))
	{
		return 1;
	}
	(*plist)->mp = mp;
	(*plist)->head = kalloc_t(mp, klist_node);
	if (NULL == (*plist)->head)
	{
		kfree(mp, *plist);
		return 1;
	}
	(*plist)->head->data = NULL;
	(*plist)->head->next = NULL;
	(*plist)->tail = (*plist)->head;
	kthread_mutex_init(&(*plist)->head_mtx, NULL);
	kthread_mutex_init(&(*plist)->tail_mtx, NULL);
	kthread_cond_init(&(*plist)->list_cond, NULL);
	return 0;
}

int
khb_list_uninit(khb_list_t list)
{
	klist_node_t tmp_node = NULL;
	klist_node_t head_node = NULL;
	if (NULL == list)
	{
		return 1;
	}
	kthread_mutex_lock(&list->tail_mtx);
	kthread_cond_signal(&list->list_cond);
	kthread_mutex_unlock(&list->tail_mtx);

	head_node = list->head;
	while (head_node)
	{
		tmp_node = head_node;
		head_node = tmp_node->next;
		kfree(list->mp, tmp_node);
	}
	kthread_mutex_destroy(&list->head_mtx);
	kthread_mutex_destroy(&list->tail_mtx);
	kthread_cond_destroy(&list->list_cond);
	kfree(list->mp, list);
	return 0;
}

int
khb_list_push(khb_list_t list, void *data)
{
	klist_node_t node = NULL;
	if (NULL == list || NULL == data)
	{
		return 1;
	}
	kthread_mutex_lock(&list->tail_mtx);
	node = kalloc_t(list->mp, klist_node);
	if (NULL == node)
	{
		kthread_mutex_unlock(&list->tail_mtx);
		return 1;
	}
	node->data = data;
	node->next = NULL;
	list->tail->next = node;
	list->tail = node;
	kthread_cond_signal(&list->list_cond);
	kthread_mutex_unlock(&list->tail_mtx);
	return 0;
}

void *
khb_list_pop(khb_list_t list)
{
	void *data = NULL;
	klist_node_t node = NULL;
	if (NULL == list)
	{
		printf("NULL == list\n");
		return NULL;
	}
	kthread_mutex_lock(&list->head_mtx);
	if (NULL == list->head)
	{
		kthread_mutex_unlock(&list->head_mtx);
		printf("NULL == list->head\n");
		return NULL;
	}
	if (NULL == list->head->next)
	{
		kthread_cond_wait(&list->list_cond, &list->head_mtx);
	}

	if (NULL != list->head->next)
	{
		node = list->head;
		node->data = node->next->data;
		list->head = node->next;
	}
	if (node)
	{
		data = node->data;
		kfree(list->mp, node);
	}
	kthread_mutex_unlock(&list->head_mtx);
	return data;
}

void
khb_list_broadcast(khb_list_t list)
{
	kthread_cond_broadcast(&list->list_cond);
}


/************************************************************************/
/*				ktask                                                   */
/************************************************************************/

int
ktask_init(ktask_t * ptask, ktask_cb cb, void * args, kmem_pool_t mp)
{
	(*ptask) = kalloc_t(mp, ktask);
	if (NULL == *ptask)
	{
		return 1;
	}
	(*ptask)->mp = mp;
	(*ptask)->cb = cb;
	(*ptask)->args = args;
	(*ptask)->next = NULL;
	return 0;
}

int
ktask_uninit(ktask_t task)
{
	kfree(task->mp, task);
	return 0;
}

/************************************************************************/
/*				knet                                                    */
/************************************************************************/

int 
ksock_from_addr(struct sockaddr_in addr_in, char *ip, int *pport)
{
	strcpy(ip, inet_ntoa(addr_in.sin_addr));
	*pport = ntohs(addr_in.sin_port);
	return 0;
}

int 
ksock_to_addr(struct sockaddr_in *addr_in, char *ip, int port)
{
	addr_in->sin_family = AF_INET;
	addr_in->sin_port = htons(port);
	addr_in->sin_addr.s_addr = inet_addr(ip);
	return 0;
}

int
ksock_set_reuse(int fd)
{
	int on = 1;
	if (-1 == setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on)))
	{
		printf("setsockopt SO_KEEDALIVE :%d, fd:%d\n", k_errno(), fd);
		return 1;
	}
	return 0;
}

int
ksock_set_sendbuf(int fd, int buff)
{
	if (-1 == setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void*)&buff, sizeof(buff)))
	{
		printf("setsockopt SO_SNDBUF :%d, fd:%d\n", k_errno(), fd);
		return 1;
	}
	return 0;
}

int
ksock_set_alive(int fd, int idle, int intval, int cnt)
{
	int on = 1;
	if (-1 == setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&on, sizeof(on)))
	{
		printf("setsockopt SO_KEEDALIVE :%d, fd:%d\n", k_errno(), fd);
		return 1;
	}
#ifdef WIN32
	{
		struct tcp_keepalive setting;
		struct tcp_keepalive ret;
		int byteret = 0;
		setting.onoff = 1;
		setting.keepalivetime = idle * 1000;
		setting.keepaliveinterval = intval * 1000;
		if (-1 == WSAIoctl(fd, SIO_KEEPALIVE_VALS, &setting, sizeof(setting), &ret, sizeof(ret), &byteret, NULL, NULL))
		{
			printf("WSAIoctl SIO_KEEPALIVE_VALS :%d, fd:%d\n", k_errno(), fd);
			return 1;
		}
	}
#else
	if (-1 == setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, (const char *)&idle, sizeof(idle)))
	{
		printf("setsockopt TCP_KEEPIDLE :%d, fd:%d\n", k_errno(), fd);
		return 1;
	}
	if (-1 == setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, (const char *)&intval, sizeof(intval)))
	{
		printf("setsockopt TCP_KEEPINTVL :%d, fd:%d\n", k_errno(), fd);
		return 1;
	}
	if (-1 == setsockopt(fd, SOL_TCP, TCP_KEEPCNT, (const char *)&cnt, sizeof(cnt)))
	{
		printf("setsockopt TCP_KEEPCNT :%d, fd:%d\n", k_errno(), fd);
		return 1;
	}
#endif
	return 0;
}

int
ksock_init_fd()
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (-1 == fd)
	{
		printf("socket :%d\n", k_errno());
		return -1;
	}
	if (0 != ksock_set_reuse(fd))
	{
		return -1;
	}
	return fd;
}

int
ksock_bind(int fd, int port)
{
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (-1 == bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)))
	{
		printf("bind :%d\n", k_errno());
		return 1;
	}
	return 0;
}

int
ksock_listen_at(int fd, int port)
{
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (-1 == bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)))
	{
		printf("bind :%d\n", k_errno());
		return 1;
	}
	if (-1 == listen(fd, SOMAXCONN))/*511 from ngx and redis*/
	{
		printf("listen :%d\n", k_errno());
		return 1;
	}
	return 0;
}

int
ksock_accept(int fd, char *ip, int *pport)
{
	struct sockaddr_in addr_in;
	socklen_t len = sizeof(struct sockaddr_in);
	int newfd = accept(fd, (struct sockaddr *)&addr_in, &len);
	if (-1 == newfd)
	{
		printf("accept :%d, fd:%d\n", k_errno(), fd);
		return -1;
	}
	strcpy(ip, inet_ntoa(addr_in.sin_addr));
	*pport = ntohs(addr_in.sin_port);
	return newfd;
}

int
ksock_connect(int fd, char * ip, int port)
{
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);
	if (-1 == connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)))
	{
		printf("connect :%d\n", k_errno());
		return 1;
	}
	return 0;
}


/************************************************************************/
/*				kthreadpool                                             */
/************************************************************************/

struct kthreadpool
{
	int isrunning;
	int threadnum;
	kthread_t * threads;
	khb_list_t task_list;
	kmem_pool_t mp;

	void *data;			/*user data*/
};

static kthread_result_t KTHREAD_CALL
thread_fun(void * args)
{
	ktask_t poptask = NULL;
	kthreadpool_t threadpool = (kthreadpool_t)args;
	if (NULL == threadpool)
	{
		return 0;
	}
	while (katomic_get(threadpool->isrunning))
	{
		poptask = khb_list_pop(threadpool->task_list);
		if (NULL == poptask)
		{
			continue;
		}
		if (NULL != poptask)
		{
			poptask->cb(poptask->args);
			kfree(threadpool->mp, poptask);
		}
	}
	printf("thread exit:%d\n", (int)kthread_self());
	return 0;
}

int
kthreadpool_init(kthreadpool_t * pthreadpool, int threadnum, kmem_pool_t mp)
{
	if (0 >= threadnum)
	{
		return 1;
	}
	*pthreadpool = kalloc_t(mp, kthreadpool);
	if (NULL == *pthreadpool)
	{
		return 1;
	}
	(*pthreadpool)->mp = mp;
	(*pthreadpool)->threadnum = threadnum;
	(*pthreadpool)->threads = kalloc(mp, threadnum * sizeof(kthread_t));
	if (0 != khb_list_init(&(*pthreadpool)->task_list, mp))
	{
		kfree(mp, *pthreadpool);
		return 1;
	}
	return 0;
}

int 
kthreadpool_set_data(kthreadpool_t threadpool, void * data)
{
	threadpool->data = data;
	return 0;
}

void *
kthreadpool_get_data(kthreadpool_t threadpool)
{
	return threadpool->data;
}

int
kthreadpool_start(kthreadpool_t threadpool)
{
	int i = 0;
	if (NULL == threadpool)
	{
		return 1;
	}
	if (1 == katomic_get(threadpool->isrunning))
	{
		return 0;
	}
	katomic_set(threadpool->isrunning, 1);

	for (i = 0; i < threadpool->threadnum; ++i)
	{
		kthread_t tid;
		if (0 != kthread_create(&tid, NULL, thread_fun, (void *)threadpool))
		{
			printf("kthread_create %d\n", (int)kthread_self());
			continue;
		}
		threadpool->threads[i] = tid;
		printf("kthread_create :%d\n", (int)tid);
	}
	return 0;
}

int 
kthreadpool_isrunning(kthreadpool_t threadpool)
{
	return katomic_get(threadpool->isrunning);
}

int
kthreadpool_run(kthreadpool_t threadpool, ktask_cb cb, void * args)
{
	ktask_t task = NULL;
	if (NULL == threadpool || NULL == cb)
	{
		return 1;
	}
	if (0 != ktask_init(&task, cb, args, threadpool->mp))
	{
		return 1;
	}
	if (0 != khb_list_push(threadpool->task_list, task))
	{
		return 1;
	}
	return 0;
}

int
kthreadpool_uninit(kthreadpool_t threadpool)
{
	int i = 0;
	if (NULL == threadpool)
	{
		return 1;
	}
	katomic_set(threadpool->isrunning, 0);

	khb_list_broadcast(threadpool->task_list);

	for (i = 0; i < threadpool->threadnum; ++i)
	{
		kthread_join(threadpool->threads[i], NULL);
	}

	kfree(threadpool->mp, threadpool->threads);

	khb_list_uninit(threadpool->task_list);

	kfree(threadpool->mp, threadpool);
	return 0;
}


//kmempool
/************************************************************************/
/*				kmempool                                                */
/************************************************************************/

typedef struct kmem_pool_large kmem_pool_large, *kmem_pool_large_t;

typedef struct kmem_chain kmem_chain, *kmem_chain_t;

typedef struct kmem_pool_data kmem_pool_data, *kmem_pool_data_t;

struct kmem_pool_data
{
	char *last;			/*last used pos*/
	char *end;			/*cur pool end*/
	kmem_pool_t next;
	uint failed;
};

struct kmem_pool_large
{
	kmem_pool_large_t next;
	void *data;			/*large data*/
};

struct kmem_chain
{
	kmem_chain_t next;
	char *data;
};

struct kmem_pool
{
	kmem_pool_data data;
	uint max;
	kmem_pool_t current;
	kmem_chain_t chain;
	kmem_pool_large_t large;
};

static void *
kmempool_block(kmem_pool_t pool, uint size)
{
	kmem_pool_t p, pnew, current;

	uint psize = pool->data.end - (char *)pool;

	char *m = (char *)malloc(psize);
	if (NULL == m)
	{
		return	NULL;
	}
	memset(m, 0, psize);
	pnew = (kmem_pool_t)m;
	pnew->data.end = m + psize;
	pnew->data.next = NULL;
	pnew->data.failed = 0;
	m += sizeof(kmem_pool_data);
	pnew->data.last = m + size;

	current = pool->current;
	for (p = current; p->data.next; p = p->data.next) 
	{
		if (p->data.failed++ > 4) 
		{
			current = p->data.next;
		}
	}
	p->data.next = pnew;
	pool->current = current ? current : pnew;
	return m;
}

static void *
kmempool_large(kmem_pool_t pool, uint size)
{
	uint n = 0;
	kmem_pool_large_t large = NULL;

	void *p = malloc(size);
	if (p == NULL) 
	{
		return NULL;
	}
	memset(p, 0, size);
	for (large = pool->large; large; large = large->next) 
	{
		if (NULL == large->data) 
		{
			large->data = p;
			return p;
		}
		if (n++ > 3)
		{
			break;
		}
	}
	large = kmempool_alloc(pool, sizeof(kmem_pool_large));
	if (NULL == large)
	{
		free(p);
		return NULL;
	}
	large->data = p;
	large->next = pool->large;
	pool->large = large;
	return p;
}

int 
kmempool_init(kmem_pool_t *ppool, uint size)
{
	*ppool = (kmem_pool_t)malloc(size);
	if (NULL == *ppool)
	{
		return 1;
	}
	(*ppool)->data.last = (char *)(*ppool) + sizeof(kmem_pool);
	(*ppool)->data.end = (char *)(*ppool) + size;
	(*ppool)->data.next = NULL;
	(*ppool)->data.failed = 0;

	size = size - sizeof(kmem_pool);
	(*ppool)->max = size;
	(*ppool)->current = (*ppool);
	(*ppool)->chain = NULL;
	(*ppool)->large = NULL;
	return 0;
}

int 
kmempool_uninit(kmem_pool_t pool)
{
	kmem_pool_t p, n;
	kmem_pool_large_t l = NULL;

	for (l = pool->large; l; l = l->next) 
	{
		if (l->data) 
		{
			free(l->data);
		}
	}

	for (p = pool, n = pool->data.next; ; p = n, n = n->data.next) 
	{
		free(p);
		if (NULL == n)
		{
			break;
		}
	}
	return 0;
}

void *
kmempool_alloc(kmem_pool_t pool, uint size)
{
	if (size <= pool->max)
	{
		char* m = NULL;
		kmem_pool_t p = pool->current;
		do 
		{
			m = p->data.last;
			if ((uint)(p->data.end - m) >= size) 
			{
				p->data.last = m + size;
				memset(m, 0, size);
				return m;
			}
			p = p->data.next;
		} while (p);
		return kmempool_block(pool, size);
	}
	return kmempool_large(pool, size);
}

void *
kmempool_realloc(kmem_pool_t pool, void *old, uint oldsize, uint size)
{
	void *newp = NULL;
	if (NULL == old)
	{
		return kmempool_alloc(pool, size);
	}
	if (0 == size)
	{
		if ((char *)old + oldsize == pool->data.last)
		{
			pool->data.last = old;
		}
		else
		{
			kmempool_free(pool, old);
		}
		return NULL;
	}

	if ((char *)old + oldsize == pool->data.last && (char *)old + size <= pool->data.end)
	{
		pool->data.last = (char *)old + size;
		return old;
	}
	newp = kmempool_alloc(pool, size);
	if (NULL == newp)
	{
		return NULL;
	}
	memcpy(newp, old, oldsize);
	kmempool_free(pool, old);
	return newp;
}

int 
kmempool_free(kmem_pool_t pool, void *data)
{	
	kmem_pool_large_t l = NULL;
	if (NULL == data)
	{
		return 1;
	}
	for (l = pool->large; l; l = l->next)
	{
		if (data == l->data)
		{
			free(l->data);
			l->data = NULL;
			break;
		}
	}
	return 0;
}



/************************************************************************/
/*         kev lib                                                      */
/************************************************************************/

enum
{
	K_OP_NON		=	0,
	K_OP_ADD		=	1,
	K_OP_MOD		=	2,
	K_OP_DEL		=	3,
};

typedef struct kev_fd kev_fd, *kev_fd_t;

typedef struct kevloop_task kevloop_task, *kevloop_task_t;

typedef void (* kpoll_poll)(kevloop_t evloop);

typedef void (* kpoll_init)(kevloop_t evloop);

typedef void (* kpoll_modify)(kevloop_t evloop, int fd, int op);

typedef void (* kpoll_uninit)(kevloop_t evloop);

struct kev
{
	int fd;
	int event;			/*event handle for*/
	kevloop_cb cb;		/*callback when event*/
	kev_t next;
	kev_t prev;
	kmem_pool_t mp;
	void * data;		/*user data*/
};


struct kev_fd
{
	kev_t head;
	int events;			/*events on the fd*/
};

struct kevloop_task
{
	kevloop_cb cb;
	kev_t ev;
	kevloop_task_t next;
};

struct kevloop
{
	kthread_t tid;			/*thread id the loop run in*/
	kev_fd_t * evfds;
	kev_t * actevs;
	kevent_t event;

	kevloop_task_t head;
	kevloop_task_t tail;
	kthread_mutex_t mtx;

	kmem_pool_t mp;

	int poll_fd;
	int weakup_fd;

	/*for select module*/
	fd_set readfds;
	fd_set writefds;
	struct sockaddr_in weakupaddr;

	kpoll_modify modify;
	kpoll_poll poll;
	kpoll_uninit uninit;
};

struct kevent
{
	int threadnum;
	int isrunning;
	kevloop_t * loops;
	kthread_t * threads;
	int loop_index;				/*cycle loop*/

	void * data;		/*user data*/
};


static void
kevloop_handle_evs(kevloop_t evloop)
{
	int i = 0;
	kev_t ev = NULL;
	for (i = 0; i < EV_MAX; ++i)
	{
		ev = evloop->actevs[i];
		if (ev)
		{
			ev->cb(evloop, ev);
			evloop->actevs[i] = NULL;
		}
	}
}

static void
kevloop_add_ev(kevloop_t evloop, kev_t ev)
{
	int op = K_OP_NON;
	kev_t tmpev = NULL;
	if (NULL == evloop->evfds[ev->fd])
	{
		evloop->evfds[ev->fd] = kalloc_t(evloop->mp, kev_fd);
		if (NULL == evloop->evfds[ev->fd])
		{
			kfree(evloop->mp, ev);
			return;
		}
	}
	if (NULL == evloop->evfds[ev->fd]->head)
	{
		op = K_OP_ADD;
	}
	else
	{
		op = K_OP_MOD;
	}
	if (1 == (ev->event & evloop->evfds[ev->fd]->events))
	{
		op = K_OP_NON;
	}
	tmpev = evloop->evfds[ev->fd]->head;
	if (NULL == tmpev)
	{
		evloop->evfds[ev->fd]->head = ev;
	}
	else
	{
		while (tmpev->next)
		{
			tmpev = tmpev->next;
		}
		tmpev->next = ev;
	}
	evloop->evfds[ev->fd]->events |= ev->event;
	evloop->modify(evloop, ev->fd, op);
}


static void
kevloop_remove_ev(kevloop_t evloop, kev_t ev)
{
	int op = K_OP_NON;
	kev_t tmpev = NULL;
	int oevents = 0;
	if (NULL == evloop->evfds[ev->fd])
	{
		kfree(evloop->mp, ev);
		return;
	}
	tmpev = evloop->evfds[ev->fd]->head;
	if (NULL == tmpev)
	{
		kfree(evloop->mp, ev);
		return;
	}
	oevents = evloop->evfds[ev->fd]->events;
	evloop->evfds[ev->fd]->events &= ~ev->event;
	if (tmpev == ev)
	{
		evloop->evfds[ev->fd]->head = ev->next;
	}
	else
	{
		evloop->evfds[ev->fd]->events |= tmpev->event;
	}
	while (tmpev->next)
	{
		if (tmpev->next == ev)
		{
			tmpev->next = ev->next;
		}
		else
		{
			evloop->evfds[ev->fd]->events |= tmpev->next->event;
			tmpev->next = tmpev->next->next;
		}
	}
	if (oevents != evloop->evfds[ev->fd]->events)
	{
		op = K_OP_MOD;
	}
	if (0 == evloop->evfds[ev->fd]->events)
	{
		op = K_OP_DEL;
	}
	evloop->modify(evloop, ev->fd, op);
	kfree(evloop->mp, ev);
	return;
}

static int kevloop_run(kevloop_t evloop, kevloop_cb cb, kev_t ev);

#ifdef LINUX
/************************************************************************/
/*				linux poll                                              */
/************************************************************************/

//kev_epoll.c
#include <sys/epoll.h>
#include <fcntl.h>

#define EPOLL_MAX_EV	64

static void
epoll_poll(kevloop_t evloop)
{
	int i = 0;
	int j = 0;
	int fd = 0;
	struct epoll_event events[EPOLL_MAX_EV];
	int evnum = epoll_wait(evloop->poll_fd, events, EPOLL_MAX_EV, -1);
	//printf("evnum:%d\n", evnum);
	for (i = 0; i < evnum; ++i)
	{
		j = 0;
		struct epoll_event ev = events[i];
		fd = ev.data.fd;
		kev_fd_t evfd = evloop->evfds[fd];
		if (NULL == evfd)
		{
			printf("NULL == evfd\n");
			continue;
		}
		kev_t tmpev = evfd->head;
		if (NULL == tmpev)
		{
			printf("NULL == tmpev\n");
			continue;
		}
		if (fd != tmpev->fd)
		{
			printf("fd:%d, tmpev->fd:%d, evfd->events:%d\n", fd, tmpev->fd, evfd->events);
			continue;
		}
		do
		{
			if (0 == ev.events)
			{
				printf("0 == ev.events\n");
			}
			if (tmpev->event & ev.events)
			{
				evloop->actevs[j++] = tmpev;
			}
		}
		while (NULL != (tmpev = tmpev->next));
		kevloop_handle_evs(evloop);
	}
}

static void
epoll_modify(kevloop_t evloop, int fd, int op)
{
	int epoll_op = 0;
	switch (op)
	{
	case K_OP_ADD:
		epoll_op = EPOLL_CTL_ADD;
		break;
	case K_OP_MOD:
		epoll_op = EPOLL_CTL_MOD;
		break;
	case K_OP_DEL:
		epoll_op = EPOLL_CTL_DEL;
		break;
	case K_OP_NON:
	default:
		return;
	}
	int retev = evloop->evfds[fd]->events;
	struct epoll_event epev;
	memset(&epev, 0, sizeof(epev));
	epev.data.fd = fd;
	epev.events = (retev & K_EV_READ ? EPOLLIN : 0) | (retev & K_EV_WRITE ? EPOLLOUT : 0) | EPOLLET;
	//	printf("epoll ctl,op:%d, fd:%d, retev:%d\n", op, ev->fd, retev);
	epoll_ctl(evloop->poll_fd, epoll_op, fd, &epev);
}

static void
epoll_uninit(kevloop_t evloop)
{
	close(evloop->poll_fd);
	close(evloop->weakup_fd);
}

static int
epoll_init(kevloop_t evloop)
{
	evloop->poll = epoll_poll;
	evloop->modify = epoll_modify;
	evloop->uninit = epoll_uninit;
	evloop->poll_fd = epoll_create1(0);
	evloop->weakup_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	return 0;
}



static void
weakup_cb(kevloop_t evloop, kev_t ev)
{
	uint64_t on = 1;
	int ret = read(ev->fd, &on, sizeof on);
	if (ret != sizeof on)
	{
		printf("weakup_cb read %s\n", k_strerr());
	}
}

static void
kevloop_waitweak(kevloop_t evloop)
{
	kev_t weakup_ev = NULL;
	kev_init(&weakup_ev, evloop->weakup_fd, K_EV_READ, weakup_cb, evloop->mp);
	kevloop_run(evloop, kevloop_add_ev, weakup_ev);
}

static void
kevloop_weakup(kevloop_t evloop)
{
	uint64_t on = 1;
	int ret = write(evloop->weakup_fd, &on, sizeof on);
	if (ret != sizeof on)
	{
		printf("k_evloop_weakup write %s\n", k_strerr());
	}
}

#endif

#ifdef _WIN32

/************************************************************************/
/*				win32 poll                                              */
/************************************************************************/

static void
wpoll_handle_fdset(kevloop_t evloop, fd_set * pset, int event)
{
	u_int i = 0;
	int j = 0;
	int fd = 0;
	kev_fd_t evfd = NULL;
	kev_t tmpev = NULL;
	for (i = 0; i < pset->fd_count; ++i)
	{
		j = 0;
		fd = pset->fd_array[i];
		evfd = evloop->evfds[fd];
		if (NULL == evfd)
		{
			printf("NULL == evfd\n");
			continue;
		}
		tmpev = evfd->head;
		if (NULL == tmpev)
		{
			printf("NULL == tmpev\n");
			continue;
		}
		do
		{
			if (tmpev->event & event)
			{
				evloop->actevs[j++] = tmpev;
			}
		}
		while (NULL != (tmpev = tmpev->next));
	}
}

static void
wpoll_poll(kevloop_t evloop)
{
	int ret = 0;
	fd_set readfds = evloop->readfds;
	fd_set writefds = evloop->writefds;
	ret = select(0, &readfds, &writefds, NULL, NULL);
	if (0 >= ret)
	{
		printf("select :%d\n", k_errno());
		evloop->event->isrunning = 0;
		return;
	}
	wpoll_handle_fdset(evloop, &readfds, K_EV_READ);
	wpoll_handle_fdset(evloop, &writefds, K_EV_WRITE);
	kevloop_handle_evs(evloop);
}

static void
wpoll_modify(kevloop_t evloop, int fd, int op)
{
	int event = evloop->evfds[fd]->events;
	switch (op)
	{
	case K_OP_ADD:
		if ((event & K_EV_READ) &&
			!FD_ISSET(fd, &evloop->readfds))
		{
			FD_SET(fd, &evloop->readfds);
		}
		if ((event & K_EV_WRITE) &&
			!FD_ISSET(fd, &evloop->writefds))
		{
			FD_SET(fd, &evloop->writefds);
		}
		break;
	case K_OP_MOD:
	case K_OP_DEL:
		FD_CLR(fd, &evloop->readfds);
		FD_CLR(fd, &evloop->writefds);
		if (event & K_EV_READ)
		{
			FD_SET(fd, &evloop->readfds);
		}
		if (event & K_EV_WRITE)
		{
			FD_SET(fd, &evloop->writefds);
		}
		break;
	case K_OP_NON:
	default:
		return;
	}
}

static void
wpoll_uninit(kevloop_t evloop)
{
	FD_ZERO(&evloop->readfds);
	FD_ZERO(&evloop->writefds);
	closesocket(evloop->weakup_fd);
}

static int udp_port = 18800;

static int
wpoll_init(kevloop_t evloop)
{
	int try = 0;
	int failed = 1;
	evloop->poll = wpoll_poll;
	evloop->modify = wpoll_modify;
	evloop->uninit = wpoll_uninit;
	evloop->poll_fd = 0;
	if (-1 == ksock_init())
	{
		return 1;
	}
	evloop->weakup_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (-1 == evloop->weakup_fd)
	{
		printf("socket :%d\n", k_errno());
		return 1;
	}
	ksock_set_non_blocking(evloop->weakup_fd);
	FD_ZERO(&evloop->readfds);
	FD_ZERO(&evloop->writefds);
	
	while (++try < 10)
	{
		ksock_to_addr(&(evloop->weakupaddr), "127.0.0.1", udp_port++);
		if (-1 != bind(evloop->weakup_fd, (struct sockaddr *)&(evloop->weakupaddr), sizeof(struct sockaddr)))
		{
			failed = 0;
			break;
		}
	}
	if (failed)
	{
		printf("weakup bind :%d\n", k_errno());
		return 1;
	}
	return 0;
}


static void
weakup_cb(kevloop_t evloop, kev_t ev)
{
	int ret = 0;
	char on[4] = {0};
	int addrlen = sizeof(struct sockaddr);
	ret = recvfrom(evloop->weakup_fd, on, sizeof(on), 0, (struct sockaddr *)&(evloop->weakupaddr), &addrlen);
	if (ret != sizeof on)
	{
		printf("recvfrom ret:%d, errno:%d\n", ret, k_errno());
	}
}

static void
kevloop_waitweak(kevloop_t evloop)
{
	kev_t weakup_ev = NULL;
	kev_init(&weakup_ev, evloop->weakup_fd, K_EV_READ, weakup_cb, evloop->mp);
	kevloop_run(evloop, kevloop_add_ev, weakup_ev);
}

static void
kevloop_weakup(kevloop_t evloop)
{
	int on = 1;
	int ret = 0;
	ret = sendto(evloop->weakup_fd, (char *)&on, sizeof(int), 0, (struct sockaddr *)&(evloop->weakupaddr), sizeof(struct sockaddr));
	if (ret != sizeof on)
	{
		printf("k_evloop_weakup :%d\n", k_errno());
	}
}

#endif

#ifdef LINUX
#define poll_init(x)	epoll_init(x);
__thread kevloop_t t_evloop = NULL;
#else
#ifdef _WIN32
#define poll_init(x)	wpoll_init(x);
__declspec(thread) kevloop_t t_evloop = NULL;
#endif
#endif


/************************************************************************/
/*				kev                                                     */
/************************************************************************/

int
kev_init(kev_t * pev, int fd, int event, kevloop_cb cb, kmem_pool_t mp)
{
	*pev = kalloc_t(mp, kev);
	if (NULL == *pev)
	{
		return 1;
	}
	(*pev)->mp = mp;
	(*pev)->fd = fd;
	(*pev)->event = event;
	(*pev)->cb = cb;
	(*pev)->next = NULL;
	(*pev)->prev = NULL;
	(*pev)->data = NULL;
	return 0;
}

int
kev_set_data(kev_t ev, void * data)
{
	ev->data = data;
	return 0;
}

void *
kev_get_data(kev_t ev)
{
	return ev->data;
}

int
kev_uninit(kev_t ev)
{
	kfree(ev->mp, ev);
	return 0;
}


/************************************************************************/
/*				kevloop                                                 */
/************************************************************************/

static void
kevloop_handle_pandings(kevloop_t evloop)
{
	kevloop_task_t task = NULL;
	kevloop_task_t tmptask = NULL;
	kthread_mutex_lock(&evloop->mtx);
	task = evloop->head;
	evloop->head = evloop->tail = NULL;
	while (task)
	{
		task->cb(evloop, task->ev);
		tmptask = task;
		task = tmptask->next;
		kfree(evloop->mp, tmptask);
	}
	kthread_mutex_unlock(&evloop->mtx);

}


static int
kevloop_init(kevloop_t * pevloop)
{
	*pevloop = k_malloc_t(kevloop);
	kmempool_init(&(*pevloop)->mp, MEM_POOL_SIZE);
	(*pevloop)->evfds = kalloc((*pevloop)->mp, FD_MAX * sizeof(kev_fd_t));
	(*pevloop)->actevs = kalloc((*pevloop)->mp, EV_MAX * sizeof(kev_t));
	(*pevloop)->head = NULL;
	(*pevloop)->tail = NULL;
	kthread_mutex_init(&(*pevloop)->mtx, NULL);
	poll_init(*pevloop);
	return 0;
}


static int
kevloop_loop(kevloop_t evloop)
{
	while (1 == evloop->event->isrunning)
	{
		evloop->poll(evloop);
		kevloop_handle_pandings(evloop);
	}
	return 0;
}


static int
kevloop_run(kevloop_t evloop, kevloop_cb cb, kev_t ev)
{
	if (evloop->tid == kthread_self())
	{
		cb(evloop, ev);
	}
	else
	{
		kevloop_task_t task = NULL;
		kthread_mutex_lock(&evloop->mtx);
		task = kalloc_t(evloop->mp, kevloop_task);
		if (NULL == task)
		{
			kthread_mutex_unlock(&evloop->mtx);
			return 1;
		}
		task->cb = cb;
		task->ev = ev;
		task->next = NULL;
		if (NULL == evloop->tail)
		{
			evloop->head = evloop->tail = task;
		}
		else
		{
			evloop->tail->next = task;
			evloop->tail = task;
		}
		kthread_mutex_unlock(&evloop->mtx);
		kevloop_weakup(evloop);
	}
	return 0;
}

static int
kevloop_uninit(kevloop_t evloop)
{
	int i = 0;
	kev_uninit(evloop->evfds[evloop->weakup_fd]->head);
	for (i = 0; i < FD_MAX; ++i)
	{
		if (NULL != evloop->evfds[i])
		{
			kfree(evloop->mp, evloop->evfds[i]);
		}
	}
	for (i = 0; i < EV_MAX; ++i)
	{
		if (NULL != evloop->actevs[i])
		{
			kfree(evloop->mp, evloop->actevs[i]);
		}
	}
	kthread_mutex_destroy(&evloop->mtx);
	evloop->uninit(evloop);
	kfree(evloop->mp, evloop->evfds);
	kfree(evloop->mp, evloop->actevs);
	kmempool_uninit(evloop->mp);
	k_free(evloop);
	return 0;
}


/************************************************************************/
/*				kevent                                                  */
/************************************************************************/

int
kevent_init(kevent_t * pevent, int threadnum)
{
	int i = 0;
	*pevent = k_malloc_t(kevent);
	if (NULL == *pevent)
	{
		return 1;
	}
	(*pevent)->loops = k_malloc(threadnum * sizeof(kevloop));
	(*pevent)->threads = k_malloc(threadnum * sizeof(kthread_t));
	if (NULL == (*pevent)->loops)
	{
		k_free(*pevent);
		return 1;
	}
	for (i = 0; i < threadnum; ++i)
	{
		kevloop_init(&(*pevent)->loops[i]);
		(*pevent)->loops[i]->event = *pevent;
	}
	(*pevent)->loop_index = 0;
	(*pevent)->threadnum = threadnum;
	return 0;
}

int
kevent_set_data(kevent_t event, void * data)
{
	event->data = data;
	return 0;
}

kevloop_t
kevent_fetch_loop(kevent_t event)
{
	kevloop_t evloop = event->loops[event->loop_index++];
	if (NULL == evloop)
	{
		return NULL;
	}
	if (event->loop_index == event->threadnum)
	{
		event->loop_index = 0;
	}
	return evloop;
}

int
kevent_watch(kevloop_t evloop, kev_t ev)
{	
	if (0 != kevloop_run(evloop, kevloop_add_ev, ev))
	{
		return 1;
	}
	return 0;
}

int
kevent_ignore(kevloop_t evloop, kev_t ev)
{
	if (0 != kevloop_run(evloop, kevloop_remove_ev, ev))
	{
		return 1;
	}
	return 0;
}

static kthread_result_t KTHREAD_CALL
poll_loop(void * args)
{
	kevloop_t evloop = NULL;
	printf("poll_loop tid:%d\n", (int)kthread_self());
	if (NULL != t_evloop)
	{
		printf("t_evloop is not null,tid:%d\n", (int)kthread_self());
		return 0;
	}
	evloop = (kevloop_t)args;
	evloop->tid = kthread_self();
	kevloop_waitweak(evloop);
	t_evloop = evloop;
	kevloop_loop(evloop);
	return 0;
}

int
kevent_start(kevent_t event)
{
	int i = 0;
	event->isrunning = 1;
	for (i = 0; i < event->threadnum; ++i)
	{
		kthread_create(&event->threads[i], NULL, poll_loop, event->loops[i]);
	}
	return 0;
}

int
kevent_uninit(kevent_t event)
{
	int i = 0;
	event->isrunning = 0;
	for (i = 0; i < event->threadnum; ++i)
	{
		kevloop_weakup(event->loops[i]);
		kthread_join(event->threads[i], NULL);
		kevloop_uninit(event->loops[i]);
	}
	printf("kevent_uninit\n");
	k_free(event->threads);
	k_free(event->loops);
	k_free(event);
	return 0;
}


/************************************************************************/
/*				ktcp_session                                            */
/************************************************************************/


static int
ktcp_session_init(ktcp_session_t * psession, int fd, kmem_pool_t mp)
{
	*psession = kalloc_t(mp, ktcp_session);
	if (NULL == *psession)
	{
		return 1;
	}
	(*psession)->fd = fd;
	(*psession)->err = 0;
	(*psession)->data = NULL;
	(*psession)->mp = mp;
	kbuffer_init(&(*psession)->recv_buffer, mp);
	kbuffer_init(&(*psession)->send_buffer, NULL);
	kthread_mutex_init(&(*psession)->send_lock, NULL);
	return 0;
}

static int
ktcp_session_uninit(ktcp_session_t session)
{
	kbuffer_uninit(session->recv_buffer);
	kbuffer_uninit(session->send_buffer);
	kthread_mutex_destroy(&session->send_lock);
	kfree(session->mp, session);
	return 0;
}

static int
ktcp_session_set_local(ktcp_session_t session, char *ip, int port)
{
	if (NULL != ip)
	{
		strcpy(session->localip, ip);
	}
	if (0 != port)
	{
		session->localport = port;
	}
	if (NULL == ip && 0 == port)
	{
		struct sockaddr_in addr_in;
		socklen_t len = sizeof(struct sockaddr_in);
		getsockname(session->fd, (struct sockaddr *)&addr_in, &len);
		strcpy(session->localip, inet_ntoa(addr_in.sin_addr));
		session->localport = ntohs(addr_in.sin_port);
	}
	return 0;
}

static int
ktcp_session_set_peer(ktcp_session_t session, char *ip, int port)
{
	strcpy(session->peerip, ip);
	session->peerport = port;
	return 0;
}


/************************************************************************/
/*				ktcp                                                    */
/************************************************************************/

struct ktcp
{
	kev_t accept_ev;			/*accept ev*/
	kevent_t event;

	ktcp_cb read_cb;
	ktcp_cb connected_cb;
	ktcp_cb disconnected_cb;

	kmem_pool_t mp;

	void *data;					/*user data*/
};

static void
ktcp_close_cb(kevloop_t evloop, kev_t ev)
{
	ktcp_t tcp = (ktcp_t)evloop->event->data;
	ktcp_session_t session = (ktcp_session_t)(ev->data);

	if (tcp->disconnected_cb)
	{
		tcp->disconnected_cb(tcp, session);
	}

	kevent_ignore(evloop, ev);
	ksock_shutdown(session->fd, K_SHUT_RDWR);
	ksock_close(session->fd);
	ktcp_session_uninit(session);
}


static void
ktcp_read_cb(kevloop_t evloop, kev_t ev)
{
	int ret = 0;
	ktcp_t tcp = (ktcp_t)evloop->event->data;
	ktcp_session_t session = (ktcp_session_t)(ev->data);
	ret = kbuffer_read_fd(session->recv_buffer, session->fd);
	if (-1 == ret && K_EAGAIN == k_errno())
	{
		printf("recv :%d\n", k_errno());
		if (K_SOCK_MAXERR <= session->err)
		{
			ktcp_close_cb(evloop, ev);
		}
		else
		{
			session->err ++;
		}
		return;
	}
	if (0 >= ret)
	{
		ktcp_close_cb(evloop, ev);
		return;
	}
	if (tcp->read_cb)
	{
		tcp->read_cb(tcp, session);
	}
}

static void
ktcp_write_cb(kevloop_t evloop, kev_t ev)
{
	ktcp_t tcp = (ktcp_t)evloop->event->data;
	ktcp_session_t session = (ktcp_session_t)(ev->data);
	kevent_ignore(evloop, ev);
	printf("ktcp_write_cb,fd:%d\n", session->fd);
	ktcp_send(tcp, session, NULL, 0);
}

static void
ktcp_accept_cb(kevloop_t evloop, kev_t ev)
{
	char ip[IP_SIZE] = {0};
	int port = 0;
	ktcp_session_t session;
	kev_t read_ev = NULL;
	ktcp_t tcp = NULL;
	kevloop_t curloop = NULL;
	int fd = ksock_accept(ev->fd, ip, &port);
	if (-1 == fd)
	{
		return;
	}
	tcp = (ktcp_t)evloop->event->data;
	ksock_set_reuse(fd);
	ksock_set_alive(fd, K_SOCK_IDLE, K_SOCK_INTVAL, K_SOCK_CNT);
	ksock_set_non_blocking(fd);
	ksock_set_sendbuf(fd, K_SOCK_SENDBUF);
	curloop = kevent_fetch_loop(tcp->event);
	if (NULL == curloop)
	{
		return;
	}
	ktcp_session_init(&session, fd, curloop->mp);
	ktcp_session_set_peer(session, ip, port);
	if (tcp->connected_cb)
	{
		tcp->connected_cb(tcp, session);
	}
	kev_init(&read_ev, fd, K_EV_READ, ktcp_read_cb, curloop->mp);
	kev_set_data(read_ev, session);
	kevent_watch(curloop, read_ev);
}

int
ktcp_init(ktcp_t * ptcp, int threadnum, kmem_pool_t mp)
{
	*ptcp = kalloc_t(mp, ktcp);
	if (NULL == *ptcp)
	{
		return 1;
	}
	if (-1 == ksock_init())
	{
		return 1;
	}
	(*ptcp)->data = NULL;
	(*ptcp)->mp = mp;
	kevent_init(&(*ptcp)->event, threadnum);
	kevent_set_data((*ptcp)->event, (*ptcp));
	return 0;
}

int
ktcp_connect(ktcp_t tcp, int selfport, char *ip, int port)
{
	ktcp_session_t session = NULL;
	kev_t read_ev = NULL;
	kev_t write_ev = NULL;
	kevloop_t curloop = NULL;
	int fd = ksock_init_fd();
	if (0 != ksock_bind(fd, selfport))
	{
		return 1;
	}
	if (0 != ksock_connect(fd, ip, port))
	{
		return 1;
	}
	ksock_set_alive(fd, K_SOCK_IDLE, K_SOCK_INTVAL, K_SOCK_CNT);
	ksock_set_non_blocking(fd);
	ksock_set_sendbuf(fd, K_SOCK_SENDBUF);
	curloop = kevent_fetch_loop(tcp->event);
	if (NULL == curloop)
	{
		return 1;
	}
	ktcp_session_init(&session, fd, curloop->mp);
	ktcp_session_set_peer(session, ip, port);
	ktcp_session_set_local(session, NULL, 0);
	if (tcp->connected_cb)
	{
		tcp->connected_cb(tcp, session);
	}
	kev_init(&read_ev, fd, K_EV_READ, ktcp_read_cb, curloop->mp);
	kev_init(&write_ev, fd, K_EV_WRITE, ktcp_write_cb, curloop->mp);
	kev_set_data(read_ev, session);
	kev_set_data(write_ev, session);
	kevent_watch(curloop, read_ev);
	kevent_watch(curloop, write_ev);

	return 0;
}


int
ktcp_start(ktcp_t tcp)
{
	return kevent_start(tcp->event);
}

int
ktcp_listen(ktcp_t tcp, int port)
{
	kev_t accept_ev = NULL;
	int fd = ksock_init_fd();
	kevloop_t curloop = kevent_fetch_loop(tcp->event);
	if (NULL == curloop)
	{
		return 1;
	}
	ksock_set_alive(fd, K_SOCK_IDLE, K_SOCK_INTVAL, K_SOCK_CNT);
	ksock_set_non_blocking(fd);
	kev_init(&accept_ev, fd, K_EV_READ, ktcp_accept_cb, NULL);
	if (NULL != tcp->accept_ev)
	{
		accept_ev->prev = tcp->accept_ev;
	}
	tcp->accept_ev = accept_ev;
	kevent_watch(curloop, accept_ev);
	return ksock_listen_at(fd, port);
}

int
ktcp_close_session(ktcp_t tcp, ktcp_session_t session)
{
	ksock_shutdown(session->fd, K_SHUT_WR);
	return 0;
}

int 
ktcp_set_data(ktcp_t tcp, void *data)
{
	if (NULL == tcp)
	{
		return 1;
	}
	tcp->data = data;
	return 0;
}

void *
ktcp_get_data(ktcp_t tcp)
{
	return tcp->data;
}

int
ktcp_set_cb(ktcp_t tcp, int cb_type, ktcp_cb cb)
{
	switch (cb_type)
	{
	case KCB_CONNECTED:
		tcp->connected_cb = cb;
		break;
	case KCB_DISCONNECTED:
		tcp->disconnected_cb = cb;
		break;
	case KCB_READ:
		tcp->read_cb = cb;
		break;
	default:
		break;
	}
	return 0;
}

int
ktcp_send(ktcp_t tcp, ktcp_session_t session, void * data, int len)
{
	int ret = 0;
	kthread_mutex_lock(&session->send_lock);
	if (NULL != data)
	{
		kbuffer_write(session->send_buffer, data, len);
	}
	ret = kbuffer_write_fd(session->send_buffer, session->fd);
	if (ret <= 0)
	{
		if (K_EAGAIN == k_errno() && K_SOCK_MAXERR > session->err)
		{
			session->err ++;
		}
		else
		{
			printf("ktcp_send %d\n", k_errno());
			ktcp_close_session(tcp, session);
			kthread_mutex_unlock(&session->send_lock);
			return 1;	
		}
	}
	if (kbuffer_readable(session->send_buffer) > 0)
	{
		kev_t write_ev = NULL;
		kevloop_t curloop = kevent_fetch_loop(tcp->event);
		if (NULL == curloop)
		{
			printf("NULL == curloop\n");
			kthread_mutex_unlock(&session->send_lock);
			return 1;
		}
		kev_init(&write_ev, session->fd, K_EV_WRITE, ktcp_write_cb, curloop->mp);
		kev_set_data(write_ev, session);
		kevent_watch(curloop, write_ev);
	}
	kthread_mutex_unlock(&session->send_lock);
	return 0;
}

int
ktcp_uninit(ktcp_t tcp)
{
	kev_t accept_ev = tcp->accept_ev;
	kevent_uninit(tcp->event);
	while (accept_ev)
	{
		int fd = accept_ev->fd;
		kev_t tmpev = accept_ev;
		accept_ev = accept_ev->prev;
		kev_uninit(tmpev);
		ksock_close(fd);
	}
	kfree(tcp->mp, tcp);
	return 0;
}

/************************************************************************/
/*				kbuffer                                                 */
/************************************************************************/

struct kbuffer
{
	char *data;			/*real data*/
	int size;			/*total size*/
	int rindex;			/*indicate read*/
	int windex;			/*indicate write*/
	kmem_pool_t mp;

};

int
kbuffer_readable(kbuffer_t buffer)
{
	if (NULL == buffer)
	{
		return 1;
	}
	return buffer->windex - buffer->rindex;
}

void *
kbuffer_read(kbuffer_t buffer, int *psize)
{
	void *p = NULL;
	if (NULL == buffer)
	{
		return NULL;
	}
	p = buffer->data + buffer->rindex;
	if (*psize > buffer->windex - buffer->rindex)
	{
		*psize = buffer->windex - buffer->rindex;
	}
	return p;
}

void
kbuffer_shift(kbuffer_t buffer, int size)
{
	if (NULL == buffer)
	{
		return;
	}
	buffer->rindex += size;
	if (buffer->rindex >= buffer->size)
	{
		buffer->rindex = buffer->windex = 0;
	}
}

int
kbuffer_write(kbuffer_t buffer, void *data, int size)
{
	if (NULL == buffer)
	{
		return 1;
	}
	if (buffer->size - buffer->windex < size)
	{
		buffer->windex -= buffer->rindex;
		buffer->rindex = 0;
		buffer->data = krealloc(buffer->mp, buffer->data, buffer->size, buffer->windex + size);
	}
	memcpy(buffer->data+buffer->windex, data, size);
	buffer->windex += size;
	return 0;
}

int
kbuffer_read_fd(kbuffer_t buffer, int fd)
{
	int ret = 0;
	int needread = 0;
	if (NULL == buffer)
	{
		return -1;
	}
	if (0 != ksock_ioctl(fd, FIONREAD, &needread))
	{
		return -1;
	}
	if (0 >= needread)
	{
		return -1;
	}
	if (buffer->size - buffer->windex < needread && 0 < buffer->rindex)
	{
		buffer->windex -= buffer->rindex;
		buffer->rindex = 0;
	}
	if (buffer->size - buffer->windex < needread)
	{
		buffer->data = krealloc(buffer->mp, buffer->data, buffer->size, buffer->windex + needread);		
	}
	ret = recv(fd, buffer->data + buffer->windex, needread, 0);
	//printf("recv fd:%d,len%d,err:%d\n", fd, ret, k_errno());
	if (ret > 0)
	{
		buffer->windex += ret;
	}
	return ret;
}

int
kbuffer_write_fd(kbuffer_t buffer, int fd)
{
	int ret = 0;
	if (NULL == buffer)
	{
		return 1;
	}
	if (buffer->windex - buffer->rindex <= 0)
	{
		errno = K_EAGAIN;
		return 1;
	}
	ret = send(fd, buffer->data + buffer->rindex, buffer->windex - buffer->rindex, 0);
	//printf("send fd:%d,len:%d,err:%d\n", fd, ret,k_errno());
	if (ret > 0)
	{
		buffer->rindex += ret;
		if (buffer->rindex >= buffer->windex)
		{
			buffer->rindex = buffer->windex = 0;
		}
	}
	return ret;
}

int
kbuffer_init(kbuffer_t *pbuffer, kmem_pool_t mp)
{
	(*pbuffer) = kalloc_t(mp, kbuffer);
	if (NULL == (*pbuffer))
	{
		return 1;
	}
	(*pbuffer)->mp = mp;
	(*pbuffer)->data = kalloc(mp, K_BUFFER_SIZE * sizeof(char));
	(*pbuffer)->size = K_BUFFER_SIZE;
	(*pbuffer)->rindex = 0;
	(*pbuffer)->windex = 0;
	return 0;
}

int
kbuffer_uninit(kbuffer_t buffer)
{
	if (NULL == buffer)
	{
		return 0;
	}
	if (buffer->data)
	{
		kfree(buffer->mp, buffer->data);
	}
	kfree(buffer->mp, buffer);
	return 0;
}

//krbtree
/************************************************************************/
/*				krbtree                                                 */
/************************************************************************/

enum krbtree_color
{
	RED,
	BLACK,
};

typedef struct krbtree_node krbtree_node, *krbtree_node_t;

struct krbtree_node 
{
	krbtree_node_t left;			/*private*/
	krbtree_node_t right;			/*private*/
	krbtree_node_t parent;			/*private*/
	enum krbtree_color color;		/*private*/

	void *key;
	void *value;
};


struct krbtree 
{
	krbtree_node_t root;
	krbtree_node_t sentinel;
	krbtree_cmp cmp;
	kmem_pool_t mp;
};

static void
krbtree_rotate_left(krbtree_t tree, krbtree_node_t node)
{
	krbtree_node_t tmp = node->right;
	node->right = tmp->left;
	if (tree->sentinel != tmp->left)
	{
		tmp->left->parent = node;
	}
	if (tree->sentinel != tmp)
	{
		tmp->parent = node->parent;
	}
	if (NULL != node->parent)
	{
		if (node == node->parent->left)
		{
			node->parent->left = tmp;
		}
		else
		{
			node->parent->right = tmp;
		}
	}
	else
	{
		tree->root = tmp;
	}
	tmp->left = node;
	if (tree->sentinel != node)
	{
		node->parent = tmp;
	}
}

static void
krbtree_rotate_right(krbtree_t tree, krbtree_node_t node)
{
	krbtree_node_t tmp = node->left;
	node->left = tmp->right;
	if (tree->sentinel != tmp->right)
	{
		tmp->right->parent = node;
	}
	if (tree->sentinel != tmp)
	{
		tmp->parent = node->parent;
	}
	if (NULL != node->parent)
	{
		if (node == node->parent->right)
		{
			node->parent->right = tmp;
		}
		else
		{
			node->parent->left = tmp;
		}
	}
	else
	{
		tree->root = tmp;
	}
	tmp->right = node;
	if (tree->sentinel != node)
	{
		node->parent = tmp;
	}
}

static void
krbtree_insert_fixup(krbtree_t tree, krbtree_node_t node)
{
	while (node != tree->root && RED == node->parent->color)
	{
		if (node->parent == node->parent->left)
		{
			krbtree_node_t tmp = node->parent->parent->right;
			if (RED == tmp->color)
			{
				node->parent->color = BLACK;
				tmp->color = BLACK;
				node->parent->parent->color = RED;
				node = node->parent->parent;
			}
			else
			{
				if (node == node->parent->right)
				{
					node = node->parent;
					krbtree_rotate_left(tree, node);
				}
				node->parent->color = BLACK;
				node->parent->parent->color = RED;
				krbtree_rotate_right(tree, node->parent->parent);
			}
		}
		else
		{
			krbtree_node_t tmp = node->parent->parent->left;
			if (RED == tmp->color)
			{
				node->parent->color = BLACK;
				tmp->color = BLACK;
				node->parent->parent->color = RED;
				node = node->parent->parent;
			}
			else
			{
				if (node == node->parent->left)
				{
					node = node->parent;
					krbtree_rotate_right(tree, node);
				}
				node->parent->color = BLACK;
				node->parent->parent->color = RED;
				krbtree_rotate_left(tree, node->parent->parent);
			}
		}
	}
	tree->root->color = BLACK;
}

static void
krbtree_erase_fixup(krbtree_t tree, krbtree_node_t node)
{
	while (node != tree->root && BLACK == node->color)
	{
		if (node == node->parent->left)
		{
			krbtree_node_t tmp = node->parent->right;
			if (RED == tmp->color)
			{
				tmp->color = BLACK;
				node->parent->color = RED;
				krbtree_rotate_left(tree, node->parent);
				tmp = node->parent->right;
			}
			if (BLACK == tmp->left->color && BLACK == tmp->right->color)
			{
				tmp->color = RED;
				node = node->parent;
			}
			else
			{
				if (BLACK == tmp->right->color)
				{
					tmp->left->color = BLACK;
					tmp->color = RED;
					krbtree_rotate_right(tree, tmp);
					tmp = node->parent->right;
				}
				tmp->color = node->parent->color;
				node->parent->color = BLACK;
				tmp->right->color = BLACK;
				krbtree_rotate_left(tree, node->parent);
				node = tree->root;
			}
		}
		else
		{
			krbtree_node_t tmp = node->parent->left;
			if (RED == tmp->color)
			{
				tmp->color = BLACK;
				node->parent->color = RED;
				krbtree_rotate_right(tree, node->parent);
				tmp = node->parent->left;
			}
			if (BLACK == tmp->right->color && BLACK == tmp->left->color)
			{
				tmp->color = RED;
				node = node->parent;
			}
			else
			{
				if (BLACK == tmp->left->color)
				{
					tmp->right->color = BLACK;
					tmp->color = RED;
					krbtree_rotate_left(tree, tmp);
					tmp = node->parent->left;
				}
				tmp->color = node->parent->color;
				node->parent->color = BLACK;
				tmp->left->color = BLACK;
				krbtree_rotate_right(tree, node->parent);
				node = tree->root;
			}
		}
	}
	node->color = BLACK;
}

static int
default_rbtree_cmp(void *left_key, void *right_key)
{
	return (int)left_key - (int)right_key;
}

int 
krbtree_init(krbtree_t *ptree, krbtree_cmp cmp, kmem_pool_t mp)
{
	*ptree = kalloc_t(mp, krbtree);
	if (NULL == *ptree)
	{
		return 1;
	}
	(*ptree)->cmp = cmp;
	if (NULL == cmp)
	{
		(*ptree)->cmp = default_rbtree_cmp;
	}
	(*ptree)->mp = mp;
	(*ptree)->sentinel = kalloc_t(mp, krbtree_node);
	if (NULL == (*ptree)->sentinel)
	{
		kfree(mp, *ptree);
		return 1;
	}
	(*ptree)->root = (*ptree)->sentinel;
	(*ptree)->sentinel->left = (*ptree)->sentinel;
	(*ptree)->sentinel->right = (*ptree)->sentinel;
	(*ptree)->sentinel->parent = NULL;
	(*ptree)->sentinel->color = BLACK;
	(*ptree)->sentinel->key = NULL;
	(*ptree)->sentinel->value = NULL;

	return 0;
}

void *
krbtree_find(krbtree_t tree, void *key)
{
	int ret = 0;
	krbtree_node_t current = tree->root;
	while (tree->sentinel != current)
	{
		ret = tree->cmp(key, current->key);
		if (0 == ret)
		{
			return current->value;
		}
		current = ret < 0 ? current->left : current->right;
	}
	return NULL;
}

int 
krbtree_insert(krbtree_t tree, void *key, void *value)
{
	krbtree_node_t current, parent, node;
	int ret = 0;
	current = tree->root;
	parent = NULL;
	while (tree->sentinel != current)
	{
		ret = tree->cmp(key, current->key);
		if (0 == ret)
		{
			return 1;
		}
		parent = current;
		current = ret < 0 ? current->left : current->right;
	}

	node = kalloc_t(tree->mp, krbtree_node);
	if (NULL == node)
	{
		return 1;
	}
	node->parent = parent;
	node->left = tree->sentinel;
	node->right = tree->sentinel;
	node->color = RED;
	node->key = key;
	node->value = value;

	if (NULL != parent)
	{
		if (0 > tree->cmp(key, parent->key))
		{
			parent->left = node;
		}
		else
		{
			parent->right = node;
		}
	}
	else
	{
		tree->root = node;
	}
	krbtree_insert_fixup(tree, node);
	return 0;
}

int 
krbtree_erase(krbtree_t tree, void *key)
{
	int ret = 0;
	int find = 0;
	krbtree_node_t x, y;
	krbtree_node_t current = tree->root;
	while (tree->sentinel != current)
	{
		ret = tree->cmp(key, current->key);
		if (0 == ret)
		{
			find = 1;
			break;
		}
		current = ret < 0 ? current->left : current->right;
	}
	if (0 == find)
	{
		return 1;
	}

	if (tree->sentinel == current->left || tree->sentinel == current->right)
	{
		y = current;
	}
	else
	{
		y = current->right;
		while (tree->sentinel != y->left)
		{
			y = y->left;
		}
	}

	if (tree->sentinel != y->left)
	{
		x = y->left;
	}
	else
	{
		x = y->right;
	}

	x->parent = y->parent;
	if (NULL != y->parent)
	{
		if (y == y->parent->left)
		{
			y->parent->left = x;
		}
		else
		{
			y->parent->right = x;
		}
	}
	else
	{
		tree->root = x;
	}

	if (y != current)
	{
		current->key = y->key;
		current->value = y->value;
	}

	if (BLACK == y->color)
	{
		krbtree_erase_fixup(tree, x);
	}
	kfree(tree->mp, y);
	return 0;
}

static int
krbtree_foreach_node(krbtree_t tree, krbtree_node_t node, krbtree_foreach_cb cb, void *p)
{
	if (tree->sentinel == node)
	{
		return 0;
	}
	if (0 != krbtree_foreach_node(tree, node->left, cb, p))
	{
		return 0;
	}
	if (0 != krbtree_foreach_node(tree, node->right, cb, p))
	{
		return 0;
	}
	return cb(node->key, node->value, p);
}

int 
krbtree_foreach(krbtree_t tree, krbtree_foreach_cb cb, void *p)
{
	return krbtree_foreach_node(tree, tree->root, cb, p);
}

static void
krbtree_delete_node(krbtree_t tree, krbtree_node_t node)
{
	if (tree->sentinel == node)
	{
		return;
	}
	krbtree_delete_node(tree, node->left);
	krbtree_delete_node(tree, node->right);
	kfree(tree->mp, node);
}

int 
krbtree_clear(krbtree_t tree)
{
	krbtree_delete_node(tree, tree->root);
	tree->root = tree->sentinel;
	return 0;
}

int 
krbtree_uninit(krbtree_t tree)
{
	krbtree_delete_node(tree, tree->root);
	kfree(tree->mp, tree->sentinel);
	kfree(tree->mp, tree);
	return 0;
}


/************************************************************************/
/*				kminheap                                                */
/************************************************************************/

struct kminheap 
{
	kmem_pool_t mp;
	kminheap_node_t *array;
	int orsize;
	int cursize;
	int size;

	void * data;
};

int 
kminheap_node_init(kminheap_node_t *pnode, int key, void *value, kmem_pool_t mp)
{
	*pnode = kalloc_t(mp, kminheap_node);
	if (NULL == *pnode)
	{
		return 1;
	}
	(*pnode)->key = key;
	(*pnode)->value = value;
	(*pnode)->mp = mp;
	(*pnode)->pos = 0;	
	return 0;
}

int 
kminheap_node_uninit(kminheap_node_t node)
{
	kfree(node->mp, node);
	return 0;
}


static int
kminheap_expand(kminheap_t minheap)
{
	uint newsize = minheap->size + minheap->orsize / 2;
	minheap->array = krealloc(minheap->mp, minheap->array, minheap->size  * sizeof(kminheap_node_t), newsize  * sizeof(kminheap_node_t));
	if (NULL == minheap->array)
	{
		return 1;
	}
	minheap->size = newsize;
	return 0;
}

static int
kminheap_adjust_down(kminheap_t minheap, int beg, int end)
{
	int i = beg;
	int j = 2 * i + 1;
	kminheap_node_t tmp = minheap->array[i];
	if (NULL == tmp)
	{
		return 0;
	}
	while (j <= end)
	{
		if (NULL == minheap->array[j] || NULL == minheap->array[j + 1])
		{
			i = j;
			j = 2 * j + 1;
			continue;
		}
		if (j < end && minheap->array[j + 1]->key <= minheap->array[j]->key)
		{
			j ++;
		}
		if (tmp->key <= minheap->array[j]->key)
		{
			break;
		}
		else
		{
			minheap->array[i] = minheap->array[j];
			minheap->array[i]->pos = i;
			minheap->array[j] = NULL;
			i = j;
			j = 2 * j + 1;
		}
	}
	if (tmp)
	{
		minheap->array[i] = tmp;
		minheap->array[i]->pos = i;
		minheap->array[beg] = NULL;
	}
	return 0;
}

static int
kminheap_adjust_up(kminheap_t minheap, int beg)
{
	int j = beg;
	int i = (j - 1) / 2;
	kminheap_node_t tmp = minheap->array[j];
	if (NULL == tmp)
	{
		return 0;
	}
	while (0 < j)
	{
		if (NULL == minheap->array[i])
		{
			j = i;
			i = (i - 1) / 2;
			continue;
		}
		if (minheap->array[i]->key <= tmp->key)
		{
			break;
		}
		else
		{
			minheap->array[j] = minheap->array[i];
			minheap->array[j]->pos = j;
			minheap->array[i] = NULL;
			j = i;
			i = (i - 1) / 2;
		}
	}
	if (tmp)
	{
		minheap->array[j] = tmp;
		minheap->array[j]->pos = j;
		minheap->array[beg] = NULL;
	}
	return 0;
}

int 
kminheap_init(kminheap_t *pminheap, uint size, kmem_pool_t mp)
{
	(*pminheap) = kalloc_t(mp, kminheap);
	if (NULL == *pminheap)
	{
		return 1;
	}
	(*pminheap)->array = kalloc(mp, size * sizeof(kminheap_node_t));
	if (NULL == (*pminheap)->array)
	{
		kfree(mp, *pminheap);
		return 1;
	}
	
	(*pminheap)->mp = mp;
	(*pminheap)->orsize = (*pminheap)->size = size;
	(*pminheap)->cursize = 0;
	return 0;
}

int 
kminheap_uninit(kminheap_t minheap)
{
	int i = 0;
	for (i = 0; i < minheap->cursize; ++i)
	{
		if (minheap->array[i])
		{
			kminheap_node_uninit(minheap->array[i]);
		}
	}
	kfree(minheap->mp, minheap->array);
	kfree(minheap->mp, minheap);
	return 0;
}

int 
kminheap_set_data(kminheap_t minheap, void *data)
{
	minheap->data = data;
	return 0;
}

void * 
kminheap_get_data(kminheap_t minheap)
{
	return minheap->data;
}

int 
kminheap_add(kminheap_t minheap, kminheap_node_t node)
{
	if (minheap->cursize >= minheap->size)
	{
		if (0 != kminheap_expand(minheap))
		{
			return 1;
		}
	}
	node->pos = minheap->cursize;
	minheap->array[minheap->cursize] = node;
	kminheap_adjust_up(minheap, minheap->cursize);
	minheap->cursize ++;
	return 0;
}

int 
kminheap_remove(kminheap_t minheap, kminheap_node_t node)
{
	if (0 > node->pos || minheap->cursize <= node->pos)
	{
		return 1;
	}
	if (node != minheap->array[node->pos])
	{
		return 1;
	}
	minheap->array[node->pos] = minheap->array[minheap->cursize -1];
	minheap->array[minheap->cursize -1] = NULL;
	minheap->cursize --;
	kminheap_adjust_down(minheap, 0, minheap->cursize - 1);
	kminheap_node_uninit(node);
	return 0;
}

int 
kminheap_find(kminheap_t minheap, kminheap_node_t node)
{
	if (0 > node->pos || minheap->cursize <= node->pos)
	{
		return 1;
	}
	if (NULL != minheap->array[node->pos] && node == minheap->array[node->pos])
	{
		return 0;
	}
	return 1;
}

int 
kminheap_foreach(kminheap_t minheap, kminheap_foreach_cb cb, void *p)
{
	int i = 0;
	for (i = 0; i < minheap->cursize; ++i)
	{
		if (minheap->array[i])
		{
			if (0 != cb(minheap, minheap->array[i], p))
			{
				return 1;
			}
		}
	}
	return 0;
}


kminheap_node_t 
kminheap_top(kminheap_t minheap)
{
	if (0 >= minheap->cursize)
	{
		return NULL;
	}
	return minheap->array[0];
}

kminheap_node_t 
kminheap_pop(kminheap_t minheap)
{
	kminheap_node_t node = NULL;
	if (0 >= minheap->cursize)
	{
		return NULL;
	}
	node = minheap->array[0];
	minheap->array[0] = minheap->array[minheap->cursize - 1];
	minheap->array[minheap->cursize -1] = NULL;
	minheap->cursize --;
	kminheap_adjust_down(minheap, 0, minheap->cursize - 1);
	return node;
}

kminheap_node_t 
kminheap_next(kminheap_t minheap, kminheap_node_t node)
{
	kminheap_node_t ret_node = NULL;
	int i = node->pos + 1;
	while (i < minheap->cursize)
	{
		ret_node = minheap->array[i++];
		if (ret_node)
		{
			return ret_node;
		}
	}
	return NULL;
}


//ktimer
/************************************************************************/
/*				ktimer                                                  */
/************************************************************************/

struct ktimer_node
{
	kminheap_node_t minheap_node;
	kmem_pool_t mp;
	int time;
	ktimer_cb cb;
	int count;
	ktimer_t timer;

	void *data;			/*user data*/
};


struct ktimer
{
	kminheap_t minheap;
	kmem_pool_t mp;
	int used_time;
	kthread_t tid;
	int isrunning;
	kthreadpool_t threadpool;
	kthread_mutex_t mtx;
	kthread_cond_t cnd;
	void *data;			/*user data*/
};

int 
ktimer_node_init(ktimer_node_t *pnode, int time, ktimer_cb cb, int count, kmem_pool_t mp)
{
	*pnode = kalloc_t(mp, ktimer_node);
	if (NULL == *pnode)
	{
		return 1;
	}
	if (0 != kminheap_node_init(&((*pnode)->minheap_node), time, *pnode, mp))
	{
		kfree(mp, *pnode);
		return 1;
	}
	(*pnode)->mp = mp;
	(*pnode)->cb = cb;
	(*pnode)->time = time;
	(*pnode)->count = count;
	(*pnode)->timer = NULL;
	(*pnode)->data = NULL;
	return 0;
}

int 
ktimer_node_uninit(ktimer_node_t node)
{
	if (node->minheap_node)
	{
		kminheap_node_uninit(node->minheap_node);
	}
	kfree(node->mp, node);
	return 0;
}

int 
ktimer_node_set_data(ktimer_node_t node, void *data)
{
	node->data = data;
	return 0;
}

void *
ktimer_node_get_data(ktimer_node_t node)
{
	return node->data;
}

int 
ktimer_init(ktimer_t *ptimer, int thr_num, kmem_pool_t mp)
{
	*ptimer = kalloc_t(mp, ktimer);
	if (NULL == *ptimer)
	{
		return 1;
	}
	if (0 != kminheap_init(&((*ptimer)->minheap), K_TIMER_SIZE, mp))
	{
		kfree(mp, *ptimer);
		return 1;
	}
	if (0 == thr_num)
	{
		thr_num = K_TIMER_THR;
	}
	if (0 != kthreadpool_init(&((*ptimer)->threadpool), thr_num, mp))
	{
		kfree(mp, (*ptimer)->minheap);
		kfree(mp, *ptimer);
		return 1;
	}
	(*ptimer)->mp = mp;
	(*ptimer)->used_time = 0;
	kminheap_set_data((*ptimer)->minheap, *ptimer);
	kthread_mutex_init(&((*ptimer)->mtx), NULL);
	kthread_cond_init(&((*ptimer)->cnd), NULL);
	return 0;
}

int 
ktimer_uninit(ktimer_t timer)
{
	if (NULL == timer)
	{
		return 0;
	}
	if (0 == katomic_get(timer->isrunning))
	{
		return 0;
	}
	katomic_set(timer->isrunning, 0);
	kthread_cond_signal(&timer->cnd);
	kthread_join(timer->tid, NULL);
	while (1)
	{
		kminheap_node_t node = kminheap_pop(timer->minheap);
		if (NULL == node)
		{
			break;
		}
		ktimer_node_uninit((ktimer_node_t)node->value);
	}
	kthreadpool_uninit(timer->threadpool);
	kminheap_uninit(timer->minheap);
	kthread_mutex_destroy(&timer->mtx);
	kthread_cond_destroy(&timer->cnd);
	kfree(timer->mp, timer);
	return 0;
}

int 
ktimer_isrunning(ktimer_t timer)
{
	return katomic_get(timer->isrunning);
}

int 
ktimer_set_data(ktimer_t timer, void *data)
{
	timer->data = data;
	return 0;
}

void *
ktimer_get_data(ktimer_t timer)
{
	return timer->data;
}

int 
ktimer_add(ktimer_t timer, ktimer_node_t node)
{
	int ret = 0;
	kthread_mutex_lock(&timer->mtx);
	node->minheap_node->key = node->time + timer->used_time;
	node->timer = timer;
	ret = kminheap_add(timer->minheap, node->minheap_node);
	kthread_cond_signal(&timer->cnd);
	kthread_mutex_unlock(&timer->mtx);
	return ret;
}

int 
ktimer_remove(ktimer_t timer, ktimer_node_t node)
{
	int ret = 0;
	kthread_mutex_lock(&timer->mtx);
	ret = kminheap_remove(timer->minheap, node->minheap_node);
	if (0 == ret)
	{
		node->minheap_node = NULL;
		ktimer_node_uninit(node);
	}
	else
	{
		node->minheap_node->key = -1;
		kthread_cond_signal(&timer->cnd);
	}
	kthread_mutex_unlock(&timer->mtx);
	return ret;
}

static int
timer_foreach_cb(kminheap_t minheap, kminheap_node_t node, void *p)
{
	ktimer_cb cb = (ktimer_cb)p;
	ktimer_node_t timer_node = (ktimer_node_t)node->value;
	return timer_node->cb == cb;
}

int 
ktimer_find(ktimer_t timer, ktimer_cb cb)
{
	int ret = 1;
	kthread_mutex_lock(&timer->mtx);
	if (0 != kminheap_foreach(timer->minheap, timer_foreach_cb, cb))
	{
		ret = 0;
	}
	kthread_mutex_unlock(&timer->mtx);
	return ret;
}

int 
ktimer_foreach(ktimer_t timer, ktimer_foreach_cb cb, void *p)
{
	int ret = 1;
	kminheap_node_t node = NULL;
	kthread_mutex_lock(&timer->mtx);
	node = kminheap_top(timer->minheap);
	while (node)
	{
		ktimer_node_t timer_node = (ktimer_node_t)node->value;
		if (0 != cb(timer, timer_node, p))
		{
			ret = 0;
			break;
		}
		node = kminheap_next(timer->minheap, node);
	}
	kthread_mutex_unlock(&timer->mtx);
	return ret;
}

static void
timer_thread_run(void *args)
{
	ktimer_node_t arg_node = (ktimer_node_t)args;
	ktimer_t timer = arg_node->timer;
	if (NULL == timer || NULL == arg_node)
	{
		printf("NULL == timer || NULL == arg_node \n");
		return;
	}
	if (NULL == arg_node->cb)
	{
		printf("NULL == arg_node->cb\n");
		return;
	}
	arg_node->cb(timer, arg_node->time, arg_node->count, arg_node->data);
	ktimer_node_uninit(arg_node);
}

static kthread_result_t KTHREAD_CALL
timer_run(void *args)
{
	kminheap_node_t node = NULL;
	ktimer_t timer = (ktimer_t)args;
	int timeout = 0;
	int ret = 0;
	int wait_time = 0;
	while (1)
	{
		ktimer_node_t time_node = NULL;
		ktimer_node_t arg_node = NULL;
		kthread_mutex_lock(&timer->mtx);
		node = (kminheap_node_t)kminheap_top(timer->minheap);
		if (NULL == node)
		{
			kthread_cond_wait(&timer->cnd, &timer->mtx);
		}
		if (0 == katomic_get(timer->isrunning))
		{
			kthread_mutex_unlock(&timer->mtx);
			break;
		}
		node = (kminheap_node_t)kminheap_pop(timer->minheap);
		if (NULL == node)
		{
			kthread_mutex_unlock(&timer->mtx);
			break;
		}
		if (0 >= node->key)
		{
			ktimer_node_uninit((ktimer_node_t)node->value);
			kthread_mutex_unlock(&timer->mtx);
			continue;
		}
		timeout = node->key - timer->used_time;
		wait_time = (int)time(NULL);
		if (0 > timeout)
		{
			timeout = 0;
		}
		ret = kthread_cond_timedwait(&timer->cnd, &timer->mtx, timeout);
		if (0 == ret)
		{
			if (0 < node->key)
			{
				int need_time = timeout - ((int)time(NULL) - wait_time);
				node->key = need_time + timer->used_time;
				kminheap_add(timer->minheap, node);
			}
			kthread_mutex_unlock(&timer->mtx);
			continue;
		}
		else if (K_TIMEOUT == ret)
		{
			//timeout
			timer->used_time = node->key;
		}
		else
		{
			//error
			printf("kthread_cond_timedwait %d\n", k_errno());
			kthread_mutex_unlock(&timer->mtx);
			break;
		}
		time_node = (ktimer_node_t)node->value;
		if (0 >= node->key)
		{
			ktimer_node_uninit(time_node);
			kthread_mutex_unlock(&timer->mtx);
			continue;
		}
		ktimer_node_init(&arg_node, time_node->time, time_node->cb, time_node->count, time_node->mp);
		ktimer_node_set_data(arg_node, time_node->data);
		arg_node->timer = timer;
		kthreadpool_run(timer->threadpool, timer_thread_run, arg_node);
		if (1 == time_node->count)
		{
			ktimer_node_uninit(time_node);
			kthread_mutex_unlock(&timer->mtx);
			continue;
		}
		if (1 < time_node->count)
		{
			time_node->count --;
		}
		node->key = time_node->time + timer->used_time;
		kminheap_add(timer->minheap, node);
		kthread_mutex_unlock(&timer->mtx);
	}
	return 0;
}

int 
ktimer_start(ktimer_t timer)
{
	if (1 == katomic_get(timer->isrunning))
	{
		return 0;
	}
	katomic_set(timer->isrunning, 1);
	kthreadpool_start(timer->threadpool);
	kthread_create(&timer->tid, NULL, timer_run, timer);
	return 0;
}


/************************************************************************/
/*				kvalist                                                 */
/************************************************************************/

typedef struct kva kva, *kva_t;

struct kva 
{
	uchar type;
	union
	{
		int ival;
		float fval;
		char *data;
	};
};

struct kvalist 
{
	kva_t *vas;
	kmem_pool_t mp;
	uint headindex;
	uint tailindex;
	uint maxsize;
	uint len;
};

int 
kvalist_init(kvalist_t *pvalist, kmem_pool_t mp)
{
	*pvalist = kalloc_t(mp, kvalist);
	if (NULL == *pvalist)
	{
		return 1;
	}
	(*pvalist)->vas = kalloc(mp, K_VALIST_SIZE * sizeof(kva_t));
	if (NULL == (*pvalist)->vas)
	{
		kfree(mp, *pvalist);
		return 1;
	}
	(*pvalist)->mp = mp;
	(*pvalist)->headindex = 0;
	(*pvalist)->tailindex = 0;
	(*pvalist)->len = 0;
	(*pvalist)->maxsize = K_VALIST_SIZE;
	return 0;
}

int 
kvalist_uninit(kvalist_t valist)
{
	kvalist_clear(valist);
	kfree(valist->mp, valist->vas);
	kfree(valist->mp, valist);
	return 0;
}

int 
kvalist_count(kvalist_t valist)
{
	return valist->tailindex - valist->headindex;
}

int 
kvalist_clear(kvalist_t valist)
{
	uint i = 0;
	for (i = valist->headindex; i < valist->tailindex; ++i)
	{
		kva_t va = valist->vas[i];
		if (type_string == va->type && va->data)
		{
			kfree(valist->mp, va->data);
		}
		kfree(valist->mp, va);
		valist->vas[i] = NULL;
	}
	valist->headindex = 0;
	valist->tailindex = 0;
	valist->len = 0;
	return 0;
}

uchar 
kvalist_type(kvalist_t valist, uint index)
{
	kva_t va = NULL;
	if (index + valist->headindex >= valist->tailindex)
	{
		return type_unknown;
	}
	va = valist->vas[index];
	if (NULL == va)
	{
		return type_unknown;
	}
	return va->type;
}

static int
kvalist_expand(kvalist_t valist)
{
	uint oldx = valist->maxsize * sizeof(kva_t);
	uint newx = oldx + K_VALIST_SIZE * sizeof(kva_t);
	valist->vas = krealloc(valist->mp, valist->vas, oldx, newx);
	if (NULL == valist->vas)
	{
		return 1;
	}
	valist->maxsize += K_VALIST_SIZE;
	return 0;
}

int 
kvalist_push_int(kvalist_t valist, int val)
{
	kva_t va = NULL;
	if (valist->tailindex >= valist->maxsize)
	{
		if (0 != kvalist_expand(valist))
		{
			return 1;
		}
	}
	va = kalloc_t(valist->mp, kva);
	va->type = type_int;
	va->ival = val;
	valist->vas[valist->tailindex ++] = va;
	valist->len += sizeof(int) + sizeof(uchar);
	return 0;
}

int 
kvalist_push_float(kvalist_t valist, float val)
{
	kva_t va = NULL;
	if (valist->tailindex >= valist->maxsize)
	{
		if (0 != kvalist_expand(valist))
		{
			return 1;
		}
	}
	va = kalloc_t(valist->mp, kva);
	va->type = type_float;
	va->fval = val;
	valist->vas[valist->tailindex ++] = va;
	valist->len += sizeof(float) + sizeof(uchar);
	return 0;
}

int 
kvalist_push_string(kvalist_t valist, char *val)
{
	kva_t va = NULL;
	if (valist->tailindex >= valist->maxsize)
	{
		if (0 != kvalist_expand(valist))
		{
			return 1;
		}
	}
	va = kalloc_t(valist->mp, kva);
	va->type = type_string;
	va->data = kalloc(valist->mp, strlen(val) + 1);
	strcpy(va->data, val);
	valist->vas[valist->tailindex ++] = va;
	valist->len += strlen(val) + 1 + sizeof(uchar);
	return 0;
}

int 
kvalist_pop_int(kvalist_t valist)
{
	int ret = 0;
	kva_t va = valist->vas[valist->headindex];
	do 
	{
		if (NULL == va)
		{
			printf("NULL == va\n");
			break;
		}
		if (type_int != va->type)
		{
			printf("type_int != va->type\n");
			break;
		}
		ret = va->ival;
		valist->vas[valist->headindex++] = NULL;
		valist->len -= sizeof(int) + sizeof(uchar);
		kfree(valist->mp, va);
	} while (0);
	return ret;
}

float 
kvalist_pop_float(kvalist_t valist)
{
	float ret = 0.0;
	kva_t va = valist->vas[valist->headindex];
	do 
	{
		if (NULL == va)
		{
			printf("NULL == va\n");
			break;
		}
		if (type_float != va->type)
		{
			printf("type_float != va->type\n");
			break;
		}
		ret = va->fval;
		valist->vas[valist->headindex++] = NULL;
		valist->len -= sizeof(float) + sizeof(uchar);
		kfree(valist->mp, va);
	} while (0);
	return ret;
}

char *
kvalist_pop_string(kvalist_t valist)
{
	char *ret = "";
	kva_t va = valist->vas[valist->headindex];
	do 
	{
		if (NULL == va)
		{
			printf("NULL == va\n");
			break;
		}
		if (type_string != va->type)
		{
			printf("type_string != va->type\n");
			break;
		}
		if (NULL == va->data)
		{
			printf("NULL == va->data\n");
			break;
		}
		ret = kalloc(valist->mp, strlen(va->data) + 1);
		strcpy(ret, va->data);
		valist->vas[valist->headindex++] = NULL;
		valist->len -= strlen(va->data) + 1 + sizeof(uchar);
		kfree(valist->mp, va->data);
		kfree(valist->mp, va);
	} while (0);
	return ret;
}


int 
kvalist_set_int(kvalist_t valist, uint index, int val)
{
	do 
	{
		kva_t va = NULL;
		if (index + valist->headindex >= valist->tailindex)
		{
			break;
		}
		va = valist->vas[index];
		if (NULL == va)
		{
			break;
		}
		if (type_int != va->type)
		{
			break;
		}
		va->ival = val;
		return 0;
	} while (0);
	return 1;
}

int 
kvalist_set_float(kvalist_t valist, uint index, float val)
{
	do 
	{
		kva_t va = NULL;
		if (index + valist->headindex >= valist->tailindex)
		{
			break;
		}
		va = valist->vas[index];
		if (NULL == va)
		{
			break;
		}
		if (type_float != va->type)
		{
			break;
		}
		va->fval = val;
		return 0;
	} while (0);
	return 1;
}

int 
kvalist_set_string(kvalist_t valist, uint index, char *val)
{
	do 
	{
		kva_t va = NULL;
		if (index + valist->headindex >= valist->tailindex)
		{
			break;
		}
		va = valist->vas[index];
		if (NULL == va)
		{
			break;
		}
		if (type_string != va->type)
		{
			break;
		}
		va->data = krealloc(valist->mp, va->data, strlen(va->data) + 1, strlen(val) + 1);
		strcpy(va->data, val);
		valist->len += strlen(val);
		valist->len -= strlen(va->data);
		return 0;
	} while (0);
	return 1;
}

int 
kvalist_append(kvalist_t valist, kvalist_t appendlist)
{
	uint i = 0;
	kva_t va = NULL;
	kva_t newva = NULL;
	for (i = appendlist->headindex; i < appendlist->tailindex; ++i)
	{
		if (valist->tailindex >= valist->maxsize)
		{
			if (0 != kvalist_expand(valist))
			{
				return 1;
			}
			i--;
			continue;
		}
		va = appendlist->vas[i];
		if (NULL == va)
		{
			continue;
		}
		newva = kalloc_t(valist->mp, kva);
		memcpy(newva, va, sizeof(kva));
		if (type_int == va->type)
		{
			valist->len += sizeof(int) + sizeof(uchar);
		}
		else if (type_float == va->type)
		{
			valist->len += sizeof(float) + sizeof(uchar);
		}
		else if (type_string == va->type)
		{
			newva->data = kalloc(valist->mp, strlen(va->data) + 1);
			strcpy(newva->data, va->data);
			valist->len += strlen(va->data) + 1 + sizeof(uchar);
		}
		valist->vas[valist->tailindex ++] = newva;
	}
	return 0;
}

int 
kvalist_data_len(kvalist_t valist)
{
	return valist->len;
}

int 
kvalist_serial(kvalist_t valist, char *data)
{
	uint i = 0;
	uint index = 0;
	for (i = valist->headindex; i < valist->tailindex; ++i)
	{
		kva_t va = valist->vas[i];
		uchar type = type_unknown;
		if (NULL == va)
		{
			printf("NULL == va\n");
			continue;
		}
		type = va->type;
		if (type_unknown == type)
		{
			printf("type_unknown == type\n");
			continue;
		}
		memcpy(data + index, &type, sizeof(uchar));
		index += sizeof(uchar);
		switch (type)
		{
		case type_int:
			{
				memcpy(data + index, &va->ival, sizeof(int));
				index += sizeof(int);
			}
			break;
		case type_float:
			{
				memcpy(data + index, &va->fval, sizeof(float));
				index += sizeof(float);
			}
			break;
		case type_string:
			{
				memcpy(data + index, va->data, strlen(va->data) + 1);
				index += strlen(va->data) + 1;
			}
			break;
		default:
			printf("kvalist_serial warning, type:%d\n", type);
			break;
		}
	}
	return 0;
}

int 
kvalist_deserial(kvalist_t valist, char *data, uint len)
{
	uint index = 0;
	uchar type = type_unknown;
	while (index < len)
	{
		type = *(uchar *)(data + index);
		index += sizeof(uchar);
		switch (type)
		{
		case type_int:
			{
				int ival = *(int *)(data + index);
				index += sizeof(int);
				kvalist_push_int(valist, ival);
			}
			break;
		case type_float:
			{
				float fval = *(float *)(data + index);
				index += sizeof(float);
				kvalist_push_float(valist, fval);
			}
			break;
		case type_string:
			{
				char *val = data + index;
				index += strlen(val) + 1;
				kvalist_push_string(valist, val);
			}
			break;
		default:
			printf("kvalist_deserial warning, type:%d\n", type);
			break;
		}
	}
	return 0;
}

int 
kvalist_dump(kvalist_t valist)
{
	uint i = 0;
	printf("*****************************\n");
	printf("headindex:%d, tailindex:%d\n", valist->headindex, valist->tailindex);
	printf("count:%d, maxsize:%d, len:%d\n", kvalist_count(valist), valist->maxsize, valist->len);
	for (i = valist->headindex; i < valist->tailindex; ++i)
	{
		uchar type = type_unknown;
		kva_t va = valist->vas[i];
		if (NULL == va)
		{
			continue;
		}
		type = va->type;
		switch (type)
		{
		case type_int:
			{
				printf("i:%d,type:%d,val:%d\n", i, type, va->ival);
			}
			break;
		case type_float:
			{
				printf("i:%d,type:%d,val:%f\n", i, type, va->fval);
			}
			break;
		case type_string:
			{
				printf("i:%d,type:%d,val:%s\n", i, type, va->data);
			}
			break;
		default:
			printf("i:%d, unknowtype\n", i);
			break;
		}
	}

	return 0;
}



//khashmap

/************************************************************************/
/*				khashmap                                                */
/************************************************************************/


/* Robert Jenkins' 32 bit Mix Function */
static int
khash_default_hash(void *key, int size)
{
	uint hashkey = (uint)key;
	hashkey += (hashkey << 12);
	hashkey ^= (hashkey >> 22);
	hashkey += (hashkey << 4);
	hashkey ^= (hashkey >> 9);
	hashkey += (hashkey << 10);
	hashkey ^= (hashkey >> 2);
	hashkey += (hashkey << 7);
	hashkey ^= (hashkey >> 12);

	/* Knuth's Multiplicative Method */
	hashkey = (hashkey >> 3) * 2654435761U;
	return hashkey & (size - 1);
}

#define mix(a,b,c) \
{ \
	a -= b; a -= c; a ^= (c>>13); \
	b -= c; b -= a; b ^= (a<<8); \
	c -= a; c -= b; c ^= (b>>13); \
	a -= b; a -= c; a ^= (c>>12); \
	b -= c; b -= a; b ^= (a<<16); \
	c -= a; c -= b; c ^= (b>>5); \
	a -= b; a -= c; a ^= (c>>3); \
	b -= c; b -= a; b ^= (a<<10); \
	c -= a; c -= b; c ^= (b>>15); \
}

static uint hash_str( k, length, initval)
register uchar *k;        /* the key */
register uint  length;   /* the length of the key */
register uint  initval;  /* the previous hash, or an arbitrary value */
{
	register uint a,b,c,len;

	/* Set up the internal state */
	len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */ 

	/*------------------------------------ handle most of the key*/
	while (len >= 12)
	{
		a += (k[0] +((uint)k[1]<<8) +((uint)k[2]<<16) +((uint)k[3]<<24));
		b += (k[4] +((uint)k[5]<<8) +((uint)k[6]<<16) +((uint)k[7]<<24));
		c += (k[8] +((uint)k[9]<<8) +((uint)k[10]<<16)+((uint)k[11]<<24));
		mix(a,b,c);
		k += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes*/
	c += length;
	switch(len)              /* all the case statements fall through*/
	{
	case 11: c+=((uint)k[10]<<24);
	case 10: c+=((uint)k[9]<<16);
	case 9 : c+=((uint)k[8]<<8);
		/* the first byte of c is reserved for the length */
	case 8 : b+=((uint)k[7]<<24);
	case 7 : b+=((uint)k[6]<<16);
	case 6 : b+=((uint)k[5]<<8);
	case 5 : b+=k[4];
	case 4 : a+=((uint)k[3]<<24);
	case 3 : a+=((uint)k[2]<<16);
	case 2 : a+=((uint)k[1]<<8);
	case 1 : a+=k[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result*/
	return c;
}

int
khash_default_hash_str(void *key, int size)
{
	uchar * str = (uchar *)key;
	int hashkey = hash_str(str, strlen(str), 0);
	return hashkey & (size - 1);
}


static int
khash_default_cmp(void *key1, void *key2)
{
	if ((int)key1 == (int)key2)
	{
		return 0;
	}
	else if ((int)key1 > (int)key2)
	{
		return 1;
	}
	else
	{
		return -1;
	}
}

typedef struct khash_node khash_node, *khash_node_t;


struct khash_node 
{
	void *key;
	void *value;
	khash_node_t next;
};

struct khashmap 
{
	khash_node_t *buckets;
	uint loadfactor;
	uint size;
	uint capacity;
	uint maxload;
	uint conflict;
	khash_cb cb;
	khash_cmp_cb cmp_cb;

	kmem_pool_t mp;
	void *data;			/*user data*/
};


static int
khash_fit_capacity(uint capacity)
{
	uint newcap = 1;
	while (newcap < capacity)
	{
		newcap <<= 1;
	}
	return newcap;
}

static int
khashmap_expand(khashmap_t map)
{
	uint i = 0;
	uint newpos = 0;
	khash_node_t node = NULL;
	khash_node_t *newbuckets = kalloc(map->mp, (map->capacity<<1) * sizeof(khash_node_t));
	if (NULL == newbuckets)
	{
		return 1;
	}
	for (i = 0; i < map->capacity; ++i)
	{
		node = map->buckets[i];
		if (NULL == node)
		{
			continue;
		}
		newpos = map->cb(node->key, map->capacity);
		newbuckets[newpos] = node;
	}
	map->capacity <<= 1;
	map->maxload = (uint)(map->capacity * ((float)map->loadfactor / 100.0));
	kfree(map->mp, map->buckets);
	map->buckets = newbuckets;
	return 0;
}

int 
khashmap_init(khashmap_t *pmap, uint capacity, uint loadfactor, kmem_pool_t mp)
{
	*pmap = kalloc_t(mp, khashmap);
	if (NULL == *pmap)
	{
		return 1;
	}
	
	if (0 == capacity)
	{
		(*pmap)->capacity = K_HASHMAP_SIZE;	
	}
	else
	{
		(*pmap)->capacity = khash_fit_capacity(capacity);
	}
	if (0 == loadfactor)
	{
		(*pmap)->loadfactor = K_HASHMAP_LOAD;
	}
	else
	{
		(*pmap)->loadfactor = loadfactor;
	}
	(*pmap)->mp = mp;
	(*pmap)->size = 0;
	(*pmap)->conflict = 0;
	(*pmap)->maxload = (uint)((*pmap)->capacity * ((float)(*pmap)->loadfactor / 100.0));
	(*pmap)->cb = khash_default_hash;
	(*pmap)->cmp_cb = khash_default_cmp;
	(*pmap)->buckets = kalloc(mp, (*pmap)->capacity * sizeof(khash_node_t));
	if (NULL == (*pmap)->buckets)
	{
		kfree(mp, *pmap);
		return 1;
	}
	return 0;
}

static int
khashmap_node_uninit(khashmap_t map, khash_node_t node)
{
	if (NULL != node->next)
	{
		khashmap_node_uninit(map, node->next);
	}
	kfree(map->mp, node);
	return 0;
}

int 
khashmap_uninit(khashmap_t map)
{
	uint i = 0;
	for (i = 0; i < map->capacity; ++i)
	{
		if (NULL != map->buckets[i])
		{
			khashmap_node_uninit(map, map->buckets[i]);
		}
	}
	kfree(map->mp, map->buckets);
	kfree(map->mp, map);
	return 0;
}

int 
khashmap_set_hash(khashmap_t map, khash_cb cb)
{
	map->cb = cb;
	return 0;
}

int 
khashmap_set_cmp(khashmap_t map, khash_cmp_cb cb)
{
	map->cmp_cb = cb;
	return 0;
}

int 
khashmap_set_data(khashmap_t map, void *data)
{
	map->data = data;
	return 0;
}

void *
khashmap_get_data(khashmap_t map)
{
	return map->data;
}

int 
khashmap_insert(khashmap_t map, void *key, void *value)
{
	uint pos = 0;
	khash_node_t node = NULL;
	if (NULL != khashmap_find(map, key))
	{
		return 1;
	}
	if (map->size > map->maxload)
	{
		if (0 != khashmap_expand(map))
		{
			return 1;
		}
	}
	pos = map->cb(key, map->capacity);
	if (pos >= map->capacity)
	{
		return 1;
	}
	node = kalloc_t(map->mp, khash_node);
	if (NULL == node)
	{
		return 1;
	}

	node->key = key;
	node->value = value;
	if (NULL != map->buckets[pos])
	{
		node->next = map->buckets[pos];
		map->conflict ++;
	}
	map->buckets[pos] = node;
	map->size ++;
	return 0;
}

void *
khashmap_find(khashmap_t map, void *key)
{
	khash_node_t node = NULL;
	uint pos = map->cb(key, map->capacity);
	if (pos >= map->capacity)
	{
		return NULL;
	}
	node = map->buckets[pos];
	while (node)
	{
		if (0 == map->cmp_cb(key, node->key))
		{
			return node->value;
		}
		node = node->next;
	}
	return NULL;
}

int 
khashmap_set_value(khashmap_t map, void *key, void *value)
{
	khash_node_t node = NULL;
	uint pos = map->cb(key, map->capacity);
	if (pos >= map->capacity)
	{
		return 1;
	}
	node = map->buckets[pos];
	while (node)
	{
		if (0 == map->cmp_cb(key, node->key))
		{
			node->value = value;
			return 0;
		}
		node = node->next;
	}
	return 1;
}

int 
khashmap_erase(khashmap_t map, void *key)
{
	khash_node_t node = NULL;
	khash_node_t tmpnode = NULL;
	uint pos = map->cb(key, map->capacity);
	if (pos >= map->capacity)
	{
		return 1;
	}
	node = map->buckets[pos];
	if (NULL == node)
	{
		return 1;
	}
	if (node->key == key)
	{
		kfree(map->mp, node);
		map->buckets[pos] = NULL;
		map->size --;
		return 0;
	}
	tmpnode = node->next;
	while (tmpnode)
	{
		if (key == tmpnode->key)
		{
			node->next = tmpnode->next;
			kfree(map->mp, tmpnode);
			map->size --;
			return 0;
		}
		node = node->next;
		tmpnode = node->next;
	}
	return 1;
}

int 
khashmap_size(khashmap_t map)
{
	return map->size;
}

int 
khashmap_foreach(khashmap_t map, khashmap_foreach_cb cb, void *p)
{
	uint i = 0;
	khash_node_t node = NULL;
	for (i = 0; i < map->capacity; ++i)
	{
		node = map->buckets[i];
		if (NULL == node)
		{
			continue;
		}
		if (0 != cb(map, node->key, node->value, p))
		{
			break;
		}
	}
	return 0;
}

int 
khashmap_conflict(khashmap_t map)
{
	return map->conflict;
}



/************************************************************************/
/*						k_quicksort                                     */
/************************************************************************/

static int
k_quicksort_cmp(int data1, int data2)
{
	return data1 - data2;
}

static void
k_quicksort_swap(int *data1, int *data2)
{
	int tmp = *data1;
	*data1 = *data2;
	*data2 = tmp;
}

static void
k_quicksort_t(int data[], int first, int last)
{
	int bound = 0;
	int lower = first + 1;
	int upper = last;
	k_quicksort_swap(&data[first], &data[(first + last) / 2]);
	bound = data[first];
	while (lower <= upper)
	{
		while (0 > k_quicksort_cmp(data[lower], bound))
		{
			lower ++;
		}
		while (0 > k_quicksort_cmp(bound, data[upper]))
		{
			upper --;
		}
		if (lower < upper)
		{
			k_quicksort_swap(&data[lower ++], &data[upper --]);
		}
		else
		{
			lower ++;
		}
	}
	k_quicksort_swap(&data[upper], &data[first]);
	if (first < upper - 1)
	{
		k_quicksort_t(data, first, upper - 1);
	}
	if (upper + 1 < last)
	{
		k_quicksort_t(data, upper + 1, last);
	}
}

void
k_quicksort(int data[], int n)
{
	int i = 0;
	int max = 0;
	if (2 > n)
	{
		return;
	}
	for (i = 1, max = 0; i < n; ++i)
	{
		if (0 > k_quicksort_cmp(data[max], data[i]))
		{
			max = i;
		}
	}
	k_quicksort_swap(&data[n - 1], &data[max]);
	k_quicksort_t(data, 0, n - 2);
}


/************************************************************************/
/*				kquadtree                                               */
/************************************************************************/

struct kquad_node
{
	kquad_box_t box;
	klist_t node_list;
	kquad_node_t sub_nodes[KQUAD_SUBS];
	void *data;			/*user data*/
};

struct kquad_tree
{
	kquad_node_t root;
	int depth;
	float overlap;
	kmem_pool_t mp;
};


int
kquad_box_init(kquad_box_t * pbox, int xmin, int ymin, int xmax, int ymax, kmem_pool_t mp)
{
	*pbox = kalloc_t(mp, kquad_box);
	if (NULL == *pbox)
	{
		return 1;
	}
	(*pbox)->mp = mp;
	(*pbox)->xmin = xmin;
	(*pbox)->ymin = ymin;
	(*pbox)->xmax = xmax;
	(*pbox)->ymax = ymax;
	return 0;
}

int 
kquad_box_uninit(kquad_box_t box)
{
	kfree(box->mp, box);
	return 0;
}

int 
kquad_box_set_data(kquad_box_t box, void *data)
{
	box->data = data;
	return 0;
}

void *
kquad_box_get_data(kquad_box_t box)
{
	return box->data;
}

static void 
kquad_box_split(const kquad_box_t box, kquad_box_t *ne, kquad_box_t *nw, kquad_box_t *se, kquad_box_t *sw, float overlap, kmem_pool_t mp)
{
	int dx = (int)((box->xmax - box->xmin) * (1.0 + overlap) / 2);
	int dy = (int)((box->ymax - box->ymin) * (1.0 + overlap) / 2);

	kquad_box_init(ne, box->xmax - dx, box->ymax - dy, box->xmax, box->ymax, mp);
	kquad_box_init(nw, box->xmin, box->ymax - dy, box->xmin + dx, box->ymax, mp);
	kquad_box_init(sw, box->xmin, box->ymin, box->xmin + dx, box->ymin + dy, mp);
	kquad_box_init(se, box->xmax - dx, box->ymin, box->xmax, box->ymin + dy, mp);
}


static int
kquad_node_init(kquad_node_t *pnode, kquad_box_t box, kmem_pool_t mp)
{
	*pnode = kalloc_t(mp, kquad_node);
	if (NULL == *pnode)
	{
		return 1;
	}
	(*pnode)->box = box;
	return 0;
}

static int
kquad_node_uninit(kquad_node_t node, kmem_pool_t mp)
{
	if (NULL == node)
	{
		return 1;
	}
	if (0 != node->sub_nodes[NE])
	{
		kquad_node_uninit(node->sub_nodes[NE], mp);
		kquad_node_uninit(node->sub_nodes[NW], mp);
		kquad_node_uninit(node->sub_nodes[SE], mp);
		kquad_node_uninit(node->sub_nodes[SW], mp);
	}
	if (NULL != node->node_list)
	{
		klist_uninit(node->node_list);
	}
	kquad_box_uninit(node->box);
	kfree(mp, node);
	return 0;
}



static int
kquad_node_create_child(kquad_node_t node, int depth, float overlap, kmem_pool_t mp)
{
	kquad_box_t ne, nw, se, sw;

	kquad_box_split(node->box, &ne, &nw, &se, &sw, overlap, mp);

	kquad_node_init(&(node->sub_nodes[NE]), ne, mp);
	kquad_node_init(&(node->sub_nodes[NW]), nw, mp);
	kquad_node_init(&(node->sub_nodes[SW]), sw, mp);
	kquad_node_init(&(node->sub_nodes[SE]), se, mp);
	return 0;
}

static void
kquad_box_inflate(kquad_box_t box, int dx, int dy)
{
	if (dx <= 0 || dy <= 0)
	{
		return;
	}
	box->xmin -= dx / 2;
	box->xmax += dx / 2;
	box->ymin -= dy / 2;
	box->ymax += dy / 2;
}

static int
kquad_box_inside(const kquad_box_t first, const kquad_box_t second)
{
	return (second->xmin < first->xmin && second->xmax > first->xmax && 
		second->ymin < first->ymin && second->ymax > first->ymax) ? 1 : 0;
}

static int
kquad_box_overlapped(const kquad_box_t first, const kquad_box_t second)
{
	return (first->xmin > second->xmax || first->xmax < second->xmin ||
		first->ymin > second->ymax || first->ymax < second->ymin) ? 0 : 1;
}

static int
kquadtree_insert_node(kquad_tree_t tree, kquad_node_t parent, kquad_box_t box, int *depth)
{
	if (parent == tree->root)
	{
		if (!kquad_box_overlapped(box, parent->box))
		{
			return 1;
		}
	}
	else
	{
		if (!kquad_box_inside(box, parent->box))
		{
			return 1;
		}
	}
	if (++(*depth) < tree->depth)
	{
		if (0 == parent->sub_nodes[NE])
		{
			kquad_node_create_child(parent, (*depth), tree->overlap, tree->mp);
		}
		if (kquad_box_inside(box, parent->sub_nodes[NE]->box))
		{
			return kquadtree_insert_node(tree, parent->sub_nodes[NE], box, depth);
		}
		if (kquad_box_inside(box, parent->sub_nodes[NW]->box))
		{
			return kquadtree_insert_node(tree, parent->sub_nodes[NW], box, depth);
		}
		if (kquad_box_inside(box, parent->sub_nodes[SW]->box))
		{
			return kquadtree_insert_node(tree, parent->sub_nodes[SW], box, depth);
		}
		if (kquad_box_inside(box, parent->sub_nodes[SE]->box))
		{
			return kquadtree_insert_node(tree, parent->sub_nodes[SE], box, depth);
		}
	}
	if (NULL == parent->node_list)
	{
		klist_init(&(parent->node_list), tree->mp);
	}
	//printf("node:0x%x,box:0x%x,%d,%d,%d,%d, insert box:%d,%d,%d,%d\n", (int)parent, (int)box, parent->box->xmin, parent->box->ymin, parent->box->xmax, parent->box->ymax, 
		//box->xmin, box->ymin, box->xmax, box->ymax);
	klist_push(parent->node_list, box);
	return 0;
}

static void
kquadtree_search_node(kquad_node_t node, kquad_box_t box, klist_t ret_list)
{
	if (!kquad_box_overlapped(node->box, box))
	{
		return;
	}
	if (NULL != node->node_list)
	{
		klist_node_t list_node = node->node_list->head;
		while (list_node)
		{
			kquad_box_t tmpbox = (kquad_box_t)list_node->data;
			if (kquad_box_overlapped(tmpbox, box))
			{
				klist_push(ret_list, list_node->data);
			}
			list_node = list_node->next;
		}
	}
	if (NULL != node->sub_nodes[NE])
	{
		kquadtree_search_node(node->sub_nodes[NE], box, ret_list);
		kquadtree_search_node(node->sub_nodes[NW], box, ret_list);
		kquadtree_search_node(node->sub_nodes[SW], box, ret_list);
		kquadtree_search_node(node->sub_nodes[SE], box, ret_list);
	}
}


static int 
kquadtree_foreach_node(kquad_tree_t tree, kquad_node_t node, kquadtree_foreach_cb cb, void *p)
{
	if (0 != node->sub_nodes[NE])
	{
		if (0 != kquadtree_foreach_node(tree, node->sub_nodes[NE], cb, p))
		{
			return 1;
		}
		if (0 != kquadtree_foreach_node(tree, node->sub_nodes[NW], cb, p))
		{
			return 1;
		}
		if (0 != kquadtree_foreach_node(tree, node->sub_nodes[SE], cb, p))
		{
			return 1;
		}
		if (0 != kquadtree_foreach_node(tree, node->sub_nodes[SW], cb, p))
		{
			return 1;
		}
	}
	return cb(node, p);
}


int 
kquadtree_init(kquad_tree_t *ptree, kquad_box_t box, int depth, float overlap, kmem_pool_t mp)
{
	if (depth > KQTREE_DEPTH_MAX || depth < KQTREE_DEPTH_MIN)
	{
		return 1;
	}
	if (overlap > KQBOX_OVERLAP_MAX || overlap < KQBOX_OVERLAP_MIN)
	{
		return 1;
	}
	*ptree = kalloc_t(mp, kquad_tree);
	if (NULL == *ptree)
	{
		return 1;
	}
	kquad_box_inflate(box, (int)((box->xmax - box->xmin) * overlap), (int)((box->ymax - box->ymin) * overlap));
	if (0 != kquad_node_init(&(*ptree)->root, box, mp))
	{
		kfree(mp, *ptree);
		return 1;
	}
	(*ptree)->depth = depth;
	(*ptree)->overlap = overlap;
	return 0;
}

void 
kquadtree_search(kquad_tree_t tree, kquad_box_t search_box, klist_t ret_list)
{
	kquadtree_search_node(tree->root, search_box, ret_list);
}

int 
kquadtree_insert(kquad_tree_t tree, kquad_box_t box)
{
	int depth = -1;
	return kquadtree_insert_node(tree, tree->root, box, &depth);
}

static int
kquadtree_erase_cb(kquad_node_t node, void *p)
{
	if (NULL == node->node_list)
	{
		return 0;
	}
	if (0 == klist_erase(node->node_list, p))
	{
		return 1;
	}
	return 0;
}

int 
kquadtree_erase(kquad_tree_t tree, kquad_box_t box)
{
	kquadtree_foreach_node(tree, tree->root, kquadtree_erase_cb, box);
	return 0;
}

int 
kquadtree_foreach(kquad_tree_t tree, kquadtree_foreach_cb cb, void *p)
{
	return kquadtree_foreach_node(tree, tree->root, cb, p);
}

int 
kquadtree_clear(kquad_tree_t tree)
{
	kquad_node_uninit(tree->root->sub_nodes[NE], tree->mp);
	kquad_node_uninit(tree->root->sub_nodes[NW], tree->mp);
	kquad_node_uninit(tree->root->sub_nodes[SE], tree->mp);
	kquad_node_uninit(tree->root->sub_nodes[SW], tree->mp);
	tree->root->sub_nodes[NE] = NULL;
	tree->root->sub_nodes[NW] = NULL;
	tree->root->sub_nodes[SE] = NULL;
	tree->root->sub_nodes[SW] = NULL;
	return 0;
}

int 
kquadtree_uninit(kquad_tree_t tree)
{
	kquad_node_uninit(tree->root, tree->mp);
	tree->root = NULL;
	kfree(tree->mp, tree);
	return 0;
}


/************************************************************************/
/*				kcrosslist                                              */
/************************************************************************/

struct kcross_node
{
	int x;
	int y;

	kcross_node_t right;
	kcross_node_t down;

	void *data;			/*node data*/
};

struct kcrosslist
{
	kcross_node_t vhead;
	kcross_node_t hhead;

	int size;

	kmem_pool_t mp;
	void *data;			/*user data*/
};

static int
kcross_node_init(kcross_node_t *pnode, int x, int y, void *data, kmem_pool_t mp)
{
	*pnode = kalloc_t(mp, kcross_node);
	if (NULL == *pnode)
	{
		return 1;
	}
	(*pnode)->x = x;
	(*pnode)->y = y;
	(*pnode)->right = NULL;
	(*pnode)->down = NULL;
	(*pnode)->data = data;
	return 0;
}

static int
kcross_node_uninit(kcross_node_t node, kmem_pool_t mp)
{
	kfree(mp, node);
	return 0;
}


int 
kcrosslist_init(kcrosslist_t *plist, kmem_pool_t mp)
{
	*plist = kalloc_t(mp, kcrosslist);
	if (NULL == *plist)
	{
		return 1;
	}
	(*plist)->mp = mp;
	(*plist)->size = 0;
	(*plist)->vhead = NULL;
	(*plist)->hhead = NULL;
	
	return 0;
}

int 
kcrosslist_uninit(kcrosslist_t list)
{
	kcrosslist_clear(list);
	kfree(list->mp, list);
	return 0;
}

int 
kcrosslist_insert(kcrosslist_t list, int x, int y, void *data)
{

	return 0;
}

int 
kcrosslist_erase(kcrosslist_t list, int x, int y)
{

	return 0;
}

int 
kcrosslist_size(kcrosslist_t list)
{
	return list->size;
}

int 
kcrosslist_search(kcrosslist_t list, int x, int y, klist_t ret_list)
{

	return 0;
}

int 
kcrosslist_clear(kcrosslist_t list)
{

	return 0;
}




/************************************************************************/
/*				kaoi                                                    */
/************************************************************************/

int 
kaoi_obj_init(kaoi_obj_t *pobj, int x, int y, int type, int radius, kmem_pool_t mp)
{
	*pobj = kalloc_t(mp, kaoi_obj);
	if (NULL == *pobj)
	{
		return 1;
	}
	if (0 != kquad_box_init(&((*pobj)->box), x - radius, y - radius, x + radius, y + radius, mp))
	{
		kfree(mp, *pobj);
		return 1;
	}
	if (KAOI_WATCHER & type)
	{
		if (0 != khashmap_init(&((*pobj)->vis_map), KAOI_MAX_VIS, 75, mp))
		{
			kfree(mp, (*pobj)->box);
			kfree(mp, *pobj);
			return 1;
		}
		khashmap_set_data((*pobj)->vis_map, *pobj);
	}
	kquad_box_set_data((*pobj)->box, *pobj);
	klist_init(&((*pobj)->ret_list), mp);
	(*pobj)->mp = mp;
	(*pobj)->x = x;
	(*pobj)->y = y;
	(*pobj)->type = type;
	(*pobj)->radius = radius;

	return 0;
}

int 
kaoi_obj_uninit(kaoi_obj_t obj)
{
	if (NULL == obj)
	{
		return 0;
	}
	if (KAOI_WATCHER & obj->type)
	{
		khashmap_uninit(obj->vis_map);
	}
	kquad_box_uninit(obj->box);
	klist_uninit(obj->ret_list);
	kfree(obj->mp, obj);
	return 0;
}


int 
kaoi_map_init(kaoi_map_t *pmap, int map_w, int map_h, kmem_pool_t mp)
{
	*pmap = kalloc_t(mp, kaoi_map);
	if (NULL == *pmap)
	{
		return 1;
	}
	
	(*pmap)->mp = mp;
	(*pmap)->map_w = map_w;
	(*pmap)->map_h = map_h;

	kquad_box_init(&((*pmap)->tree_box), 0, 0, map_w, map_h, mp);
	kquadtree_init(&((*pmap)->tree), (*pmap)->tree_box, 5, (float)0.03, mp);

	klist_init(&((*pmap)->obj_list), NULL);
	kthread_mutex_init(&((*pmap)->aoi_lock), NULL);
	return 0;
}

int 
kaoi_map_uninit(kaoi_map_t map)
{
	if (NULL == map)
	{
		return 0;
	}
	kquadtree_uninit(map->tree);
	klist_uninit(map->obj_list);
	kthread_mutex_destroy(&map->aoi_lock);
	kfree(map->mp, map);
	return 0;
}

int 
kaoi_map_set_data(kaoi_map_t map, void *data)
{
	map->data = data;
	return 0;
}

void *
kaoi_map_get_data(kaoi_map_t map)
{
	return map->data;
}

int 
kaoi_add_obj(kaoi_map_t map, kaoi_obj_t obj)
{
	kthread_mutex_lock(&map->aoi_lock);
	if (0 != kquadtree_insert(map->tree, obj->box))
	{
		kthread_mutex_unlock(&map->aoi_lock);
		return 1;
	}
	if (KAOI_WATCHER & obj->type)
	{
		klist_push(map->obj_list, obj);
	}
	kthread_mutex_unlock(&map->aoi_lock);
	return 0;
}

int 
kaoi_remove_obj(kaoi_map_t map, kaoi_obj_t obj)
{
	kthread_mutex_lock(&map->aoi_lock);
	if (0 != kquadtree_erase(map->tree, obj->box))
	{
		kthread_mutex_unlock(&map->aoi_lock);
		return 1;
	}
	if (KAOI_WATCHER & obj->type)
	{
		klist_erase(map->obj_list, obj);
	}
	obj->type |= KAOI_DROP;
	kthread_mutex_unlock(&map->aoi_lock);
	return 0;
}

int 
kaoi_move_obj(kaoi_map_t map, kaoi_obj_t obj, int x, int y)
{
	obj->x = x;
	obj->y = y;
	obj->box->xmin = x - obj->radius;
	obj->box->xmax = x + obj->radius;
	obj->box->ymin = y - obj->radius;
	obj->box->ymax = y + obj->radius;
	return 0;
}

static int
kaoi_obj_around_cb(khashmap_t map, void *key, void *value, void *p)
{
	klist_t obj_list = (klist_t)p;
	int status = (int)value;
	kquad_box_t box = (kquad_box_t)key;
	kaoi_obj_t obj = (kaoi_obj_t)kquad_box_get_data(box);
	if (KAOI_STAY == status || KAOI_ENTER == status)
	{
		klist_push(obj_list, obj);
	}
	return 0;
}

int 
kaoi_obj_around(kaoi_map_t map, kaoi_obj_t obj, klist_t obj_list)
{
	khashmap_foreach(obj->vis_map, kaoi_obj_around_cb, obj_list);
	return 0;
}

typedef struct kaoi_foreach_arg
{
	kaoi_cb cb;
	kaoi_map_t map;
}kaoi_foreach_arg, *kaoi_foreach_arg_t;

static int
kaoi_ret_list_cb(void *data, void *p)
{
	kquad_box_t box = (kquad_box_t)data;
	kaoi_obj_t obj = (kaoi_obj_t)p;
	kaoi_obj_t box_obj = (kaoi_obj_t)kquad_box_get_data(box);
	void * value = NULL;

	if (obj->box == box)
	{
		return 0;
	}
	value = khashmap_find(obj->vis_map, box);
	if (value && KAOI_DROP == (int)value)
	{
		return 0;
	}
	if (box_obj->x < obj->box->xmin ||
		box_obj->x > obj->box->xmax ||
		box_obj->y < obj->box->ymin ||
		box_obj->y > obj->box->ymax)
	{
		return 0;
	}

	if (NULL == value)
	{
		khashmap_insert(obj->vis_map, box, (void *)KAOI_ENTER);
	}
	else
	{
		khashmap_set_value(obj->vis_map, box, (void *)KAOI_STAY);
	}
	return 0;
}

static int
kaoi_clear_status_cb(khashmap_t map, void *key, void *value, void *p)
{
	int status = (int)value;
	if (KAOI_DROP != status)
	{
		khashmap_set_value(map, key, (void *)KAOI_LEAVE);
	}
	return 0;
}

static int
kaoi_update_cb(khashmap_t map, void *key, void *value, void *p)
{
	kaoi_foreach_arg arg = *(kaoi_foreach_arg_t)p;
	kaoi_cb cb = arg.cb;
	kaoi_map_t aoi_map = arg.map;
	kquad_box_t box = (kquad_box_t)key;
	kaoi_obj_t self = (kaoi_obj_t)khashmap_get_data(map);
	kaoi_obj_t obj = (kaoi_obj_t)kquad_box_get_data(box);
	int status = (int)value;

	if (self == obj)
	{
		return 0;
	}
	cb(aoi_map, self, obj, status);
	if (KAOI_LEAVE == status)
	{
		khashmap_erase(map, key);
	}
	else if (KAOI_DROP == status)
	{
		khashmap_erase(map, key);
		kaoi_obj_uninit(obj);
	}
	return 0;
}

static int
kaoi_tick_cb(void *data, void *p)
{
	kaoi_foreach_arg arg = *(kaoi_foreach_arg_t)p;
	kaoi_map_t map = arg.map;
	kaoi_obj_t obj = (kaoi_obj_t)data;
	if (KAOI_WATCHER & obj->type)
	{
		klist_clear(obj->ret_list);
		kquadtree_search(map->tree, obj->box, obj->ret_list);
		khashmap_foreach(obj->vis_map, kaoi_clear_status_cb, NULL);
		klist_foreach(obj->ret_list, kaoi_ret_list_cb, obj);
		khashmap_foreach(obj->vis_map, kaoi_update_cb, p);
	}
	return 0;
}

int 
kaoi_tick(kaoi_map_t map, kaoi_cb cb)
{
	kaoi_foreach_arg arg;
	arg.cb = cb;
	arg.map = map;
	kthread_mutex_lock(&map->aoi_lock);
	klist_foreach(map->obj_list, kaoi_tick_cb, &arg);
	kthread_mutex_unlock(&map->aoi_lock);
	return 0;
}


/************************************************************************/
/*				kserver                                                 */
/************************************************************************/


int 
knet_init(knet_t *pnet, int thr, kmem_pool_t mp)
{
	*pnet = kalloc_t(mp, knet);
	if (NULL == *pnet)
	{
		return 1;
	}
	if (0 != ktcp_init(&(*pnet)->tcp, thr, mp))
	{
		kfree(mp, *pnet);
		return 1;
	}
	(*pnet)->mp = mp;
	(*pnet)->data = NULL;
	ktcp_set_data((*pnet)->tcp, *pnet);
	ktcp_start((*pnet)->tcp);
	return 0;
}

int 
knet_uninit(knet_t net)
{
	ktcp_uninit(net->tcp);
	kfree(net->mp, net);
	return 0;
}

static void
tcp_connectcb(ktcp_t tcp, ktcp_session_t tcp_sess)
{
	knet_t net = (knet_t)ktcp_get_data(tcp);
	ksession_t session = kalloc_t(tcp_sess->mp, ksession);
	session->tcp_sess = tcp_sess;
	kvalist_init(&session->args, tcp_sess->mp);
	kvalist_init(&session->msg, tcp_sess->mp);
	tcp_sess->data = session;
	if (net->connected_cb)
	{
		net->connected_cb(net, session, session->args);
	}
}

static void
tcp_disconnectcb(ktcp_t tcp, ktcp_session_t tcp_sess)
{
	knet_t net = (knet_t)ktcp_get_data(tcp);
	ksession_t session = (ksession_t)tcp_sess->data;
	if (net->disconnected_cb)
	{
		net->disconnected_cb(net, session, session->args);
	}
	kvalist_uninit(session->args);
	kvalist_uninit(session->msg);
	kfree(tcp_sess->mp, session);
}


static void
tcp_readcb(ktcp_t tcp, ktcp_session_t tcp_sess)
{
	int len = kbuffer_readable(tcp_sess->recv_buffer);
	knet_t net = (knet_t)ktcp_get_data(tcp);
	ksession_t session = (ksession_t)tcp_sess->data;
	char *data = kbuffer_read(tcp_sess->recv_buffer, &len);
	kvalist_deserial(session->args, data, len);
	kbuffer_shift(tcp_sess->recv_buffer, len);
	if (net->read_cb)
	{
		net->read_cb(net, session, session->args);
	}
	kvalist_clear(session->args);
}


int 
knet_set_cb(knet_t net, int cb_type, knet_cb cb)
{
	switch (cb_type)
	{
	case KCB_CONNECTED:
		net->connected_cb = cb;
		ktcp_set_cb(net->tcp, cb_type, tcp_connectcb);
		break;
	case KCB_DISCONNECTED:
		net->disconnected_cb = cb;
		ktcp_set_cb(net->tcp, cb_type, tcp_disconnectcb);
		break;
	case KCB_READ:
		net->read_cb = cb;
		ktcp_set_cb(net->tcp, cb_type, tcp_readcb);
		break;
	default:
		break;
	}
	return 0;
}

int 
knet_run_server(knet_t net, int port)
{
	ktcp_listen(net->tcp, port);
	printf("net listen at:%d\n", port);
	return 0;
}

int 
knet_send(knet_t net, ksession_t session)
{
	ktcp_session_t tcp_sess = session->tcp_sess;
	int len = kvalist_data_len(session->msg);
	char *data = kalloc(tcp_sess->mp, len);
	if (NULL == data)
	{
		return 1;
	}
	if (0 != kvalist_serial(session->msg, data))
	{
		kfree(tcp_sess->mp, data);
		return 1;
	}
	if (0 != ktcp_send(net->tcp, tcp_sess, data, len))
	{
		kfree(tcp_sess->mp, data);
		return 1;
	}
	kfree(tcp_sess->mp, data);
	kvalist_clear(session->msg);
	return 0;
}

int 
knet_connect(knet_t net, int selfport, char *ip, int port)
{
	return ktcp_connect(net->tcp, selfport, ip, port);
}

int 
knet_close(knet_t net, ksession_t session)
{
	if (session)
	{
		ktcp_close_session(net->tcp, session->tcp_sess);
		return 0;
	}
	return 1;
}
