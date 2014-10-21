make:
	cl /c src/k.c
	link /dll k.obj

	cl test/time.c
	cl test/time_c.c
	cl test/kbuffer_test.c
	cl test/krbtree_test.c
	cl test/knet_connect_test.c
        cl test/kmempool_test.c
	cl test/kminheap_test.c
	cl test/ktimer_test.c
	cl test/kvalist_test.c
	cl test/khashmap_test.c
	cl test/k_quicksort_test.c
	cl test/kquadtree_test.c
	cl test/kaoi_test.c
	cl test/ktcp_s_test.c
	cl test/ktcp_c_test.c
	cl test/knet_s_test.c
	cl test/knet_c_test.c
	cl test/p2pc.c
	cl test/p2ps.c
	cl test/kdemon_test.c
	cl test/ktest.c

	del *.obj
	del *.exp