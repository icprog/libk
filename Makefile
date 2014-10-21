make :
	gcc src/gprof_helper.c -o libgprof_helper.so -L./ -Wl,-rpath,./ -lpthread -ldl -Bdynamic -fPIC -shared

	gcc src/k.c -o libk.so -g -L./ -Wl,-rpath,./ -lpthread -Bdynamic -fPIC -shared

	gcc test/time.c -o time -g -L./ -Wl,-rpath,./ -lk
	gcc test/time_c.c -o time_c -g -L./ -Wl,-rpath,./ -lk

	gcc test/kbuffer_test.c -o kbuffer_test -g -L./ -Wl,-rpath,./ -lk
	gcc test/krbtree_test.c -o krbtree_test -g -L./ -Wl,-rpath,./ -lk
	gcc test/knet_connect_test.c -o knet_connect_test -g -L./ -Wl,-rpath,./ -lk
	gcc test/kmempool_test.c -o kmempool_test -g -L./ -Wl,-rpath,./ -lk
	gcc test/kminheap_test.c -o kminheap_test -g -L./ -Wl,-rpath,./ -lk
	gcc test/ktimer_test.c -o ktimer_test -g -L./ -Wl,-rpath,./ -lk
	gcc test/kvalist_test.c -o kvalist_test -g -L./ -Wl,-rpath,./ -lk
	gcc test/khashmap_test.c -o khashmap_test -g -L./ -Wl,-rpath,./ -lk
	gcc test/kquadtree_test.c -o kquadtree_test -g -L./ -Wl,-rpath,./ -lk
	gcc test/kaoi_test.c src/k.c -o kaoi_test -g -L./ -Wl,-rpath,./ -lgprof_helper -pg
	gcc test/ktcp_s_test.c -o ktcp_s_test -g -L./ -Wl,-rpath,./ -lk
	gcc test/ktcp_c_test.c -o ktcp_c_test -g -L./ -Wl,-rpath,./ -lk
	gcc test/knet_s_test.c -o knet_s_test -g -L./ -Wl,-rpath,./ -lk
	gcc test/knet_c_test.c -o knet_c_test -g -L./ -Wl,-rpath,./ -lk
	gcc test/p2pc.c -o p2pc -g -L./ -Wl,-rpath,./ -lk
	gcc test/p2ps.c -o p2ps -g -L./ -Wl,-rpath,./ -lk	
	gcc test/kdemon_test.c -o kdemon_test -g -L./ -Wl,-rpath,./ -lk
	gcc test/ktest.c -o ktest -g -L./ -Wl,-rpath,./ -lk

	rm -f *.o
	rm -f *.o
