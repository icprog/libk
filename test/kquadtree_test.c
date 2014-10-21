#include "../src/k.h"

#ifdef _WIN32
#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif


int list_cb(void *data, void *p)
{
	kquad_box_t box = (kquad_box_t)data;

	printf("box:%d,%d,%d,%d\n", box->xmin, box->ymin, box->xmax, box->ymax);
	return 0;
}

int tree_cb(kquad_node_t node, void *p)
{
	//printf("tree node->box:%d,%d,%d,%d\n", node->box.xmin, node->box.ymin, node->box.xmax, node->box.ymax);
	return 0;
}

int
main()
{
#ifdef LINUX
	mtrace();
#endif
	int i = 0;
	int depth = 5;
	float overlap = (float)0.1;
	kquad_box_t treebox;
	kquad_box_t box[5];
	klist_t list;
	kquad_box_t search_box;
	kquad_tree_t tree;

	k_core_dump();
	kmem_check_start();

        klist_init(&list, NULL);

	kquad_box_init(&treebox, 10, 10, 100, 100, NULL);
	
	kquadtree_init(&tree, treebox, depth, overlap, NULL);

	kquad_box_init(&box[0], 15, 15, 25, 25, NULL);

	kquadtree_insert(tree, box[0]);

	kquad_box_init(&box[1], 30, 30, 40, 40, NULL);

	kquadtree_insert(tree, box[1]);

	kquad_box_init(&box[2], 60, 60, 70, 70, NULL);

	kquadtree_insert(tree, box[2]);

	kquad_box_init(&box[3], 60, 20, 70, 30, NULL);

	kquadtree_insert(tree, box[3]);

	kquad_box_init(&box[4], 10, 30, 28, 50, NULL);

	kquadtree_insert(tree, box[4]);

	kquad_box_init(&search_box, 20, 20, 35, 45, NULL);

	kquadtree_foreach(tree, tree_cb, NULL);

	kquadtree_search(tree, search_box, list);

	klist_foreach(list, list_cb, NULL);

	kquad_box_uninit(search_box);

	kquadtree_clear(tree);

	kquadtree_uninit(tree);

	klist_uninit(list);

	getchar();
	kmem_check_leak();
	kmem_check_stop();

	getchar();
	return 0;
}
