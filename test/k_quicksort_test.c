#include "../src/k.h"

#ifdef _WIN32
#pragma comment(lib, "k.lib")
//#include "vld.h"
#endif

int
main()
{
	int i = 0;

	int data[] = {3,1,6,2,8,5,9,4};

	k_quicksort(data, 8);

	for (i = 0; i < 8; ++i)
	{
		printf("%d,", data[i]);
	}
	printf("\n");

	getchar();

	return 0;
}