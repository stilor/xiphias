/* vi: set ts=4 sw=4 et : */
/* vim: set comments= cinoptions=\:0,t0,+8,c4,C1 : */

#include <stdio.h>
#include "xutil.h"

int
main(int argc, char *argv[])
{
	printf("%p\n", xmalloc(32));
	return 0;
}
