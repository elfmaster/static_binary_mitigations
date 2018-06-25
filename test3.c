#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Make sure we have a data segment for testing purposes */
static int test_dummy = 5;

int main(int argc, char **argv) {
	int i;
	int j = 0;

	printf("Hello world\n");
	exit(0);
}

