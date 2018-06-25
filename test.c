#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(void)
{
	printf("I'm pausing while you check my RELRO status in /proc/%d/maps\n", getpid());
	pause();
	exit(EXIT_SUCCESS);
}
