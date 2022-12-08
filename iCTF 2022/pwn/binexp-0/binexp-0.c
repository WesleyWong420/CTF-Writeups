#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
	int win;
	char buf[32];
	char flag[100];

	win = 0;

	FILE *f = fopen("flag.txt", "r");
	if (f == NULL) {
		puts("'flag.txt' not found.");
		exit(0);
	}

	fgets(flag, 100, f);
	gets(buf);

	if(win != 0) {
		printf("%s\n", flag);
	} else {
		puts("You failed!\n");
	}
}
