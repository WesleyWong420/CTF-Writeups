#include <stdio.h>
#include <stdlib.h>

char flag[100];

int win() {
	printf("%s", flag);
	fflush(stdout);
}

int main(int argc, char *argv[]) {
	char buf[64];

	FILE *f = fopen("flag.txt", "r");
	if (f == NULL) {
		puts("'flag.txt' not found.");
		exit(0);
	}

	fgets(flag, 100, f);

	puts("Can you make this jump?");
	gets(buf);
	puts("Welp... Guest not.");
}
