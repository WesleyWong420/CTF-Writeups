#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

bool solve1 = false;

void checker(int check1, int check2) {

	if (check1 == 0xDEADBEEF) {
		if (check2 == 0xCAFEBABE) {
			solve1 = true;
		}
		else {
			puts("Wrong!");
			exit(0);
		}
	}
	else {
		puts("Wrong!");
		exit(0);
	}
}

void flag() {
	char flag[64];

	if (solve1) {
		FILE *f = fopen("flag.txt", "r");
		fgets(flag, 64, f);
		printf("%s", flag);
		fflush(stdout);
	}
	else {
		puts("Wrong!");
	}
}

int main(int argc, char *argv[]) {
	char buf[10];

	puts("Can you pass the checker?");
	gets(buf);
	puts("Welp... Guest not.");
}
