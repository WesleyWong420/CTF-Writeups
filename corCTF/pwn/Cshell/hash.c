#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
//gcc hash.c -static -lcrypt -o hash

char salt[5] = "1337\0";
char *hash;

void setup(){
	char password_L[33];
	printf("Create a password.\n> ");
	scanf("%32s",&password_L);
	char *hash = crypt(password_L,salt);
    printf("%s\n", hash);
}

int main(){
    setup();
}

