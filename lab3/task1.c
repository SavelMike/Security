#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <ctype.h>


int char2int(int c) {
	if (isdigit(c)) {
		return c - '0';
	}
	if (islower(c)) {
		return c - 'a' + 10;
	}

	return c - 'A' + 10;
}

int main(void) {
	char* line = NULL;
	size_t size = 0;
	ssize_t len;
	int i;	
	
	if ((len = getline(&line, &size, stdin)) == -1) {
		printf("Getline failure\n");
		return 1;
	}

	if ((len == 1) || (len % 2 == 0)) {
		printf("String is empty or odd number of chars\n");
		return 1;
	}
	len--;

	for (i = 0; i < len; i++) {
		if (!isxdigit(line[i])) {
			printf("Not a hex digit\n");
			return 1;
		}
	}

	for (i = 0; i < len; i += 2) {
		printf("%c", char2int(line[i]) * 16 + char2int(line[i + 1]));
	}
	
	free(line);

	return 0;
}
