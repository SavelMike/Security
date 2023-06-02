#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <ctype.h>

int main(void) {
	char* line = NULL;
	size_t size = 0;
	ssize_t len;
	int i;	
	
	if ((len = getline(&line, &size, stdin)) == -1) {
		printf("Getline failure\n");
		return 1;
	}

	if (len == 1) {
		printf("String is empty\n");
		return 1;
	}
	len--; // get rid of end of line

	for (i = 0; i < len; i++) {
		printf("%x%x", (line[i] & 0xf0)>>4, line[i] & 0x0f);
	}
	
	free(line);

	return 0;
}
