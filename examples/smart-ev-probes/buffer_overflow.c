#include <stdlib.h>

int main(void) {
    volatile size_t index = 8;
    volatile char *buffer = (volatile char *)malloc(8);
    if (buffer == NULL) {
        return 2;
    }
    buffer[index] = 'X';
    free((void *)buffer);
    return 0;
}
