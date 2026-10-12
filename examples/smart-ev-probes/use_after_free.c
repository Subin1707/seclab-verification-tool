#include <stdlib.h>

int main(void) {
    volatile char *allocation = (volatile char *)malloc(16);
    if (allocation == NULL) {
        return 2;
    }
    allocation[0] = 'A';
    free((void *)allocation);
    allocation[0] = 'B';
    return 0;
}
