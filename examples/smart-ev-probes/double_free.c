#include <stdlib.h>

int main(void) {
    void *allocation = malloc(32);
    if (allocation == NULL) {
        return 2;
    }
    free(allocation);
    free(allocation);
    return 0;
}
