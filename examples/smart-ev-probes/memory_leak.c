#include <stdlib.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void lose_allocation(void) {
    char *buffer = (char *)malloc(64);
    if (buffer != NULL) {
        memset(buffer, 'L', 64);
    }
}

int main(void) {
    lose_allocation();
    return 0;
}
