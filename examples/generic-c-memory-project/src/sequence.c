#include <stddef.h>
#include <stdlib.h>

int sum_sequence(int count) {
    if (count <= 0) {
        return 0;
    }

    int *values = calloc((size_t)count, sizeof(*values));
    if (values == NULL) {
        return -1;
    }

    int total = 0;
    for (int index = 0; index < count; ++index) {
        values[index] = index + 1;
        total += values[index];
    }

    free(values);
    return total;
}
