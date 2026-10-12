#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fputs("usage: program COUNT\n", stderr);
        return 64;
    }
    errno = 0;
    char *end = NULL;
    long count = strtol(argv[1], &end, 10);
    if (errno != 0 || end == argv[1] || *end != '\0' || count < 0 || count > 64) {
        puts("{\"sum\":-1}");
        return 2;
    }
    int *values = calloc((size_t)(count == 0 ? 1 : count), sizeof(*values));
    if (values == NULL) {
        return 70;
    }
    long sum = 0;
    for (long index = 0; index < count; ++index) {
        values[index] = (int)(index + 1);
        sum += values[index];
    }
    free(values);
    printf("{\"sum\":%ld}\n", sum);
    return 0;
}
