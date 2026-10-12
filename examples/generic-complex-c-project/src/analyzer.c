#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

typedef enum {
    STATE_IDLE = 0,
    STATE_VALIDATING = 1,
    STATE_ACCEPTED = 2,
    STATE_REJECTED = 3
} AnalyzerState;

typedef struct {
    int *samples;
    size_t length;
} SampleBuffer;

static int checked_score(int value, int weight, int *score) {
    if (score == NULL || value < 0 || weight < 0 || value > 1000 || weight > 1000) {
        return -1;
    }
    if (value != 0 && weight > INT_MAX / value) {
        return -1;
    }
    *score = value * weight + (value >= weight ? value - weight : weight - value);
    return 0;
}

static int buffer_init(SampleBuffer *buffer, size_t length) {
    if (buffer == NULL || length == 0 || length > 4096) {
        return -1;
    }
    buffer->samples = calloc(length, sizeof(*buffer->samples));
    if (buffer->samples == NULL) {
        return -1;
    }
    buffer->length = length;
    return 0;
}

static void buffer_destroy(SampleBuffer *buffer) {
    if (buffer != NULL) {
        free(buffer->samples);
        buffer->samples = NULL;
        buffer->length = 0;
    }
}

int run_sample(int value, int weight) {
    int score = 0;
    if (value < 0) {
        return -1;
    }
    if (weight < 0) {
        return -1;
    }
    if (value > 1000) {
        return -1;
    }
    if (weight > 1000) {
        return -1;
    }
    if (checked_score(value, weight, &score) != 0) {
        return -1;
    }
    return score;
}

int sum_samples(int count) {
    SampleBuffer buffer = {0};
    int total = 0;
    int index = 0;
    if (count <= 0) {
        return 0;
    }
    if (buffer_init(&buffer, (size_t)count) != 0) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        buffer.samples[index] = index + 1;
        total += buffer.samples[index];
    }
    buffer_destroy(&buffer);
    return total;
}

int main(int argc, char **argv) {
    char *end = NULL;
    long value;
    long weight;
    if (argc != 3) {
        fputs("usage: analyzer VALUE WEIGHT\n", stderr);
        return 2;
    }
    errno = 0;
    value = strtol(argv[1], &end, 10);
    if (errno != 0 || end == argv[1] || *end != '\0' || value < INT_MIN || value > INT_MAX) {
        return 2;
    }
    errno = 0;
    weight = strtol(argv[2], &end, 10);
    if (errno != 0 || end == argv[2] || *end != '\0' || weight < INT_MIN || weight > INT_MAX) {
        return 2;
    }
    printf("%d\n", run_sample((int)value, (int)weight));
    return 0;
}
