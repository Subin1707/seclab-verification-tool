int identity_value(int value) {
    return value;
}

int build_failure_value(int value) {
    return value;
}

int wait_for_negative(int value) {
    volatile unsigned long ticks = 0;
    while (value < 0) {
        ++ticks;
    }
    return value;
}
