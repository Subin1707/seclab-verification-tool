int model_step(int mode) {
    if (mode < 0) {
        return 0;
    }
    if (mode == 0) {
        return 1;
    }
    return 2;
}
