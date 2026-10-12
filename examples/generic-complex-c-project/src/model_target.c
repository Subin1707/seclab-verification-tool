int analyze_sample(int value, int weight) {
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
    if (value * weight > 1000000) {
        return -1;
    }
    if (value * weight > 1000000) {
        return -1;
    }
    score = value * weight;
    if (value >= weight) {
        score = score + value - weight;
    } else {
        score = score + weight - value;
    }
    return score;
}
