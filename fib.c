int _start() {
    int a = 0, b = 1, c = 0;

    for (int i = 0; i < 10; i++) {
        c = a + b;
        a = b;
        b = c;
    }

    return c;
}