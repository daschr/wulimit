#include <unistd.h>

void forker(void *p) {
    while(1)
        _beginthread(forker, 4048, NULL);
}

int main(int ac, char *as[]) {
    while(1)
        _beginthread(forker, 4048, NULL);
}
