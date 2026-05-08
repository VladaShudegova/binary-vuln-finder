#include <stdio.h>
#include <string.h>
#include <stdlib.h>


void func_a(char* input) {
    char buf[16];
    strcpy(buf, input); 
    printf("%s\n", buf);
}

void func_b() {
    printf("Just a harmless function\n");
}

int main(int argc, char** argv) {
    if (argc < 3) return 1;
    int mode = atoi(argv[2]);

    if (mode > 10) {
        func_a(argv[1]);
    } else {
        func_b();
    }
    return 0;
}
