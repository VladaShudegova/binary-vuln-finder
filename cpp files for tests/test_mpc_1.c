#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void complex_target(char* input, int a, int b) {
    char buf[16];
    
   
    if (a > 5) {
        printf("Branch A\n");
    } else {
        printf("Branch B\n");
    }


    if (b == 42) {
  
        if (a < 10) {
             printf("Path 1\n");
        } else {
             printf("Path 2\n");
        }
        strcpy(buf, input); 
    }
}

int main(int argc, char** argv) {
    if (argc < 4) return 1;
    complex_target(argv[1], atoi(argv[2]), atoi(argv[3]));
    return 0;
}
