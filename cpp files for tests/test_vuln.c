#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char *gets(char *s); 


void secret_goal() {
    printf("[!] You reached the secret function!\n");
}

void vuln_logic(char* input) {
    char buffer1[16];
    char buffer2[16];
    char buffer3[16];

    printf("Enter something for gets: ");
    gets(buffer1); 

    strcpy(buffer2, input);

    strcat(buffer3, input);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        return 1;
    }
    vuln_logic(argv[1]);
    return 0;
}
