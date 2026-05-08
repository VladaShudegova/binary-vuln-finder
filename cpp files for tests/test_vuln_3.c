#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void helper_unused() {
    printf("This should NOT be in the corridor.\n");
}

void process_data(char* input) {
    char buffer[16];
    // Наша цель здесь
    strcpy(buffer, input); 
    printf("Processed: %s\n", buffer);
}

int check_access(int level) {
    if (level == 1337) {
        return 1; // Путь к цели
    }
    return 0; // Тупик
}

int main(int argc, char** argv) {
    if (argc < 3) return 1;

    int secret = atoi(argv[2]);

    if (check_access(secret)) {
        printf("Access granted!\n");
        process_data(argv[1]);
    } else {
        printf("Access denied.\n");
        // Этот блок не должен попасть в коридор
    }

    return 0;
}
