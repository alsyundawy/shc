#include <unistd.h>
#include <stdio.h>

int main() {
    char *args[] = {"./test.sh.x", "-S bash -e", "-c", "echo hello", NULL};
    execvp("/usr/bin/env", args);
    perror("execvp");
    return 1;
}
