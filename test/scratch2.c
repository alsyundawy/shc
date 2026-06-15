#include <stdio.h>


int main() {
    char shll[100];
    char opts[100] = "";
    int i = sscanf("#!/bin/bash", " #!%s %[^\n]", shll, opts);
    printf("i=%d shll='%s' opts='%s'\n", i, shll, opts);
    return 0;
}
