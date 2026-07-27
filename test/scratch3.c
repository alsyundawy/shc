#include <stdio.h>
#include <unistd.h>

int main() {
  char arg0[] = "./test.sh.x";
  char arg1[] = "-S bash -e";
  char arg2[] = "-c";
  char arg3[] = "echo hello";
  char *args[] = {arg0, arg1, arg2, arg3, NULL};
  execvp("/usr/bin/env", args);
  perror("execvp");
  return 1;
}
