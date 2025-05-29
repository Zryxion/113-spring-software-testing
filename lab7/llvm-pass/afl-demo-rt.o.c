#include <stdio.h>
#include <stdlib.h>

void __demo_crash() {
  fprintf(stderr, "system call crash: attacker-controlled input detected!\n");
  abort();
}
