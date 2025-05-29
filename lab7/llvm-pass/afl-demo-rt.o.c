#include <stdio.h>
#include <stdlib.h>

void __demo_crash() {
  fprintf(stderr, "[AFL-DEMO] Command Injection Detected! Crashing...\n");
  abort();
}
