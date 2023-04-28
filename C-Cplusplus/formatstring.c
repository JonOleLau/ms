#include <stdio.h>

void vuln_func(char* input) {
  char buffer[20];
  sprintf(buffer, input);
  printf(buffer);
}

int main() {
  char* user_input = "%s %s %s\n";
  vuln_func(user_input);
  return 0;
}