#include <stdio.h>
#include <string.h>

void func1() {
  int buffer[5];
  int i;
  for (i = 0; i <= 5; i++) {
    buffer[i] = i;
  }
}

void func2(char* input) {
  char buffer[10];
  strcpy(buffer, input);
  printf("Input: %s\n", buffer);
}

int main() {
  char input[10];
  printf("Enter a string: ");
  scanf("%s", input);
  func1();
  func2(input);
  return 0;
}