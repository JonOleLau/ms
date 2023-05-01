#include <stdlib.h>

void func1() {
  int* ptr = malloc(10 * sizeof(int));
  // do some work with ptr
  // forget to free ptr
}

void func2() {
  int* ptr = malloc(20 * sizeof(int));
  // do some work with ptr
  // forget to free ptr
}

int main() {
  while (1) {
    func1();
    func2();
    // more code
  }
  return 0;
}