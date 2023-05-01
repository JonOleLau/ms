#include <stdio.h>
#include <stdlib.h>

void func1() {
  int* ptr = NULL;
  *ptr = 5;
}

void func2(int* arr) {
  if (arr == NULL) {
    printf("Array is null.\n");
  } else {
    printf("Array length: %d\n", arr[0]);
    printf("First element: %d\n", arr[1]);
  }
}

int main() {
  int* arr = NULL;
  func1();
  func2(arr);
  return 0;
}