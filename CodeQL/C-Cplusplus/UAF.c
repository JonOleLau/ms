#include <stdlib.h>
#include <stdio.h>

int main()
{
  int* ptr = (int*)malloc(sizeof(int));
  *ptr = 5;
  printf("%d\n", *ptr);
  free(ptr);
  printf("%d\n", *ptr);
  return 0;
}