#include <stdio.h>
#include <string.h>

struct user {
  char username[10];
  char password[10];
  int role;
};

int main() {
  struct user users[2];
  strcpy(users[0].username, "admin");
  strcpy(users[0].password, "admin123");
  users[0].role = 0;

  strcpy(users[1].username, "guest");
  strcpy(users[1].password, "guest123");
  users[1].role = 1;

  char input_username[10];
  char input_password[10];
  printf("Enter username: ");
  scanf("%s", input_username);
  printf("Enter password: ");
  scanf("%s", input_password);

  int authenticated = 0;
  int role = -1;
  for (int i = 0; i < 2; i++) {
    if (strcmp(input_username, users[i].username) == 0 && strcmp(input_password, users[i].password) == 0) {
      authenticated = 1;
      role = users[i].role;
      break;
    }
  }

  if (authenticated) {
    if (role == 0) {
      printf("Welcome admin!\n");
      // perform admin actions
    } else {
      printf("Welcome guest!\n");
      // perform guest actions
    }
  } else {
    printf("Invalid credentials\n");
  }

  return 0;
}