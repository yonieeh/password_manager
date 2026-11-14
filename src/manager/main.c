#include "../input_manager/manager.h"
#include "../api/api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <ctype.h>

static bool string_equals(char *string_1, char *string_2)
{
  return !strcmp(string_1, string_2);
}

static bool digits_only(const char *string) {
  if (string == NULL || *string == '\0') return false;
  while (*string) {
    if (isdigit(*string++) == 0) return false;
  }
  return true;
}

int main()
{
  set_buffer();

  while (1)
  {
    printf("> ");
    fflush(stdout);
    char **input = read_user_input();

    if (input == NULL)
    {
      printf("\n");
      continue;
    }

    if (string_equals(input[0], ""))
    {
      free_user_input(input);
      continue;
    }

    if (string_equals(input[0], "generate")) {
      free_user_input(input);
      printf("Indicate password length\n");
      printf("> ");
      fflush(stdout);
      input = read_user_input();
      bool is_digits_only = digits_only(input[0]);
      while (!is_digits_only) {
        printf("Invalid length. Indicate password length\n");
        printf("> ");
        fflush(stdout);
        free_user_input(input);
        input = read_user_input();
      }
    }

  }
}