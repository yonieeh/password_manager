#include "../input_manager/manager.h"
#include "../api/api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <ctype.h>

#define MAX_PASSWORD_LENGTH 128

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

/* Codigo generado por Claude para refactorizacion de generar password */

static int ask_yes_no(const char *what)
{
  while (1) {
    printf("Include %s? [Y/n]\n> ", what);
    fflush(stdout);
    char **input = read_user_input();
    if (input == NULL) return -1;

    char c = (char) tolower((unsigned char) input[0][0]);
    free_user_input(input);

    if (c == '\0' || c == 'y') return 1;
    if (c == 'n') return 0;
    printf("Invalid option. ");
  }
}

static int ask_length(void)
{
  while (1) {
    printf("Indicate password length\n> ");
    fflush(stdout);
    char **input = read_user_input();
    if (input == NULL) return 0;

    bool ok = digits_only(input[0]);
    long n = ok ? strtol(input[0], NULL, 10) : 0;
    free_user_input(input);

    if (ok && n >= 1 && n <= MAX_PASSWORD_LENGTH) return (int) n;
    printf("Invalid length (1-%d). ", MAX_PASSWORD_LENGTH);
  }
}

static void generate_command(void)
{
  int length  = ask_length();
  if (length == 0) {
    clearerr(stdin);
    printf("\nCancelled.\n");
    return;
  }
  const char *names[4] = { "lowercase letters", "uppercase letters",
                           "numbers", "symbols" };
  int answers[4];
  for (int i = 0; i < 4; i++) {
    answers[i] = ask_yes_no(names[i]);
    if (answers[i] < 0) {
      clearerr(stdin);
      printf("\nCancelled.\n");
      return;
    }
  }

  int lower = answers[0];
  int upper = answers[1];
  int numbers = answers[2];
  int symbols = answers[3];

  if (lower < 0 || upper < 0 || numbers < 0 || symbols < 0) {
    clearerr(stdin);
    printf("\nCancelled.\n");
    return;
  }

  if (!lower && !upper && !numbers && !symbols) {
    printf("Select at least one character type.\n");
    return;
  }

  char password[MAX_PASSWORD_LENGTH + 1];
  if (generate_password(password, (size_t) length + 1,
                        lower, upper, numbers, symbols) != 0) {
    printf("Error generating the password.\n");
    return;
  }

  printf("Generated password: %s\n", password);
  explicit_bzero(password, sizeof(password));
}

/* Fin refactorizacion Claude */

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
      if (feof(stdin)) {
        break;
      }
      continue;
    }

    if (string_equals(input[0], ""))
    {
      free_user_input(input);
      continue;
    }

    if (string_equals(input[0], "generate")) {
      /* Codigo previo a la refactorizacion que se ocupo como prompt para Claude 
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
        is_digits_only = digits_only(input[0]);
      }
      int length = atoi(input[0]);
      free_user_input(input);
      printf("Include lowercase letters? [Y/n]\n");
      printf("> ");
      fflush(stdout);
      input = read_user_input();
      char lowercase = tolower((unsigned char) input[0][0]);
      while (lowercase != 'y' && lowercase != 'n') {
        printf("Invalid option. Include lowercase letters? [Y/n]\n");
        printf("> ");
        fflush(stdout);
        free_user_input(input);
        input = read_user_input();
        lowercase = tolower((unsigned char) input[0][0]);
      }
      bool lowercase_t = lowercase == 'y';

      free_user_input(input);
      printf("Include uppercase letters? [Y/n]\n");
      printf("> ");
      fflush(stdout);
      input = read_user_input();
      char uppercase = tolower((unsigned char) input[0][0]);
      while (uppercase != 'y' && uppercase != 'n') {
        printf("Invalid option. Include uppercase letters? [Y/n]\n");
        printf("> ");
        fflush(stdout);
        free_user_input(input);
        input = read_user_input();
        uppercase = tolower((unsigned char) input[0][0]);
      }
      bool uppercase_t = uppercase == 'y';

      free_user_input(input);
      printf("Include numbers? [Y/n]\n");
      printf("> ");
      fflush(stdout);
      input = read_user_input();
      char numbers = tolower((unsigned char) input[0][0]);
      while (numbers != 'y' && numbers != 'n') {
        printf("Invalid option. Include numbers? [Y/n]\n");
        printf("> ");
        fflush(stdout);
        free_user_input(input);
        input = read_user_input();
        numbers = tolower((unsigned char) input[0][0]);
      }
      bool numbers_t = numbers == 'y';

      free_user_input(input);
      printf("Include symbols? [Y/n]\n");
      printf("> ");
      fflush(stdout);
      input = read_user_input();
      char symbols = tolower((unsigned char) input[0][0]);
      while (symbols != 'y' && symbols != 'n') {
        printf("Invalid option. Include symbols? [Y/n]\n");
        printf("> ");
        fflush(stdout);
        free_user_input(input);
        input = read_user_input();
        symbols = tolower((unsigned char) input[0][0]);
      }
      bool symbols_t = symbols == 'y';

      char* password[length];
      int result = generate_password(password, length, lowercase_t, uppercase_t, numbers_t, symbols_t);

      if (result != 0) {
        printf("Error generating the password.\n");
      } else {
        printf("Generated password: %s", *password);
      }
      */
      generate_command();
    }

    free_user_input(input);
  }
}