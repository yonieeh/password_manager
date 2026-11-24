// commands/commands.c
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "../config.h"
#include "../vault/entry.h"
#include "../vault/vault.h"
#include "../clipboard/clipboard.h"
#include "../input_manager/manager.h"
#include "../string_utils/string_utils.h"
#include "../api/api.h"
#include "../display/display.h"

int ask_yes_no(const char *what)
{
  while (1)
  {
    printf("Include %s? [Y/n]\n> ", what);
    fflush(stdout);
    char **input = read_user_input();
    if (input == NULL)
      return -1;

    char c = (char)tolower((unsigned char)input[0][0]);
    free_user_input(input);

    if (c == '\0' || c == 'y')
      return 1;
    if (c == 'n')
      return 0;
    printf("Invalid option. ");
  }
}

int ask_length(void)
{
  while (1)
  {
    printf("Indicate password length\n> ");
    fflush(stdout);
    char **input = read_user_input();
    if (input == NULL)
      return 0;

    bool ok = digits_only(input[0]);
    long n = ok ? strtol(input[0], NULL, 10) : 0;
    free_user_input(input);

    if (ok && n >= 1 && n <= MAX_PASSWORD_LENGTH)
      return (int)n;
    printf("Invalid length (1-%d). ", MAX_PASSWORD_LENGTH);
  }
}

int ask_name(entry_t *entry)
{
  while (1)
  {
    printf("Indicate what the password is for\n> ");
    fflush(stdout);

    char *line = read_line();
    if (line == NULL)
      return -1;

    if (line[0] == '\0')
    {
      free(line);
      printf("Name cannot be empty. ");
      continue;
    }
    if (strlen(line) > MAX_NAME_LEN)
    {
      free(line);
      printf("Name too long (max %d). ", MAX_NAME_LEN);
      continue;
    }

    entry->site_name = line;

    return 0;
  }
}

int ask_notes(entry_t *entry)
{
  while (1)
  {
    printf("Write notes for the password (optional)\n> ");
    fflush(stdout);

    char *line = read_line();
    if (line == NULL)
      return -1;

    if (strlen(line) > MAX_NOTE_LEN)
    {
      free(line);
      printf("Notes are too long (max %d). ", MAX_NOTE_LEN);
      continue;
    }

    entry->notes = line;

    return 0;
  }
}

int ask_password(entry_t *entry)
{
  while (1)
  {
    printf("Write the password to store (hidden)\n> ");
    fflush(stdout);

    char *first = read_secret_line();
    if (first == NULL)
      return -1;

    size_t len = strlen(first);

    if (len == 0)
    {
      free(first);
      printf("Password cannot be empty. ");
      continue;
    }
    if (len > MAX_PASSWORD_LENGTH)
    {
      explicit_bzero(first, len);
      free(first);
      printf("Password is too long (max %d). ", MAX_PASSWORD_LENGTH);
      continue;
    }

    printf("Confirm the password (hidden)\n> ");
    fflush(stdout);

    char *second = read_secret_line();
    if (second == NULL)
    {
      explicit_bzero(first, len);
      free(first);
      return -1;
    }

    bool match = (strcmp(first, second) == 0);
    explicit_bzero(second, strlen(second));
    free(second);

    if (match)
    {
      entry->password = first;
      return 0;
    }

    explicit_bzero(first, len);
    free(first);
    printf("Passwords do not match. Try again.\n");
  }
}

int generate_command(entry_t *out)
{
  entry_t e = {0};
  char password[MAX_PASSWORD_LENGTH + 1] = {0};
  const char *names[4] = {"lowercase letters", "uppercase letters",
                          "numbers", "symbols"};
  int answers[4];
  int length;

  if (ask_name(&e) == -1)
    goto cancelled;
  if (ask_notes(&e) == -1)
    goto cancelled;

  length = ask_length();
  if (length == 0)
    goto cancelled;

  for (int i = 0; i < 4; i++)
  {
    answers[i] = ask_yes_no(names[i]);
    if (answers[i] < 0)
      goto cancelled;
  }

  if (!answers[0] && !answers[1] && !answers[2] && !answers[3])
  {
    printf("Select at least one character type.\n");
    goto fail;
  }

  if (generate_password(password, (size_t)length + 1,
                        answers[0], answers[1], answers[2], answers[3]) != 0)
  {
    printf("Error generating the password.\n");
    goto fail;
  }

  e.password = strdup(password);
  if (e.password == NULL)
    goto fail;

  if (clipboard_copy(password, 30) == 0)
    printf("Password copied to clipboard (cleared in 30 s).\n");
  else
    show_secret_temporarily(password, SECRET_DISPLAY_SECS);
  explicit_bzero(password, sizeof password);
  *out = e;
  return 0;

cancelled:
  clearerr(stdin);
  printf("\nCancelled.\n");
fail:
  explicit_bzero(password, sizeof password);
  entry_free(&e);
  return -1;
}

/* Fin refactorizacion Claude */

int add_command(entry_t *out)
{
  entry_t e = {0};

  if (ask_name(&e) == -1)
    goto cancelled;
  if (ask_notes(&e) == -1)
    goto cancelled;
  if (ask_password(&e) == -1)
    goto cancelled;

  *out = e;
  return 0;

cancelled:
  clearerr(stdin);
  printf("\nCancelled.\n");
  entry_free(&e);
  return -1;
}

static int ask_id(unsigned long *out)
{
  while (1) {
    printf("Enter the ID of the password to see\n> ");
    fflush(stdout);
    char **input = read_user_input();
    if (input == NULL) return -1;

    bool ok = digits_only(input[0]) && strlen(input[0]) <= 9;
    if (ok) *out = strtoul(input[0], NULL, 10);
    free_user_input(input);

    if (ok) return 0;
    printf("Invalid format. ");
  }
}

void cmd_show(const vault_t *v)
{
  unsigned long id;
  if (ask_id(&id) != 0) { clearerr(stdin); printf("\nCancelled.\n"); return; }

  for (size_t i = 0; i < v->count; i++) {
    if ((unsigned long) v->entries[i].id == id) {
      show_secret_temporarily(v->entries[i].password, SECRET_DISPLAY_SECS);
      return;
    }
  }
  printf("No entry with id %lu.\n", id);
}