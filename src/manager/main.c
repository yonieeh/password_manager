#include "../input_manager/manager.h"
#include "../api/api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <ctype.h>

#define MAX_PASSWORD_LENGTH 128
#define MAX_NAME_LEN 128
#define MAX_NOTE_LEN 512

static bool string_equals(char *string_1, char *string_2)
{
  return !strcmp(string_1, string_2);
}

static bool digits_only(const char *string)
{
  if (string == NULL || *string == '\0')
    return false;
  while (*string)
  {
    if (isdigit(*string++) == 0)
      return false;
  }
  return true;
}

typedef struct {
  char *password;
  char *site_name;
  char *notes;
} entry_t;

typedef struct {
  entry_t *entries;
  size_t count;
  size_t capacity;
} vault_t;

/* Codigo base para copiar la password al portapapeles en lugar de simplemente mostrarla en pantalla. Generado por Claude */

typedef struct
{
  const char *env;
  const char *bin;
  const char *copy_cmd;
  const char *clear_cmd;
} clip_backend;

static const clip_backend BACKENDS[] = {
#ifdef __APPLE__
    {NULL, "pbcopy", "pbcopy", "printf '' | pbcopy"},
#endif
    {"WAYLAND_DISPLAY", "wl-copy", "wl-copy", "wl-copy --clear"},
    {"DISPLAY", "xclip", "xclip -selection clipboard -in",
     "printf '' | xclip -selection clipboard -in"},
    {"DISPLAY", "xsel", "xsel --clipboard --input",
     "xsel --clipboard --clear"},
    {NULL, "clip.exe", "clip.exe", "printf '' | clip.exe"}, /* WSL */
};

static const clip_backend *find_backend(void)
{
  char probe[64];
  for (size_t i = 0; i < sizeof BACKENDS / sizeof BACKENDS[0]; i++)
  {
    const clip_backend *b = &BACKENDS[i];
    if (b->env && !getenv(b->env))
      continue;
    snprintf(probe, sizeof probe, "command -v %s >/dev/null 2>&1", b->bin);
    if (system(probe) == 0)
      return b;
  }
  return NULL;
}

int clipboard_copy(const char *text, unsigned clear_after_secs)
{
  const clip_backend *b = find_backend();
  if (b == NULL)
    return -1;

  FILE *p = popen(b->copy_cmd, "w");
  if (p == NULL)
    return -1;

  size_t len = strlen(text);
  size_t written = fwrite(text, 1, len, p);
  if (pclose(p) != 0 || written != len)
    return -1;

  char cmd[256];
  int n = snprintf(cmd, sizeof cmd,
                   "(sleep %u; %s) >/dev/null 2>&1 &",
                   clear_after_secs, b->clear_cmd);
  if (n < 0 || (size_t)n >= sizeof cmd)
    return 0;

  system(cmd);
  return 0;
}

/* Codigo generado por Claude para refactorizacion de generar password */

static int ask_yes_no(const char *what)
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

static int ask_length(void)
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


static int ask_name(entry_t *entry)
{
  while (1)
  {
    printf("Indicate what the password is for\n> ");
    fflush(stdout);

    char *line = read_line();
    if (line == NULL)
      return -1;

    if (line[0] == '\0') {
      free(line);
      printf("Name cannot be empty. ");
      continue;
    }
    if (strlen(line) > MAX_NAME_LEN) {
      free(line);
      printf("Name too long (max %d). ", MAX_NAME_LEN);
      continue;
    }

    entry->site_name = strdup(line);
    return 0;
  }
}

static int ask_notes(entry_t *entry)
{
  while (1)
  {
    printf("Write notes for the password (optional)\n> ");
    fflush(stdout);

    char *line = read_line();
    if (line == NULL)
      return -1;

    if (strlen(line) > MAX_NOTE_LEN) {
      free(line);
      printf("Notes are too long (max %d). ", MAX_NOTE_LEN);
      continue;
    }

    entry->notes = strdup(line);
    return 0;
  }
}

static int generate_command(entry_t *out)
{
  entry_t e = {0};
  char password[MAX_PASSWORD_LENGTH + 1] = {0};
  const char *names[4] = {"lowercase letters", "uppercase letters",
                          "numbers", "symbols"};
  int answers[4];
  int length;

  if (ask_name(&e) == -1)  goto cancelled;
  if (ask_notes(&e) == -1) goto cancelled;

  length = ask_length();
  if (length == 0) goto cancelled;

  for (int i = 0; i < 4; i++)
  {
    answers[i] = ask_yes_no(names[i]);
    if (answers[i] < 0) goto cancelled;
  }

  if (!answers[0] && !answers[1] && !answers[2] && !answers[3])
  {
    printf("Select at least one character type.\n");
    goto fail;
  }

  if (generate_password(password, (size_t) length + 1,
                        answers[0], answers[1], answers[2], answers[3]) != 0)
  {
    printf("Error generating the password.\n");
    goto fail;
  }

  e.password = strdup(password);
  if (e.password == NULL) goto fail;

  if (clipboard_copy(password, 30) == 0)
    printf("Password copied to clipboard (cleared in 30 s).\n");
  else
    printf("Generated password: %s\n", password);

  explicit_bzero(password, sizeof password);
  *out = e;            
  return 0;

cancelled:
  clearerr(stdin);
  printf("\nCancelled.\n");
fail:
  explicit_bzero(password, sizeof password);
  //entry_free(&e);
  return -1;
}

/* Fin refactorizacion Claude */

int main()
{
  set_buffer();

  vault_t vault;
  entry_t a;
  vault.entries = calloc(sizeof(a), 128);
  vault.capacity = 128;
  vault.count = 0;

  while (1)
  {
    printf("> ");
    fflush(stdout);
    char **input = read_user_input();

    if (input == NULL)
    {
      printf("\n");
      if (feof(stdin))
      {
        break;
      }
      continue;
    }

    if (string_equals(input[0], ""))
    {
      free_user_input(input);
      continue;
    }

    if (string_equals(input[0], "generate"))
    {
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
      entry_t e = {0}; 
      generate_command(&e);
      vault.entries[vault.count] = e;
      vault.count++;
    }

    if (string_equals(input[0], "show"))
    {
      printf("Site name | Password | Notes\n");
      for (int i = 0; i < vault.count; i++) 
      {
        printf("%s | %s | %s\n", vault.entries[i].site_name, vault.entries[i].password, vault.entries[i].notes);
      }
    }

    free_user_input(input);
  }
}