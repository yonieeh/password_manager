#include "session/prompt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include <sodium.h>

void prompt_free(char *s)
{
  if (s == NULL) return;
  sodium_memzero(s, strlen(s));
  free(s);
}

/* Línea completa (con espacios), sin salto de línea. NULL en EOF o error. */
static char *read_plain_line(void)
{
  char *line = NULL;
  size_t cap = 0;

  ssize_t n = getline(&line, &cap, stdin);
  if (n < 0) {
    free(line);
    return NULL;
  }
  if (n > 0 && line[n - 1] == '\n') line[--n] = '\0';
  if (n > 0 && line[n - 1] == '\r') line[--n] = '\0';
  return line;
}

char *prompt_line(const char *prompt)
{
  printf("%s", prompt);
  fflush(stdout);
  return read_plain_line();
}

char *prompt_hidden(const char *prompt)
{
  printf("%s", prompt);
  fflush(stdout);

  struct termios old, hidden;
  int tty = isatty(STDIN_FILENO);
  if (tty) {
    if (tcgetattr(STDIN_FILENO, &old) != 0) {
      tty = 0;
    } else {
      hidden = old;
      hidden.c_lflag &= ~(tcflag_t) ECHO;
      if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) tty = 0;
    }
  }

  char *line = read_plain_line();

  if (tty) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);   /* siempre restaurar */
    printf("\n");                                /* el Enter del usuario no se vio */
  }
  return line;
}