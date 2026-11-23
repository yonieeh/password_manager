// Import used global libraries
#include <stdio.h>  // FILE, fopen, fclose, etc.
#include <string.h> // strtok, strcpy, etc.
#include <stdlib.h> // malloc, calloc, free, etc.

// Import the header file of this module, because it has the constant definitions
#include "manager.h"

static char inbuf[BUFFER_SIZE];

/*
  * Sets the buffer for stdin to a custom size defined by BUFFER_SIZE.
*/
void set_buffer(void) {
  setvbuf(stdin, inbuf, _IOFBF, sizeof inbuf);
}

/*
 * Splits a string "str" by a separator "sep", returns an array with the
 * resulting strings. Equivalent to Python's str.split(sep).
 */
static char **split_by_sep(char *str, char *sep)
{
  char **new_str = calloc(MAX_SPLIT, sizeof(char *));
  int index = 0;
  size_t len;

  char *token = strtok(str, sep);
  while (token != NULL && index < MAX_SPLIT)      /* sin overflow del arreglo */
  {
    new_str[index] = calloc(BUFFER_SIZE, sizeof(char));
    strcpy(new_str[index++], token);
    token = strtok(NULL, sep);
  }

  if (index == 0)                                  /* línea sin tokens */
  {
    new_str[0] = calloc(1, sizeof(char));          /* input[0] = "" */
    return new_str;
  }

  // Remove dangling Windows (\r) and Unix (\n) newlines
  len = strlen(new_str[index - 1]);
  if (len > 1 && new_str[index - 1][len - 2] == '\r')
    new_str[index - 1][len - 2] = '\0';
  else if (len && new_str[index - 1][len - 1] == '\n')
    new_str[index - 1][len - 1] = '\0';
  return new_str;
}

/*
 * Reads a line fo user input and returns it as an array of strings
 */
char **read_user_input(void)
{
  char input[BUFFER_SIZE];
  if (fgets(input, BUFFER_SIZE, stdin) == NULL)
    return NULL;                      /* EOF o error */
  return split_by_sep(input, " ");
}

/* 
Reads a whole line from user input and returns it as a malloc'd whole string without newline, or NULL on EOF/error. Caller must free. 
*/
char *read_line(void)
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

/*
 * Frees user input obtained by the read_user_input function
 */
void free_user_input(char **input)
{
  for (int i = 0; i < MAX_SPLIT; i++)
  {
    free(input[i]);
  }
  free(input);
}
