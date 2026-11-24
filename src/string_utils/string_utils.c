// string_utils/string_utils.c
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

bool string_equals(char *string_1, char *string_2)
{
  return !strcmp(string_1, string_2);
}

bool digits_only(const char *string)
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