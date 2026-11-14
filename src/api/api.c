// version corregida de Claude
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define LOWER   "abcdefghijklmnopqrstuvwxyz"
#define UPPER   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define DIGITS  "0123456789"
#define SYMBOLS "!@#$^&*?"

int generate_password(char *buf, size_t size, bool lower, bool upper, bool digits, bool symbols)
{
  char pool[sizeof(LOWER) + sizeof(UPPER) + sizeof(DIGITS) + sizeof(SYMBOLS)];
  size_t n = 0;

  if (lower)   { memcpy(pool + n, LOWER,   sizeof(LOWER) - 1);   n += sizeof(LOWER) - 1; }
  if (upper)   { memcpy(pool + n, UPPER,   sizeof(UPPER) - 1);   n += sizeof(UPPER) - 1; }
  if (digits)  { memcpy(pool + n, DIGITS,  sizeof(DIGITS) - 1);  n += sizeof(DIGITS) - 1; }
  if (symbols) { memcpy(pool + n, SYMBOLS, sizeof(SYMBOLS) - 1); n += sizeof(SYMBOLS) - 1; }

  if (n == 0 || size < 2)
    return -1;

  for (size_t i = 0; i < size - 1; i++)
    buf[i] = pool[arc4random_uniform(n)];
  buf[size - 1] = '\0';

  return 0;
}


/*
Codigo original q le pase a Claude
Preservacion de la idea original

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>

void generate_password(char *buf, int size, bool lowercase_t, bool uppercase_t, bool numbers_t, bool symbols_t) 
{
  char numbers[] = "0123456789";
  char lowercase_letters[] = "abcdefghijklmnoqprstuvwyzx";
  char uppercase_letters[] = "ABCDEFGHIJKLMNOQPRSTUYWVZX";
  char symbols[] = "!@#$^&*?";

  int total_size = sizeof(numbers) + sizeof(lowercase_letters) + sizeof(uppercase_letters) + sizeof(symbols);

  char *symbol_array[total_size];

  int pos = 0;

  if (lowercase_t) {
    for (int i = pos; i < 26; i++) {
      symbol_array[i] = lowercase_letters[i];
      pos++;
    }
  }

  if (uppercase_t) {
    for (int i = pos; i < 26; i++) {
      symbol_array[i] = uppercase_letters[i];
      pos++;
    }
  }

  if (numbers_t) {
    for (int i = pos; i < 10; i++) {
      symbol_array[i] = numbers[i];
      pos++;
    }
  }

  if (symbols_t) {
    for (int i = pos; i < 8; i++) {
      symbol_array[i] = symbols[i];
      pos++;
    }
  }


  u_int8_t *random_buf[size];

  arc4random_buf(random_buf, sizeof(random_buf));

  for (int i = 0; i < size; i++) {
    int symbol_pos = (int) random_buf[i] % (pos - 1);
    buf[i] = symbol_array[symbol_pos];
  }


};
*/