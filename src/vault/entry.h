// vault/entry.h
#ifndef ENTRY_H
#define ENTRY_H
#include <stdint.h>

typedef struct
{ 
  uint32_t id;
  char *password;
  char *site_name;
  char *notes;
} entry_t;

void entry_free(entry_t *e);

#endif
