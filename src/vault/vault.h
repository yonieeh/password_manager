// vault/vault.h
#ifndef VAULT_H
#define VAULT_H
#include <stddef.h>
#include <stdint.h>
#include "entry.h"

typedef struct
{
  entry_t *entries;
  size_t count;
  size_t capacity;
  uint32_t next_id;
} vault_t;

int vault_add(vault_t *v, entry_t e, uint32_t *out_id);
void vault_free(vault_t *v);
entry_t *vault_find(const vault_t *v, uint32_t id);
int vault_remove(vault_t *v, uint32_t id);

#endif