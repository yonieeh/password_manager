// vault/vault.c
#include "entry.h"
#include "vault.h"
#include <stdlib.h>
#include <string.h>

int vault_add(vault_t *v, entry_t e, uint32_t *out_id)
{
  if (v->count == v->capacity)
  {
    size_t new_capacity = v->capacity ? v->capacity * 2 : 8;
    entry_t *tmp = realloc(v->entries, new_capacity * sizeof *tmp);
    if (tmp == NULL)
      return -1;
    v->entries = tmp;
    v->capacity = new_capacity;
  }
  e.id = v->next_id++;
  v->entries[v->count++] = e;
  if (out_id) *out_id = e.id;
  return 0;
}

void vault_free(vault_t *v)
{
  if (v == NULL) return;

  for (size_t i = 0; i < v->count; i++)
    entry_free(&v->entries[i]);        /* borra y libera password, site_name y notes */

  free(v->entries);
  *v = (vault_t){0};                   /* deja el vault vacío */
}

entry_t *vault_find(const vault_t *v, uint32_t id)
{
  for (size_t i = 0; i < v->count; i++)
    if (v->entries[i].id == id) return &v->entries[i];
  return NULL;
}

int vault_remove(vault_t *v, uint32_t id)
{
  for (size_t i = 0; i < v->count; i++) {
    if (v->entries[i].id != id) continue;
    entry_free(&v->entries[i]);
    memmove(&v->entries[i], &v->entries[i + 1], (v->count - i - 1) * sizeof *v->entries);
    v->count--;
    memset(&v->entries[v->count], 0, sizeof *v->entries);   /* limpia la casilla sobrante */
    return 0;
  }
  return -1;
}