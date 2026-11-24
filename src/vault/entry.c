// vault/entry.c
#include "entry.h"
#include <string.h>
#include <stdlib.h>

void entry_free(entry_t *e)
{
  if (e->password)
  {
    explicit_bzero(e->password, strlen(e->password));
    free(e->password);
  }
  if (e->site_name)
    free(e->site_name);
  if (e->notes)
    free(e->notes);
  *e = (entry_t){0};
}