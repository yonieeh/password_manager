#include "../input_manager/manager.h"
#include "../api/api.h"
#include "../vault/vault.h"
#include "../vault/entry.h"
#include "../clipboard/clipboard.h"
#include "../string_utils/string_utils.h"
#include "../commands/commands.h"
#include "../commands/edit_commands.h"
#include "../display/display.h"
#include "../session/session.h"
#include "../storage/storage.h"
#include "../config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <ctype.h>
#include <unistd.h>

#define DEFAULT_VAULT_PATH "vault.pwm"

/* Segundos sin actividad en el prompt antes de bloquear el vault. */
#define DEFAULT_LOCK_SECS 120

/* PWM_LOCK_SECS=<5..86400> cambia el tiempo (útil para probar o para la demo). */
static unsigned lock_timeout_secs(void)
{
  const char *env = getenv("PWM_LOCK_SECS");
  if (env != NULL && *env != '\0')
  {
    char *end;
    long v = strtol(env, &end, 10);
    if (*end == '\0' && v >= 5 && v <= 86400)
      return (unsigned) v;
  }
  return DEFAULT_LOCK_SECS;
}

/* Uso: ./pwmanager [archivo]   (por defecto, vault.pwm en el directorio actual) */
int main(int argc, char **argv)
{
  const char *path = argc > 1 ? argv[1] : DEFAULT_VAULT_PATH;

  set_buffer();

  storage_t *storage = NULL;
  vault_t vault;
  if (session_start(path, &storage, &vault) != 0)
    return 1;

  const unsigned lock_secs = lock_timeout_secs();

  while (1)
  {
    printf("> ");
    fflush(stdout);

    /* Sin actividad: se bloquea (borra claves de memoria) y se pide la master de nuevo. */
    if (session_wait_for_input(lock_secs) == 0)
    {
      if (session_relock(path, &storage, &vault) != 0)
        return 1;
      continue;
    }

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

    if (string_equals(input[0], "exit") || string_equals(input[0], "quit"))
    {
      free_user_input(input);
      break;
    }

    if (string_equals(input[0], "generate"))
    {
      entry_t e = {0};
      if (generate_command(&e) == 0)
      {
        if (vault_add(&vault, e, NULL) == 0)
        {
          session_save(storage, &vault);
        }
        else
        {
          printf("Could not store the password.\n");
          entry_free(&e);
        }
      }
    }
    else if (string_equals(input[0], "list"))
    {
      printf("ID | Site name | Notes\n");
      for (size_t i = 0; i < vault.count; i++)
      {
        printf("%u | %s | %s\n", vault.entries[i].id,
               vault.entries[i].site_name, vault.entries[i].notes);
      }
    }
    else if (string_equals(input[0], "add"))
    {
      entry_t e = {0};

      if (add_command(&e) == 0)
      {
        uint32_t id;
        if (vault_add(&vault, e, &id) == 0)
        {
          printf("Password stored successfully (ID %u).\n", id);
          session_save(storage, &vault);
        }
        else
        {
          printf("Could not store the password.\n");
          entry_free(&e);
        }
      }
    }
    else if (string_equals(input[0], "show"))
    {
      cmd_show(&vault);
    }
    else if (string_equals(input[0], "edit"))
    {
      cmd_edit(&vault, storage);
    }
    else if (string_equals(input[0], "delete"))
    {
      cmd_delete(&vault, storage);
    }
    else if (string_equals(input[0], "passwd"))
    {
      session_change_master(storage, &vault);
    }
    else
    {
      printf("Unknown command. Available: generate, add, list, show, edit, delete, passwd, exit\n");
    }

    free_user_input(input);
  }

  vault_free(&vault);
  storage_close(storage);
  return 0;
}