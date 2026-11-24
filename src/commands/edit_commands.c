#include "commands/edit_commands.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api/api.h"
#include "clipboard/clipboard.h"
#include "config.h"
#include "display/display.h"
#include "session/prompt.h"
#include "session/session.h"

/* Valores por defecto por si config.h no los define. */
#ifndef MAX_PASSWORD_LENGTH
#define MAX_PASSWORD_LENGTH 128
#endif
#ifndef MAX_NAME_LEN
#define MAX_NAME_LEN 128
#endif
#ifndef MAX_NOTES_LEN
#define MAX_NOTES_LEN 1024
#endif
#ifndef CLIPBOARD_CLEAR_SECS
#define CLIPBOARD_CLEAR_SECS 30
#endif
#ifndef SECRET_DISPLAY_SECS
#define SECRET_DISPLAY_SECS 15
#endif

#define DEFAULT_GENERATED_LENGTH 20

static const char *or_empty(const char *s) { return s ? s : ""; }

static void cancelled_eof(void)
{
  clearerr(stdin);
  printf("\nCancelled.\n");
}

/* Retorna 0 y *out lleno, 1 si el usuario dejó la línea vacía (cancelar), -1 en EOF. */
static int ask_id(const char *message, unsigned long *out)
{
  while (1) {
    printf("%s (leave empty to cancel)\n", message);
    char *line = prompt_line("> ");
    if (line == NULL) return -1;
    if (line[0] == '\0') { free(line); return 1; }

    size_t n = strlen(line);
    bool ok = n <= 9;
    for (size_t i = 0; ok && i < n; i++)
      if (!isdigit((unsigned char) line[i])) ok = false;

    if (ok) *out = strtoul(line, NULL, 10);
    free(line);
    if (ok) return 0;
    printf("Invalid ID. ");
  }
}

/* Retorna 1 (sí), 0 (no), -1 (EOF). Enter = la opción por defecto. */
static int confirm(const char *question, bool default_yes)
{
  while (1) {
    printf("%s [%s]\n", question, default_yes ? "Y/n" : "y/N");
    char *line = prompt_line("> ");
    if (line == NULL) return -1;

    char c = (char) tolower((unsigned char) line[0]);
    free(line);

    if (c == '\0') return default_yes ? 1 : 0;
    if (c == 'y') return 1;
    if (c == 'n') return 0;
    printf("Please answer y or n. ");
  }
}

/* Resultado de leer el id y buscar la entrada. */
static entry_t *pick_entry(vault_t *v, const char *message, unsigned long *id)
{
  int r = ask_id(message, id);
  if (r < 0) { cancelled_eof(); return NULL; }
  if (r > 0) { printf("Cancelled.\n"); return NULL; }

  entry_t *e = vault_find(v, (uint32_t) *id);
  if (e == NULL) printf("No entry with id %lu.\n", *id);
  return e;
}

/* ------------------------------------------------------------------- delete */

int cmd_delete(vault_t *v, storage_t *s)
{
  unsigned long id;
  entry_t *e = pick_entry(v, "Enter the ID of the entry to delete", &id);
  if (e == NULL) return -1;

  char question[256];
  snprintf(question, sizeof question, "Delete '%.60s' (ID %lu)? This cannot be undone.",
           or_empty(e->site_name), id);

  int yes = confirm(question, false);
  if (yes < 0) { cancelled_eof(); return -1; }
  if (!yes) { printf("Cancelled.\n"); return -1; }

  if (vault_remove(v, (uint32_t) id) != 0) {     /* no debería pasar: ya la encontramos */
    printf("Could not delete the entry.\n");
    return -1;
  }
  printf("Entry deleted.\n");
  session_save(s, v);
  return 0;
}

/* --------------------------------------------------------------------- edit */

/* Pide una contraseña escrita por el usuario (oculta, con confirmación).
 * Retorna string malloc'd, o NULL en EOF. */
static char *ask_typed_password(void)
{
  while (1) {
    char *first = prompt_hidden("New password (hidden)\n> ");
    if (first == NULL) return NULL;

    size_t n = strlen(first);
    if (n == 0 || n > MAX_PASSWORD_LENGTH) {
      printf("The password must have between 1 and %d characters.\n", MAX_PASSWORD_LENGTH);
      prompt_free(first);
      continue;
    }

    char *second = prompt_hidden("Confirm the password (hidden)\n> ");
    if (second == NULL) { prompt_free(first); return NULL; }

    bool same = strcmp(first, second) == 0;
    prompt_free(second);
    if (same) return first;

    prompt_free(first);
    printf("Passwords do not match. Try again.\n");
  }
}

/* Genera una contraseña con los cuatro tipos de caracteres. 0 si ok, 1 error, -1 EOF. */
static int ask_generated_password(char **out)
{
  int length = DEFAULT_GENERATED_LENGTH;

  while (1) {
    printf("Length (1-%d, leave empty for %d)\n", MAX_PASSWORD_LENGTH, DEFAULT_GENERATED_LENGTH);
    char *line = prompt_line("> ");
    if (line == NULL) return -1;

    if (line[0] == '\0') { free(line); break; }

    size_t n = strlen(line);
    bool ok = n <= 4;
    for (size_t i = 0; ok && i < n; i++)
      if (!isdigit((unsigned char) line[i])) ok = false;
    long value = ok ? strtol(line, NULL, 10) : 0;
    free(line);

    if (ok && value >= 1 && value <= MAX_PASSWORD_LENGTH) { length = (int) value; break; }
    printf("Invalid length. ");
  }

  char buf[MAX_PASSWORD_LENGTH + 1];
  if (generate_password(buf, (size_t) length + 1, true, true, true, true) != 0) {
    printf("Error generating the password.\n");
    return 1;
  }

  *out = strdup(buf);
  explicit_bzero(buf, sizeof buf);
  return *out ? 0 : 1;
}

int cmd_edit(vault_t *v, storage_t *s)
{
  unsigned long id;
  entry_t *e = pick_entry(v, "Enter the ID of the entry to edit", &id);
  if (e == NULL) return -1;

  char *new_name = NULL, *new_notes = NULL, *new_pass = NULL;
  bool generated = false;
  int rc = -1;

  printf("Editing '%.60s' (ID %lu). Press Enter to keep the current value.\n",
         or_empty(e->site_name), id);

  /* Nombre */
  while (1) {
    printf("Name [current: %.60s]\n", or_empty(e->site_name));
    char *line = prompt_line("> ");
    if (line == NULL) { cancelled_eof(); goto done; }
    if (line[0] == '\0') { free(line); break; }
    if (strlen(line) > MAX_NAME_LEN) {
      free(line);
      printf("Name too long (max %d). ", MAX_NAME_LEN);
      continue;
    }
    new_name = line;
    break;
  }

  /* Notas ("-" las borra) */
  while (1) {
    printf("Notes [current: %.60s] (type - to clear them)\n", or_empty(e->notes));
    char *line = prompt_line("> ");
    if (line == NULL) { cancelled_eof(); goto done; }
    if (line[0] == '\0') { free(line); break; }
    if (strlen(line) > MAX_NOTES_LEN) {
      free(line);
      printf("Notes too long (max %d). ", MAX_NOTES_LEN);
      continue;
    }
    if (strcmp(line, "-") == 0) line[0] = '\0';     /* queda como string vacío */
    new_notes = line;
    break;
  }

  /* Contraseña */
  int change = confirm("Change the password?", false);
  if (change < 0) { cancelled_eof(); goto done; }
  if (change == 1) {
    int gen = confirm("Generate a new random password?", true);
    if (gen < 0) { cancelled_eof(); goto done; }

    if (gen == 1) {
      int r = ask_generated_password(&new_pass);
      if (r < 0) { cancelled_eof(); goto done; }
      if (r > 0) goto done;
      generated = true;
    } else {
      new_pass = ask_typed_password();
      if (new_pass == NULL) { cancelled_eof(); goto done; }
    }
  }

  if (new_name == NULL && new_notes == NULL && new_pass == NULL) {
    printf("No changes.\n");
    rc = 0;
    goto done;
  }

  /* Recién ahora se modifica la entrada: todo lo anterior era cancelable. */
  if (new_name)  { free(e->site_name); e->site_name = new_name; new_name = NULL; }
  if (new_notes) { free(e->notes);     e->notes = new_notes;    new_notes = NULL; }
  if (new_pass) {
    prompt_free(e->password);
    e->password = new_pass;
    new_pass = NULL;
  }

  printf("Entry updated.\n");
  session_save(s, v);

  if (generated) {
    if (clipboard_copy(e->password, CLIPBOARD_CLEAR_SECS) == 0)
      printf("New password copied to clipboard (cleared in %d s).\n", CLIPBOARD_CLEAR_SECS);
    else
      show_secret_temporarily(e->password, SECRET_DISPLAY_SECS);
  }
  rc = 0;

done:
  free(new_name);
  free(new_notes);
  prompt_free(new_pass);
  return rc;
}