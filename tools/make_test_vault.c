/*
 * make_test_vault: crea una vault de PRUEBA con una master conocida y unas entradas.
 *
 * El costo de Argon2id sale de storage.c (STORAGE_KDF_OPSLIMIT / STORAGE_KDF_MEMLIMIT),
 * que se fijan al compilar. run_experiments.sh compila este programa una vez por
 * configuración; para uso manual ver el comentario de ese script.
 *
 * Uso:  make_test_vault <archivo> <master>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "storage/storage.h"
#include "vault/vault.h"

static void add(vault_t *v, const char *site, const char *pass, const char *notes)
{
  entry_t e = {0};
  e.site_name = strdup(site);
  e.password = strdup(pass);
  e.notes = strdup(notes);
  if (e.site_name == NULL || e.password == NULL || e.notes == NULL ||
      vault_add(v, e, NULL) != 0) {
    fprintf(stderr, "sin memoria\n");
    exit(1);
  }
}

int main(int argc, char **argv)
{
  if (argc != 3) {
    fprintf(stderr, "uso: %s <archivo> <master>\n", argv[0]);
    return 2;
  }
  if (storage_init() != STORAGE_OK) return 1;

  storage_t *s = NULL;
  char recovery[STORAGE_RECOVERY_HEX_LEN + 1];
  int rc = storage_create(&s, argv[1], argv[2], recovery);
  if (rc != STORAGE_OK) {
    fprintf(stderr, "no se pudo crear: %s\n", storage_strerror(rc));
    return 1;
  }
  sodium_memzero(recovery, sizeof recovery);

  vault_t v = {0};
  v.next_id = 1;
  add(&v, "Twitter", "tw-pass-1", "cuenta de prueba");
  add(&v, "Riot Games", "riot-pass-2", "otra cuenta de prueba");
  add(&v, "Banco", "banco-pass-3", "");

  rc = storage_save(s, &v);
  vault_free(&v);
  storage_close(s);
  if (rc != STORAGE_OK) {
    fprintf(stderr, "no se pudo guardar: %s\n", storage_strerror(rc));
    return 1;
  }
  return 0;
}