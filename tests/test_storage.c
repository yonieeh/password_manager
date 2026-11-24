/*
 * Tests del módulo storage.
 *
 * Compilar (costos de KDF bajos para que sea rápido) desde la raíz del proyecto:
 *
 *   gcc -std=gnu11 -Wall -Wextra -g -O0 -fsanitize=address,undefined -Isrc \
 *     -DSTORAGE_KDF_OPSLIMIT=crypto_pwhash_OPSLIMIT_MIN \
 *     -DSTORAGE_KDF_MEMLIMIT=crypto_pwhash_MEMLIMIT_MIN \
 *     tests/test_storage.c src/storage/storage.c src/vault/entry.c src/vault/vault.c \
 *     -lsodium -o build/test_storage && ./build/test_storage
 *
 * (ajusta las rutas de entry.c / vault.c a donde estén en tu proyecto)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sodium.h>

#include "storage/storage.h"
#include "vault/vault.h"

static int failures = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      printf("  FAIL  %s:%d  %s\n", __FILE__, __LINE__, #cond);              \
      failures++;                                                            \
    }                                                                        \
  } while (0)

#define CHECK_RC(expr, expected)                                             \
  do {                                                                       \
    int rc_ = (expr);                                                        \
    if (rc_ != (expected)) {                                                 \
      printf("  FAIL  %s:%d  %s -> %d (%s), esperaba %d\n", __FILE__,        \
             __LINE__, #expr, rc_, storage_strerror(rc_), (expected));       \
      failures++;                                                            \
    }                                                                        \
  } while (0)

static void add(vault_t *v, const char *site, const char *pass, const char *notes)
{
  entry_t e = {0};
  e.site_name = strdup(site);
  e.password = strdup(pass);
  e.notes = strdup(notes);
  if (vault_add(v, e, NULL) != 0) { printf("vault_add falló\n"); exit(1); }
}

static long file_size(const char *path)
{
  struct stat st;
  return stat(path, &st) == 0 ? (long) st.st_size : -1;
}

static void flip_byte(const char *path, long offset)
{
  FILE *f = fopen(path, "r+b");
  if (!f) { printf("no pude abrir %s\n", path); exit(1); }
  fseek(f, offset, SEEK_SET);
  int c = fgetc(f);
  fseek(f, offset, SEEK_SET);
  fputc(c ^ 0x01, f);
  fclose(f);
}

static void copy_file(const char *from, const char *to)
{
  FILE *a = fopen(from, "rb"), *b = fopen(to, "wb");
  int c;
  while ((c = fgetc(a)) != EOF) fputc(c, b);
  fclose(a);
  fclose(b);
}

int main(void)
{
  const char *path = "test_vault.bin";
  const char *backup = "test_vault.bak";
  char recovery[STORAGE_RECOVERY_HEX_LEN + 1];
  storage_t *s = NULL;
  vault_t v = {0}, loaded = {0};

  setvbuf(stdout, NULL, _IONBF, 0);
  unlink(path);
  unlink(backup);

  CHECK_RC(storage_init(), STORAGE_OK);

  printf("crear vault vacío\n");
  CHECK(!storage_exists(path));
  CHECK_RC(storage_create(&s, path, "correct horse battery", recovery), STORAGE_OK);
  CHECK(storage_exists(path));
  CHECK(strlen(recovery) == STORAGE_RECOVERY_HEX_LEN);
  {
    storage_t *other = NULL;
    char other_recovery[STORAGE_RECOVERY_HEX_LEN + 1];
    CHECK_RC(storage_create(&other, path, "otra", other_recovery), STORAGE_ERR_EXISTS);
    CHECK(other == NULL);
  }
  storage_close(s);
  s = NULL;

  struct stat st;
  CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);

  printf("padding: tamaño igual con 0 y con 5 entradas\n");
  long size_empty = file_size(path);
  CHECK_RC(storage_open(&s, path, "correct horse battery", &loaded), STORAGE_OK);
  CHECK(loaded.count == 0);
  vault_free(&loaded);

  add(&v, "Twitter", "p4ss-1", "cuenta principal");
  add(&v, "Banco de Chile", "p4ss-2", "linea 1\nlinea 2, con coma; y \"comillas\"");
  add(&v, "Riot Games", "p4ss-3", "");
  add(&v, "UTF8 ñandú", "contraseña-ñ-€", "notas con acentos áéíóú");
  add(&v, "Cuatro", "p4ss-5", "x");
  CHECK_RC(storage_save(s, &v), STORAGE_OK);
  CHECK(file_size(path) == size_empty);

  printf("roundtrip\n");
  storage_close(s);
  s = NULL;
  CHECK_RC(storage_open(&s, path, "correct horse battery", &loaded), STORAGE_OK);
  CHECK(loaded.count == 5);
  CHECK(loaded.next_id == 5);
  if (loaded.count == 5) {
    for (size_t i = 0; i < 5; i++) {
      CHECK(loaded.entries[i].id == v.entries[i].id);
      CHECK(strcmp(loaded.entries[i].site_name, v.entries[i].site_name) == 0);
      CHECK(strcmp(loaded.entries[i].password, v.entries[i].password) == 0);
      CHECK(strcmp(loaded.entries[i].notes, v.entries[i].notes) == 0);
    }
  }
  vault_free(&loaded);

  printf("el contenido no aparece en claro en el archivo\n");
  {
    FILE *f = fopen(path, "rb");
    long n = file_size(path);
    char *buf = malloc((size_t) n);
    CHECK(fread(buf, 1, (size_t) n, f) == (size_t) n);
    fclose(f);
    CHECK(memmem(buf, (size_t) n, "Twitter", 7) == NULL);
    CHECK(memmem(buf, (size_t) n, "p4ss-1", 6) == NULL);
    CHECK(memmem(buf, (size_t) n, "Banco", 5) == NULL);
    free(buf);
  }

  printf("guardar varias veces usa nonces distintos\n");
  copy_file(path, backup);
  CHECK_RC(storage_save(s, &v), STORAGE_OK);
  {
    FILE *a = fopen(path, "rb"), *b = fopen(backup, "rb");
    unsigned char na[24], nb[24];
    fseek(a, 182, SEEK_SET);
    fseek(b, 182, SEEK_SET);
    CHECK(fread(na, 1, 24, a) == 24 && fread(nb, 1, 24, b) == 24);
    CHECK(memcmp(na, nb, 24) != 0);
    fclose(a);
    fclose(b);
  }
  storage_close(s);
  s = NULL;

  printf("master incorrecta / vacía\n");
  CHECK_RC(storage_open(&s, path, "mala", &loaded), STORAGE_ERR_AUTH);
  CHECK(s == NULL && loaded.count == 0);
  CHECK_RC(storage_open(&s, path, "", &loaded), STORAGE_ERR_AUTH);

  printf("archivo manipulado\n");
  copy_file(path, backup);
  flip_byte(path, 0);                              /* magic */
  CHECK_RC(storage_open(&s, path, "correct horse battery", &loaded), STORAGE_ERR_FORMAT);
  copy_file(backup, path);

  flip_byte(path, 60);                             /* master_wrap */
  CHECK_RC(storage_open(&s, path, "correct horse battery", &loaded), STORAGE_ERR_AUTH);
  copy_file(backup, path);

  flip_byte(path, 25);                             /* salt */
  CHECK_RC(storage_open(&s, path, "correct horse battery", &loaded), STORAGE_ERR_AUTH);
  copy_file(backup, path);

  flip_byte(path, 190);                            /* nonce del cuerpo */
  CHECK_RC(storage_open(&s, path, "correct horse battery", &loaded), STORAGE_ERR_TAMPERED);
  copy_file(backup, path);

  flip_byte(path, 300);                            /* texto cifrado */
  CHECK_RC(storage_open(&s, path, "correct horse battery", &loaded), STORAGE_ERR_TAMPERED);
  copy_file(backup, path);

  flip_byte(path, file_size(path) - 1);            /* tag */
  CHECK_RC(storage_open(&s, path, "correct horse battery", &loaded), STORAGE_ERR_TAMPERED);
  copy_file(backup, path);

  CHECK(truncate(path, 100) == 0);                 /* truncado */
  CHECK_RC(storage_open(&s, path, "correct horse battery", &loaded), STORAGE_ERR_FORMAT);
  copy_file(backup, path);

  CHECK(truncate(path, file_size(path) - 1) == 0); /* un byte menos */
  CHECK_RC(storage_open(&s, path, "correct horse battery", &loaded), STORAGE_ERR_TAMPERED);
  copy_file(backup, path);

  {                                                /* costos absurdos en el header */
    FILE *f = fopen(path, "r+b");
    fseek(f, 14 + 7, SEEK_SET);                    /* byte alto de memlimit */
    fputc(0x7f, f);
    fclose(f);
    CHECK_RC(storage_open(&s, path, "correct horse battery", &loaded), STORAGE_ERR_FORMAT);
    copy_file(backup, path);
  }

  CHECK_RC(storage_open(&s, "no_existe.bin", "x", &loaded), STORAGE_ERR_IO);

  printf("recovery key\n");
  CHECK_RC(storage_open_recovery(&s, path, "00112233", &loaded), STORAGE_ERR_AUTH);
  CHECK_RC(storage_open_recovery(&s, path, recovery, &loaded), STORAGE_OK);
  CHECK(loaded.count == 5);
  CHECK(strcmp(loaded.entries[0].password, "p4ss-1") == 0);

  printf("cambiar master rota la vault key y la recovery key\n");
  char new_recovery[STORAGE_RECOVERY_HEX_LEN + 1];
  copy_file(path, "test_vault.old");                /* copia vieja: master vieja + recovery vieja */
  CHECK_RC(storage_change_master(s, "nueva master 2026", &loaded, new_recovery), STORAGE_OK);
  CHECK(strlen(new_recovery) == STORAGE_RECOVERY_HEX_LEN);
  CHECK(strcmp(new_recovery, recovery) != 0);
  vault_free(&loaded);
  storage_close(s);
  s = NULL;

  CHECK_RC(storage_open(&s, path, "correct horse battery", &loaded), STORAGE_ERR_AUTH);
  CHECK_RC(storage_open(&s, path, "nueva master 2026", &loaded), STORAGE_OK);
  CHECK(loaded.count == 5);
  vault_free(&loaded);
  storage_close(s);
  s = NULL;

  CHECK_RC(storage_open_recovery(&s, path, recovery, &loaded), STORAGE_ERR_AUTH);  /* la vieja ya no sirve */
  CHECK_RC(storage_open_recovery(&s, path, new_recovery, &loaded), STORAGE_OK);
  vault_free(&loaded);
  storage_close(s);
  s = NULL;

  printf("ataque: header viejo (master vieja) + cuerpo nuevo no abre\n");
  {
    FILE *o = fopen("test_vault.old", "rb"), *n = fopen(path, "rb"), *h = fopen("test_vault.hyb", "wb");
    unsigned char hdr[182];
    CHECK(fread(hdr, 1, 182, o) == 182);
    fwrite(hdr, 1, 182, h);
    fseek(n, 182, SEEK_SET);
    int c;
    while ((c = fgetc(n)) != EOF) fputc(c, h);
    fclose(o);
    fclose(n);
    fclose(h);
    /* con la vault_key sin rotar, esto abriría: la clave vieja descifraría el cuerpo nuevo */
    CHECK_RC(storage_open(&s, "test_vault.hyb", "correct horse battery", &loaded), STORAGE_ERR_TAMPERED);
    CHECK_RC(storage_open_recovery(&s, "test_vault.hyb", recovery, &loaded), STORAGE_ERR_TAMPERED);
    unlink("test_vault.hyb");
  }

  printf("recovery key con formato (mayúsculas, espacios y guiones)\n");
  {
    char pretty[STORAGE_RECOVERY_HEX_LEN * 2];
    size_t j = 0;
    for (size_t i = 0; i < STORAGE_RECOVERY_HEX_LEN; i++) {
      if (i && i % 8 == 0) pretty[j++] = '-';
      char c = new_recovery[i];
      pretty[j++] = (c >= 'a' && c <= 'f') ? (char) (c - 32) : c;
    }
    pretty[j] = '\0';
    CHECK_RC(storage_open_recovery(&s, path, pretty, &loaded), STORAGE_OK);
    vault_free(&loaded);
    storage_close(s);
    s = NULL;
  }

  printf("vault que crece más allá de un bloque de padding\n");
  CHECK_RC(storage_open(&s, path, "nueva master 2026", &loaded), STORAGE_OK);
  for (int i = 0; i < 200; i++) {
    char name[32], pass[32];
    snprintf(name, sizeof name, "sitio-%d", i);
    snprintf(pass, sizeof pass, "clave-%d", i);
    add(&loaded, name, pass, "notas de relleno para ocupar espacio en el archivo");
  }
  CHECK_RC(storage_save(s, &loaded), STORAGE_OK);
  CHECK(file_size(path) > size_empty);
  CHECK((file_size(path) - 182 - 24 - 16) % 4096 == 0);
  vault_free(&loaded);
  storage_close(s);
  s = NULL;
  CHECK_RC(storage_open(&s, path, "nueva master 2026", &loaded), STORAGE_OK);
  CHECK(loaded.count == 205);
  CHECK(loaded.next_id == 205);
  vault_free(&loaded);
  storage_close(s);

  vault_free(&v);
  unlink(path);
  unlink(backup);
  unlink("test_vault.old");

  if (failures == 0) printf("\nTODOS LOS TESTS PASARON\n");
  else printf("\n%d CHEQUEOS FALLARON\n", failures);
  return failures == 0 ? 0 : 1;
}