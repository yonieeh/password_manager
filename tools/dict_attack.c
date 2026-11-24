/*
 * dict_attack: simula a un atacante que ROBÓ el archivo y prueba un diccionario.
 *
 * Hace exactamente lo que haría un atacante: por cada candidato, deriva la KEK con
 * Argon2id usando los parámetros que están EN CLARO en el header del archivo, e intenta
 * desenvolver la vault_key. Usa storage_open(), que hace ese mismo trabajo; un intento
 * fallido cuesta lo mismo que una derivación de Argon2id (el resto es despreciable).
 *
 * Uso:   dict_attack <vault> <diccionario.txt> [máx_intentos]
 *
 * Salida (stdout, una línea): CSV
 *   found,position,tried,seconds,guesses_per_s
 *
 * Mide UN hilo. Un atacante real paralelizaría (más núcleos, varias máquinas o GPU);
 * eso se estima aparte, multiplicando, y hay que declararlo como supuesto en el informe.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>

#include "storage/storage.h"
#include "vault/vault.h"

static double now_s(void)
{
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (double) t.tv_sec + (double) t.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
  if (argc < 3 || argc > 4) {
    fprintf(stderr, "uso: %s <vault> <diccionario.txt> [max_intentos]\n", argv[0]);
    return 2;
  }
  unsigned long max_tries = argc == 4 ? strtoul(argv[3], NULL, 10) : 0;   /* 0 = sin límite */

  if (storage_init() != STORAGE_OK) return 1;

  FILE *f = fopen(argv[2], "r");
  if (f == NULL) { perror("diccionario"); return 1; }

  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  unsigned long tried = 0;
  long found_at = -1;

  double t0 = now_s();
  while ((n = getline(&line, &cap, f)) >= 0) {
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
    if (n == 0) continue;                       /* la master vacía no se acepta */

    tried++;
    storage_t *s = NULL;
    vault_t v = {0};
    int rc = storage_open(&s, argv[1], line, &v);
    if (rc == STORAGE_OK) {
      found_at = (long) tried;
      vault_free(&v);
      storage_close(s);
      break;
    }
    if (rc != STORAGE_ERR_AUTH) {
      fprintf(stderr, "error inesperado: %s\n", storage_strerror(rc));
      free(line);
      fclose(f);
      return 1;
    }
    if (max_tries && tried >= max_tries) break;
  }
  double dt = now_s() - t0;

  free(line);
  fclose(f);

  printf("%s,%ld,%lu,%.3f,%.3f\n", found_at > 0 ? "yes" : "no", found_at, tried, dt,
         dt > 0 ? (double) tried / dt : 0.0);
  return 0;
}