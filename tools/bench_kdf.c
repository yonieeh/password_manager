/*
 * bench_kdf: mide tiempo y memoria de Argon2id para varias configuraciones.
 *
 * Compilar (desde la raíz del proyecto):
 *   mkdir -p build && gcc -std=gnu11 -Wall -Wextra -O2 tools/bench_kdf.c -lsodium -o build/bench_kdf
 *
 * Usar:
 *   ./build/bench_kdf                      # grilla por defecto, 5 repeticiones (CSV a stdout)
 *   ./build/bench_kdf -r 10 > kdf.csv      # 10 repeticiones, guardado en un archivo
 *   ./build/bench_kdf -q                   # versión rápida: solo 3 configuraciones
 *
 * Columnas del CSV:
 *   ops, mem_mib      parámetros de Argon2id (pasadas, memoria en MiB)
 *   mean_ms/min/max   tiempo de UNA derivación, en milisegundos
 *   peak_rss_mib      memoria residente máxima del proceso al terminar esa configuración
 *   guesses_per_s     1000 / mean_ms: intentos por segundo de UN hilo con esta configuración
 *
 * Notas de método:
 *  - Cada configuración se mide en un proceso hijo (fork), así el "peak RSS" es de esa
 *    configuración sola y no del máximo acumulado de las anteriores.
 *  - Antes de medir se hace una derivación de calentamiento que no se cuenta.
 *  - Cierra otros programas pesados (navegador, etc.) mientras mides: los tiempos dependen
 *    del estado de la máquina. Reporta siempre el modelo de CPU y la RAM en el informe.
 *  - Los parámetros de abajo, ops=3 y mem=256 MiB, son los que usa storage.c
 *    (crypto_pwhash_OPSLIMIT_MODERATE / MEMLIMIT_MODERATE en libsodium 1.0.18).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

typedef struct { unsigned long long ops; size_t mem_mib; } config_t;

static const config_t GRID[] = {
  {1, 8}, {1, 64}, {1, 256},
  {2, 64}, {2, 256},
  {3, 64}, {3, 256}, {3, 512},
  {4, 256}, {4, 512},
  {6, 256},
  {8, 256},
};

static const config_t QUICK[] = { {2, 64}, {3, 256}, {4, 512} };

static double now_ms(void)
{
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (double) t.tv_sec * 1000.0 + (double) t.tv_nsec / 1e6;
}

/* Corre en el hijo. Escribe 4 doubles (mean, min, max, peak_rss_mib) en el pipe. */
static int measure(const config_t *c, int reps, int out_fd)
{
  unsigned char salt[crypto_pwhash_SALTBYTES];
  unsigned char key[32];
  const char *pw = "correct horse battery staple";
  randombytes_buf(salt, sizeof salt);

  size_t mem = c->mem_mib * 1024UL * 1024UL;

  /* Calentamiento (no se cuenta): primera vez pagas page faults y cachés frías. */
  if (crypto_pwhash(key, sizeof key, pw, strlen(pw), salt, c->ops, mem,
                    crypto_pwhash_ALG_ARGON2ID13) != 0)
    return 1;

  double sum = 0, mn = 1e18, mx = 0;
  for (int i = 0; i < reps; i++) {
    double t0 = now_ms();
    if (crypto_pwhash(key, sizeof key, pw, strlen(pw), salt, c->ops, mem,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
      return 1;
    double dt = now_ms() - t0;
    sum += dt;
    if (dt < mn) mn = dt;
    if (dt > mx) mx = dt;
  }

  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);                       /* ru_maxrss está en KiB en Linux */
  double res[4] = { sum / reps, mn, mx, (double) ru.ru_maxrss / 1024.0 };
  return write(out_fd, res, sizeof res) == (ssize_t) sizeof res ? 0 : 1;
}

/* Baseline: intentos/s contra un hash rápido (SHA-256), para contrastar con Argon2id. */
static double baseline_sha256(void)
{
  unsigned char h[crypto_hash_sha256_BYTES] = "correct horse battery staple";
  const unsigned n = 2000000;

  double t0 = now_ms();
  for (unsigned i = 0; i < n; i++)
    crypto_hash_sha256(h, h, sizeof h);               /* encadenado: no se puede optimizar */
  double dt = now_ms() - t0;
  return (double) n / (dt / 1000.0) + (h[0] == 0xFF ? 1e-9 : 0.0);
}

int main(int argc, char **argv)
{
  int reps = 5, quick = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) reps = atoi(argv[++i]);
    else if (strcmp(argv[i], "-q") == 0) quick = 1;
    else { fprintf(stderr, "uso: %s [-r repeticiones] [-q]\n", argv[0]); return 2; }
  }
  if (reps < 1 || reps > 100) { fprintf(stderr, "repeticiones fuera de rango (1-100)\n"); return 2; }
  if (sodium_init() < 0) return 1;

  const config_t *cfg = quick ? QUICK : GRID;
  size_t ncfg = quick ? sizeof QUICK / sizeof *QUICK : sizeof GRID / sizeof *GRID;

  fprintf(stderr, "# libsodium %s, %d repeticiones por configuración, %ld CPUs en línea\n",
          sodium_version_string(), reps, sysconf(_SC_NPROCESSORS_ONLN));
  fprintf(stderr, "# baseline SHA-256 (1 hilo): %.0f intentos/s. Compara con guesses_per_s del CSV.\n",
          baseline_sha256());

  printf("ops,mem_mib,mean_ms,min_ms,max_ms,peak_rss_mib,guesses_per_s\n");
  fflush(stdout);

  for (size_t i = 0; i < ncfg; i++) {
    int fds[2];
    if (pipe(fds) != 0) return 1;

    pid_t pid = fork();
    if (pid == 0) {
      close(fds[0]);
      _exit(measure(&cfg[i], reps, fds[1]));
    }
    close(fds[1]);

    double res[4];
    ssize_t got = read(fds[0], res, sizeof res);
    close(fds[0]);
    int status;
    waitpid(pid, &status, 0);

    if (got != (ssize_t) sizeof res || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      fprintf(stderr, "# ops=%llu mem=%zu MiB: falló (¿sin memoria?)\n", cfg[i].ops, cfg[i].mem_mib);
      continue;
    }
    printf("%llu,%zu,%.1f,%.1f,%.1f,%.0f,%.2f\n", cfg[i].ops, cfg[i].mem_mib,
           res[0], res[1], res[2], res[3], 1000.0 / res[0]);
    fflush(stdout);
  }
  return 0;
}