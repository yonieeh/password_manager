#include "session/session.h"
#include "session/prompt.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <sodium.h>

#define MIN_MASTER_LEN   12
#define MAX_MASTER_LEN   256
#define MAX_ATTEMPTS     3

#define ENTER_ALT_SCREEN "\033[?1049h\033[H"
#define LEAVE_ALT_SCREEN "\033[2J\033[H\033[?1049l"

static int interactive(void)
{
  if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) return 1;
  fprintf(stderr, "This step needs an interactive terminal (it shows a secret that must not be redirected).\n");
  return 0;
}

/* ------------------------------------------------------------ recovery key */

static void leave_screen_and_exit(int sig)
{
  (void) sig;
  (void) !write(STDOUT_FILENO, LEAVE_ALT_SCREEN, sizeof LEAVE_ALT_SCREEN - 1);
  _exit(130);
}

/* La muestra en la pantalla alternativa: no queda en el scrollback de la terminal. */
static void show_recovery_key(const char *hex)
{
  struct sigaction sa, old_int, old_term;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = leave_screen_and_exit;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, &old_int);
  sigaction(SIGTERM, &sa, &old_term);

  printf(ENTER_ALT_SCREEN);
  printf("RECOVERY KEY\n\n  ");
  size_t len = strlen(hex);
  for (size_t i = 0; i < len; i++) {
    putchar(hex[i]);
    if ((i + 1) % 8 == 0 && i + 1 < len) putchar('-');
  }
  printf("\n\nThis is the ONLY way to open your vault if you forget the master password.\n"
         "Write it down and keep it somewhere safe, OUTSIDE this computer.\n"
         "It will not be shown again.\n\n"
         "Press Enter when you have saved it. ");
  fflush(stdout);

  prompt_free(prompt_line(""));
  clearerr(stdin);

  printf(LEAVE_ALT_SCREEN);
  fflush(stdout);

  sigaction(SIGINT, &old_int, NULL);
  sigaction(SIGTERM, &old_term, NULL);
}

/* ------------------------------------------------------------ master nueva */

/* Pide una master nueva con confirmación. NULL si el usuario cancela (EOF). */
static char *ask_new_master(void)
{
  printf("Choose a master password (at least %d characters). A passphrase of several\n"
         "random words is easier to remember and much harder to guess.\n", MIN_MASTER_LEN);

  while (1) {
    char *first = prompt_hidden("New master password\n> ");
    if (first == NULL) return NULL;

    size_t n = strlen(first);
    if (n < MIN_MASTER_LEN || n > MAX_MASTER_LEN) {
      printf("It must be between %d and %d characters.\n", MIN_MASTER_LEN, MAX_MASTER_LEN);
      prompt_free(first);
      continue;
    }

    char *second = prompt_hidden("Confirm master password\n> ");
    if (second == NULL) { prompt_free(first); return NULL; }

    int same = strlen(second) == n && sodium_memcmp(first, second, n) == 0;
    prompt_free(second);
    if (same) return first;

    prompt_free(first);
    printf("Passwords do not match. Try again.\n");
  }
}

/* -------------------------------------------------------------------- flujos */

int session_save(storage_t *s, const vault_t *vault)
{
  int rc = storage_save(s, vault);
  if (rc != STORAGE_OK) {
    printf("WARNING: could not save the vault (%s). Your changes are only in memory.\n",
           storage_strerror(rc));
    return -1;
  }
  return 0;
}

int session_change_master(storage_t *s, const vault_t *vault)
{
  if (!interactive()) return -1;

  char *master = ask_new_master();
  if (master == NULL) {
    clearerr(stdin);
    printf("\nCancelled.\n");
    return -1;
  }

  char hex[STORAGE_RECOVERY_HEX_LEN + 1];
  int rc = storage_change_master(s, master, vault, hex);
  prompt_free(master);

  if (rc != STORAGE_OK) {
    printf("Could not change the master password (%s). Nothing was changed.\n",
           storage_strerror(rc));
    return -1;
  }

  show_recovery_key(hex);
  sodium_memzero(hex, sizeof hex);
  printf("Master password changed. The previous master password and recovery key\n"
         "no longer open this vault.\n");
  return 0;
}

static int create_flow(const char *path, storage_t **s, vault_t *vault)
{
  if (!interactive()) return -1;

  printf("No vault found at '%s'. Let's create one.\n", path);

  char *master = ask_new_master();
  if (master == NULL) { printf("\nCancelled.\n"); return -1; }

  char hex[STORAGE_RECOVERY_HEX_LEN + 1];
  int rc = storage_create(s, path, master, hex);
  prompt_free(master);

  if (rc != STORAGE_OK) {
    printf("Could not create the vault (%s).\n", storage_strerror(rc));
    return -1;
  }

  show_recovery_key(hex);
  sodium_memzero(hex, sizeof hex);

  *vault = (vault_t){0};
  vault->next_id = 1;
  if (session_save(*s, vault) != 0) {
    storage_close(*s);
    *s = NULL;
    return -1;
  }
  printf("Vault created.\n");
  return 0;
}

static int recovery_flow(const char *path, storage_t **s, vault_t *vault)
{
  if (!interactive()) return -1;

  for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    char *key = prompt_hidden("Recovery key\n> ");
    if (key == NULL) { printf("\n"); return -1; }

    int rc = storage_open_recovery(s, path, key, vault);
    prompt_free(key);

    if (rc == STORAGE_OK) {
      printf("Recovery key accepted. Choose a new master password now.\n");
      /* Sin master nueva no seguimos: así la recovery key usada queda rotada. */
      if (session_change_master(*s, vault) != 0) {
        vault_free(vault);
        storage_close(*s);
        *s = NULL;
        return -1;
      }
      return 0;
    }
    printf("%s\n", storage_strerror(rc));
    if (rc != STORAGE_ERR_AUTH) return -1;
  }
  printf("Too many failed attempts.\n");
  return -1;
}

static int unlock_flow(const char *path, storage_t **s, vault_t *vault)
{
  for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    char *master = prompt_hidden("Master password (leave empty to use your recovery key)\n> ");
    if (master == NULL) { printf("\n"); return -1; }

    if (master[0] == '\0') {
      free(master);
      return recovery_flow(path, s, vault);
    }

    int rc = storage_open(s, path, master, vault);
    prompt_free(master);

    if (rc == STORAGE_OK) return 0;
    printf("%s\n", storage_strerror(rc));
    if (rc != STORAGE_ERR_AUTH) return -1;     /* reintentar no ayuda con un archivo dañado */
  }
  printf("Too many failed attempts.\n");
  return -1;
}

int session_start(const char *path, storage_t **s, vault_t *vault)
{
  *s = NULL;
  *vault = (vault_t){0};

  if (storage_init() != STORAGE_OK) {
    fprintf(stderr, "Could not initialize the crypto library.\n");
    return -1;
  }

  return storage_exists(path) ? unlock_flow(path, s, vault)
                              : create_flow(path, s, vault);
}

/* ------------------------------------------------------ bloqueo por inactividad */

#define MAX_LOCK_SECS 86400U

int session_wait_for_input(unsigned timeout_secs)
{
  /* Sin terminal (pipes, tests) no hay "usuario ausente" que detectar. */
  if (timeout_secs == 0 || !isatty(STDIN_FILENO)) return 1;
  if (timeout_secs > MAX_LOCK_SECS) timeout_secs = MAX_LOCK_SECS;

  struct pollfd p;
  p.fd = STDIN_FILENO;
  p.events = POLLIN;
  p.revents = 0;

  for (;;) {
    int r = poll(&p, 1, (int) (timeout_secs * 1000U));
    if (r > 0) return 1;                  /* hay algo que leer (o EOF) */
    if (r == 0) return 0;                 /* pasó el tiempo sin actividad */
    if (errno != EINTR) return 1;         /* error raro: no bloquear por las dudas */
  }
}

int session_relock(const char *path, storage_t **s, vault_t *vault)
{
  /* vault_free borra las contraseñas de memoria; storage_close borra la vault_key. */
  vault_free(vault);
  storage_close(*s);
  *s = NULL;

  if (isatty(STDOUT_FILENO))
    printf("\033[2J\033[3J\033[H");      /* pantalla y scrollback: que no quede nada a la vista */
  printf("Vault locked after inactivity.\n");

  return unlock_flow(path, s, vault);
}