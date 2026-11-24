#ifndef STORAGE_H
#define STORAGE_H

/*
 * Almacenamiento cifrado del vault en un solo archivo.
 *
 * Jerarquía de claves:
 *   master password --Argon2id--> KEK_master --envuelve--> vault_key
 *   recovery key (32 bytes aleatorios) -------envuelve--> vault_key
 *   vault_key --XChaCha20-Poly1305--> blob con todo el vault (con padding)
 *
 * Requiere libsodium (enlazar con -lsodium).
 */

#include <stddef.h>
#include "vault/vault.h"

/* Largo (en caracteres, sin '\0') de la recovery key en hexadecimal. */
#define STORAGE_RECOVERY_HEX_LEN 64

typedef enum {
  STORAGE_OK            =  0,
  STORAGE_ERR_IO        = -1,  /* no se pudo leer/escribir el archivo */
  STORAGE_ERR_FORMAT    = -2,  /* no es un vault, o el header es inválido */
  STORAGE_ERR_AUTH      = -3,  /* master/recovery key incorrecta, o header alterado */
  STORAGE_ERR_TAMPERED  = -4,  /* la clave abrió, pero el contenido no verifica */
  STORAGE_ERR_CRYPTO    = -5,  /* fallo de libsodium o sin memoria */
  STORAGE_ERR_EXISTS    = -6,  /* storage_create sobre un archivo que ya existe */
  STORAGE_ERR_ARG       = -7   /* argumentos inválidos */
} storage_status;

/* Sesión abierta: contiene la vault_key mientras el vault está desbloqueado. */
typedef struct storage storage_t;

/* Inicializa libsodium. Llamar una vez al inicio. 0 = ok. */
int storage_init(void);

/* 1 si el archivo existe, 0 si no. */
int storage_exists(const char *path);

/*
 * Crea un vault nuevo (vacío) en `path`. Falla con STORAGE_ERR_EXISTS si ya existe.
 * Escribe en recovery_hex la recovery key (STORAGE_RECOVERY_HEX_LEN chars + '\0'):
 * se muestra UNA vez al usuario y no se guarda en ningún lado. El que llama debe
 * limpiar recovery_hex con sodium_memzero() después de mostrarla.
 */
int storage_create(storage_t **out, const char *path, const char *master,
                   char recovery_hex[STORAGE_RECOVERY_HEX_LEN + 1]);

/*
 * Abre un vault existente con la master password y carga su contenido en *vault.
 * *vault debe venir inicializado en cero (vault_t v = {0}).
 * Si falla, *vault queda vacío y *out en NULL.
 */
int storage_open(storage_t **out, const char *path, const char *master,
                 vault_t *vault);

/* Igual que storage_open, pero con la recovery key (acepta espacios y guiones). */
int storage_open_recovery(storage_t **out, const char *path,
                          const char *recovery_hex, vault_t *vault);

/* Cifra y escribe el vault completo (escritura atómica). Llamar tras cada cambio. */
int storage_save(storage_t *s, const vault_t *vault);

/*
 * Cambia la master password y ROTA las claves: genera una vault_key nueva, re-cifra
 * el contenido con ella, y genera una recovery key nueva (la anterior queda inválida).
 * Escribe la recovery key nueva en recovery_hex (mostrarla una vez y limpiarla).
 *
 * Por qué rotar y no solo re-envolver: si la vault_key no cambiara, quien tenga una
 * copia vieja del archivo y la master vieja podría descifrar también el archivo nuevo.
 *
 * Guarda el archivo. Si falla, el estado anterior se conserva (en disco y en memoria).
 * Es lo que se usa después de abrir con la recovery key.
 */
int storage_change_master(storage_t *s, const char *new_master, const vault_t *vault,
                          char recovery_hex[STORAGE_RECOVERY_HEX_LEN + 1]);

/* Borra la vault_key de memoria y libera la sesión. Acepta NULL. */
void storage_close(storage_t *s);

/* Mensaje legible para un código de storage_status. */
const char *storage_strerror(int status);

#endif