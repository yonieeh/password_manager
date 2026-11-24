#ifndef SESSION_H
#define SESSION_H

/*
 * Flujos interactivos alrededor de storage: primer uso, desbloqueo, recovery key,
 * cambio de master y guardado. Todo lo que tiene que ver con pedirle cosas al
 * usuario vive acá, para que storage siga siendo una librería sin terminal.
 */

#include "storage/storage.h"
#include "vault/vault.h"

/*
 * Si `path` no existe: crea un vault nuevo (pide master con confirmación y muestra
 * la recovery key una sola vez). Si existe: pide la master (3 intentos; Enter vacío
 * = usar la recovery key, y en ese caso obliga a elegir una master nueva).
 *
 * Retorna 0 y deja *s y *vault listos. Retorna -1 si el usuario cancela (Ctrl-D),
 * agota los intentos o hay un error; en ese caso no hay nada que liberar.
 * *vault se pisa: no hace falta inicializarlo.
 */
int session_start(const char *path, storage_t **s, vault_t *vault);

/* Comando "passwd": pide la master nueva (con confirmación), rota las claves,
 * guarda y muestra la recovery key nueva. Retorna 0 si se cambió. */
int session_change_master(storage_t *s, const vault_t *vault);

/* Guarda el vault. Si falla, avisa al usuario por pantalla. Retorna 0 si guardó. */
int session_save(storage_t *s, const vault_t *vault);

/*
 * Espera hasta `timeout_secs` a que el usuario escriba algo en la terminal.
 * Retorna 1 si hay input (o si no hay terminal, o timeout_secs es 0), 0 si pasó el
 * tiempo sin actividad. Se llama justo antes de leer el comando del prompt principal.
 */
int session_wait_for_input(unsigned timeout_secs);

/*
 * Bloquea: borra el vault y la vault_key de memoria, limpia la pantalla y vuelve a
 * pedir la master (o la recovery key). Retorna 0 con *s y *vault listos otra vez, o
 * -1 si el usuario no logra desbloquear (en ese caso ya no hay nada que liberar).
 */
int session_relock(const char *path, storage_t **s, vault_t *vault);

#endif