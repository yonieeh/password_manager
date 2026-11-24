#ifndef EDIT_COMMANDS_H
#define EDIT_COMMANDS_H

#include "storage/storage.h"
#include "vault/vault.h"

/*
 * "delete": pide el ID, pide confirmación (por defecto NO), borra la entrada y guarda.
 * Retorna 0 si se borró, -1 si se canceló o no existe.
 */
int cmd_delete(vault_t *v, storage_t *s);

/*
 * "edit": pide el ID y luego cada campo; Enter conserva el valor actual.
 * Nada se modifica hasta que se terminó de preguntar: si el usuario cancela
 * (Ctrl-D) a la mitad, la entrada queda intacta. Guarda al terminar.
 * Retorna 0 si se editó (o no había cambios), -1 si se canceló o no existe.
 */
int cmd_edit(vault_t *v, storage_t *s);

#endif