// commands/commands.h
#ifndef COMMANDS_H
#define COMMANDS_H
#include "../vault/entry.h"
#include "../vault/vault.h"

int ask_yes_no(const char *what);
int ask_length(void);
int ask_name(entry_t *entry);
int ask_notes(entry_t *entry);
int ask_password(entry_t *entry);
int generate_command(entry_t *out);
int add_command(entry_t *out);
void cmd_show(const vault_t *v);

#endif
