#ifndef PROMPT_H
#define PROMPT_H

/*
 * Lectura de líneas completas del usuario (con espacios), con un prompt.
 * Lo usan session y los comandos de edición. Devuelven memoria del heap que el
 * que llama debe liberar (prompt_free si es un secreto).
 */

/* Muestra el prompt y lee una línea visible. NULL en EOF (Ctrl-D) o error. */
char *prompt_line(const char *prompt);

/* Igual, pero sin mostrar lo que se escribe (contraseñas). */
char *prompt_hidden(const char *prompt);

/* Borra el contenido del string y lo libera. Acepta NULL. */
void prompt_free(char *s);

#endif