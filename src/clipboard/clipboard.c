// clipboard/clipboard.c
#include "clipboard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
  const char *env;
  const char *bin;
  const char *copy_cmd;
  const char *clear_cmd;
} clip_backend;

static const clip_backend BACKENDS[] = {
#ifdef __APPLE__
    {NULL, "pbcopy", "pbcopy", "printf '' | pbcopy"},
#endif
    {"WAYLAND_DISPLAY", "wl-copy", "wl-copy", "wl-copy --clear"},
    {"DISPLAY", "xclip", "xclip -selection clipboard -in",
     "printf '' | xclip -selection clipboard -in"},
    {"DISPLAY", "xsel", "xsel --clipboard --input",
     "xsel --clipboard --clear"},
    {NULL, "clip.exe", "clip.exe", "printf '' | clip.exe"}, /* WSL */
};

static const clip_backend *find_backend(void)
{
  char probe[64];
  for (size_t i = 0; i < sizeof BACKENDS / sizeof BACKENDS[0]; i++)
  {
    const clip_backend *b = &BACKENDS[i];
    if (b->env && !getenv(b->env))
      continue;
    snprintf(probe, sizeof probe, "command -v %s >/dev/null 2>&1", b->bin);
    if (system(probe) == 0)
      return b;
  }
  return NULL;
}

int clipboard_copy(const char *text, unsigned clear_after_secs)
{
  const clip_backend *b = find_backend();
  if (b == NULL)
    return -1;

  FILE *p = popen(b->copy_cmd, "w");
  if (p == NULL)
    return -1;

  size_t len = strlen(text);
  size_t written = fwrite(text, 1, len, p);
  if (pclose(p) != 0 || written != len)
    return -1;

  char cmd[256];
  int n = snprintf(cmd, sizeof cmd,
                   "(sleep %u; %s) >/dev/null 2>&1 &",
                   clear_after_secs, b->clear_cmd);
  if (n < 0 || (size_t)n >= sizeof cmd)
    return 0;

  system(cmd);
  return 0;
}
