#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>

#define ENTER_ALT_SCREEN "\033[?1049h\033[H"
#define LEAVE_ALT_SCREEN "\033[2J\033[H\033[?1049l"

static void restore_screen_and_exit(int sig)
{
  (void) sig;
  (void) !write(STDOUT_FILENO, LEAVE_ALT_SCREEN, sizeof LEAVE_ALT_SCREEN - 1);
  _exit(130);
}

void show_secret_temporarily(const char *secret, unsigned secs)
{
  if (!isatty(STDOUT_FILENO)) {
    printf("Cannot display the password: output is not a terminal.\n");
    return;
  }

  struct sigaction sa = {0}, old_int, old_term;
  sa.sa_handler = restore_screen_and_exit;
  sigaction(SIGINT, &sa, &old_int);
  sigaction(SIGTERM, &sa, &old_term);

  printf(ENTER_ALT_SCREEN);
  printf("Password:\n\n  %s\n\n", secret);

  for (unsigned left = secs; left > 0; left--)
  {
    printf("\rPress Enter to hide it now (auto-hide in %2u s) ", left);
    fflush(stdout);

    struct pollfd p = { .fd = STDIN_FILENO, .events = POLLIN };
    if (poll(&p, 1, 1000) > 0)
    {
      int c;
      while ((c = getchar()) != '\n' && c != EOF) ;
      clearerr(stdin);
      break;
    }
  }

  printf(LEAVE_ALT_SCREEN);
  fflush(stdout);

  sigaction(SIGINT, &old_int, NULL);
  sigaction(SIGTERM, &old_term, NULL);
}