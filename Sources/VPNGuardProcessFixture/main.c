/* Harmless process-lifecycle fixture. Not packaged with the application. */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "fds-closed")) {
        return fcntl(3, F_GETFD) == -1 && errno == EBADF && fcntl(4, F_GETFD) == -1 && errno == EBADF ? 0 : 3;
    }
    if (!strcmp(argv[1], "ignore-term")) {
        signal(SIGTERM, SIG_IGN);
        if (argc > 2) { FILE *file = fopen(argv[2], "w"); if (!file) return 4; fprintf(file, "%d\n", getpid()); fclose(file); }
        for (;;) pause();
    }
    if (!strcmp(argv[1], "descendant") && argc > 2) {
        int ready[2]; if (pipe(ready)) return 4;
        pid_t child = fork(); if (child < 0) return 5;
        if (child == 0) {
            close(ready[0]); signal(SIGTERM, SIG_IGN);
            FILE *file = fopen(argv[2], "w"); if (!file) _exit(6);
            fprintf(file, "%d\n", getpid()); fclose(file);
            write(ready[1], "r", 1); close(ready[1]);
            for (;;) pause();
        }
        close(ready[1]); char byte; if (read(ready[0], &byte, 1) != 1) return 7;
        close(ready[0]); usleep(100000); return 0;
    }
    return 2;
}
