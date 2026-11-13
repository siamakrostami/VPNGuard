#include <CProcessLifecycle.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
static volatile sig_atomic_t interrupted;
static void request_stop(int number) { interrupted = number; }
static double monotonic_time(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1000000000.0;
}
static void pause_briefly(void) {
    struct timespec delay = {0, 20000000}; nanosleep(&delay, NULL);
}
static int parse_number(const char *text, int *value) {
    char *end; errno = 0; long number = strtol(text, &end, 10);
    if (errno || !*text || *end || number < -1 || number > INT_MAX) return -1;
    *value = (int)number; return 0;
}
static int write_all(int fd, const char *bytes, size_t count) {
    while (count) {
        ssize_t n = write(fd, bytes, count);
        if (n < 0 && errno == EINTR && !interrupted) continue;
        if (n <= 0) return -1;
        bytes += n; count -= (size_t)n;
    }
    return 0;
}
/* A zombie leader is deliberately retained to reserve the process-group ID.
 * Enumerate all members, including descendants, without treating that retained
 * zombie as a live process. On an inspection error keep waiting, then kill. */
static int group_has_live_members(pid_t group) {
    int size = proc_listpids(PROC_PGRP_ONLY, (uint32_t)group, NULL, 0);
    if (size <= 0) return 1;
    if (size > 16 * 1024 * 1024) return 1;
    int capacity = size + 64 * (int)sizeof(pid_t);
    pid_t *pids = calloc(1, (size_t)capacity);
    if (!pids) return 1;
    int count = proc_listpids(PROC_PGRP_ONLY, (uint32_t)group, pids, capacity);
    if (count < 0 || count >= capacity) { free(pids); return 1; }
    int live = 0;
    for (int i = 0; i < count / (int)sizeof(pid_t); i++) {
        if (pids[i] <= 0) continue;
        struct proc_bsdinfo info = {0};
        int length = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &info, sizeof(info));
        if (pids[i] == group && length != sizeof(info)) {
            siginfo_t dead_leader = {0};
            if (waitid(P_PID, (id_t)group, &dead_leader, WEXITED | WNOHANG | WNOWAIT) == 0 && dead_leader.si_pid == group) continue;
        }
        if (length == sizeof(info) && info.pbi_pgid == group && info.pbi_status != SZOMB) { live = 1; break; }
        if (length != sizeof(info) && kill(pids[i], 0) == 0) { live = 1; break; }
    }
    free(pids); return live;
}

/* proc_pidinfo does not expose an exited zombie's BSD info on macOS. A host
 * still owns its unreaped leader, so WNOWAIT proves its reserved identity even
 * when the general cookie-based API correctly refuses that zombie. This
 * fallback must never be used for a PID loaded from a journal. */
static void signal_owned_group(pid_t child, vpg_process_identity identity, int identified, int number) {
    if (identified && vpg_signal_identity(identity, number, 1) == 0) return;
    siginfo_t owned = {0};
    int result;
    do { result = waitid(P_PID, (id_t)child, &owned, WEXITED | WNOHANG | WNOWAIT); } while (result < 0 && errno == EINTR);
    if (result == 0) kill(-child, number);
}

int main(int argc, char **argv) {
    int control = -1, status = -1, foreground = -1, command = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--")) { command = i + 1; break; }
        if (i + 1 >= argc) return 125;
        int *destination = !strcmp(argv[i], "--control-fd") ? &control :
            !strcmp(argv[i], "--status-fd") ? &status :
            !strcmp(argv[i], "--foreground-group") ? &foreground : NULL;
        if (!destination || parse_number(argv[++i], destination) < 0) return 125;
    }
    if (control < 3 || status < 3 || control == status || !command || command >= argc || argv[command][0] != '/' || foreground == 0 || foreground == 1 || geteuid() != getuid()) return 125;
    if (fcntl(control, F_GETFD) < 0 || fcntl(status, F_GETFD) < 0) return 125;
    fcntl(control, F_SETFD, FD_CLOEXEC); fcntl(status, F_SETFD, FD_CLOEXEC);
    struct sigaction action = {0}; action.sa_handler = request_stop; sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL); sigaction(SIGHUP, &action, NULL); sigaction(SIGINT, &action, NULL);
    struct sigaction ignore = {0}; ignore.sa_handler = SIG_IGN; sigemptyset(&ignore.sa_mask);
    sigaction(SIGPIPE, &ignore, NULL); sigaction(SIGTTOU, &ignore, NULL);
    /* waitid(WNOWAIT) is essential: an inherited SIGCHLD=SIG_IGN would reap the
     * leader automatically and make the numeric group identity unsafe. */
    struct sigaction standard = {0}; standard.sa_handler = SIG_DFL; sigemptyset(&standard.sa_mask);
    sigaction(SIGCHLD, &standard, NULL);
    sigset_t empty; sigemptyset(&empty); sigprocmask(SIG_SETMASK, &empty, NULL);

    /* Pure C and single-threaded: fork is safe here. The child never runs
     * Swift/Foundation or allocates before exec. Its ordinary pipe read makes
     * host death an EOF, rather than leaving a suspended child behind. */
    int gate[2];
    if (pipe(gate) < 0) { close(status); close(control); return 125; }
    /* Keep both ends above stdio even if a caller has closed stdin/stdout.
     * Otherwise the child might retain its own gate writer as fd 0/1/2 and
     * never observe EOF when the host dies before opening the gate. */
    int gate_read = fcntl(gate[0], F_DUPFD_CLOEXEC, 5);
    int gate_write = fcntl(gate[1], F_DUPFD_CLOEXEC, 5);
    close(gate[0]); close(gate[1]);
    if (gate_read < 0 || gate_write < 0) {
        if (gate_read >= 0) close(gate_read);
        if (gate_write >= 0) close(gate_write);
        close(status); close(control); return 125;
    }
    gate[0] = gate_read; gate[1] = gate_write;
    int descriptor_limit = getdtablesize();
    pid_t child = fork();
    if (child < 0) { close(gate[0]); close(gate[1]); close(status); close(control); return 125; }
    if (child == 0) {
        if (setpgid(0, 0) < 0) _exit(125);
        /* Reset every catchable signal, including ignored dispositions inherited
         * from a shell. All calls in this branch are async-signal-safe. */
        for (int number = 1; number < NSIG; number++) {
            if (number != SIGKILL && number != SIGSTOP) sigaction(number, &standard, NULL);
        }
        sigprocmask(SIG_SETMASK, &empty, NULL);
        for (int fd = 3; fd < descriptor_limit; fd++) {
            if (fd != gate[0]) close(fd);
        }
        char start = 0; ssize_t count;
        do { count = read(gate[0], &start, 1); } while (count < 0 && errno == EINTR);
        close(gate[0]);
        if (count != 1 || start != 'G') _exit(125);
        execve(argv[command], &argv[command], environ);
        _exit(errno == ENOENT ? 127 : 126);
    }
    close(gate[0]);
    /* The child also sets its own group; setting it here closes the scheduling
     * race before identity validation and terminal ownership checks. */
    if (setpgid(child, child) < 0) {
        close(gate[1]); close(status); close(control);
        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
        return 125;
    }

    vpg_process_identity child_identity = {0}, host_identity = {0};
    int identified = vpg_process_identity_read(child, &child_identity) == 0 && vpg_process_identity_read(getpid(), &host_identity) == 0;
    int handed_over = 0;
    if (identified && foreground >= 0 && tcgetpgrp(STDIN_FILENO) == foreground) {
        handed_over = tcsetpgrp(STDIN_FILENO, child) == 0;
    }
    int reported = 0;
    if (identified) {
        char report[512];
        int length = snprintf(report, sizeof(report), "{\"childIdentity\":{\"pid\":%d,\"seconds\":%llu,\"microseconds\":%llu},\"hostIdentity\":{\"pid\":%d,\"seconds\":%llu,\"microseconds\":%llu}}\n", child_identity.pid, (unsigned long long)child_identity.seconds, (unsigned long long)child_identity.microseconds, host_identity.pid, (unsigned long long)host_identity.seconds, (unsigned long long)host_identity.microseconds);
        reported = length > 0 && length < sizeof(report) && write_all(status, report, (size_t)length) == 0;
    }
    close(status);
    if (reported && !interrupted) {
        const char start = 'G';
        if (write_all(gate[1], &start, 1) < 0) reported = 0;
    }
    close(gate[1]);
    int natural_exit = 0;
    if (reported) {
        while (!interrupted) {
            siginfo_t information = {0};
            if (waitid(P_PID, (id_t)child, &information, WEXITED | WSTOPPED | WNOHANG | WNOWAIT) < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (information.si_pid == child) {
                natural_exit = information.si_code == CLD_EXITED || information.si_code == CLD_KILLED || information.si_code == CLD_DUMPED;
                break;
            }
            struct pollfd watch = {control, POLLIN | POLLHUP | POLLERR, 0};
            int ready = poll(&watch, 1, 100);
            if (ready < 0) { if (errno == EINTR) continue; break; }
            if (ready > 0) {
                if (watch.revents & (POLLHUP | POLLERR | POLLNVAL)) break;
                if (watch.revents & POLLIN) {
                    char bytes[64]; ssize_t count = read(control, bytes, sizeof(bytes));
                    /* The control channel is a lifetime lease, not a command
                     * protocol. Any input or EOF requests shutdown. */
                    if (count >= 0 || errno != EINTR) break;
                }
            }
        }
    }
    close(control);
    /* The leader is still our unreaped child here, even on identity lookup
     * failure. That ownership reserves its PID, allowing this local fallback. */
    signal_owned_group(child, child_identity, identified, SIGCONT);
    signal_owned_group(child, child_identity, identified, SIGTERM);
    double deadline = monotonic_time() + 5.0;
    while (monotonic_time() < deadline && group_has_live_members(child)) pause_briefly();
    /* Final group-wide KILL is harmless for zombies and closes the last
     * enumeration race before releasing the reserved leader identity. */
    signal_owned_group(child, child_identity, identified, SIGKILL);
    if (handed_over && tcgetpgrp(STDIN_FILENO) == child) tcsetpgrp(STDIN_FILENO, foreground);
    int child_status = 0;
    while (waitpid(child, &child_status, 0) < 0) { if (errno != EINTR) return 125; }
    if (!natural_exit) return 125;
    if (WIFEXITED(child_status)) return WEXITSTATUS(child_status);
    if (WIFSIGNALED(child_status)) return 128 + WTERMSIG(child_status);
    return 125;
}
