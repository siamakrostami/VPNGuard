#include "CProcessLifecycle.h"
#include <errno.h>
#include <libproc.h>
#include <signal.h>
#include <unistd.h>

int vpg_process_identity_read(int32_t pid, vpg_process_identity *out) {
    if (pid <= 1 || !out) { errno = EINVAL; return -1; }
    struct proc_bsdinfo info = {0};
    errno = 0;
    int count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if (count != sizeof(info)) { if (!errno) errno = ESRCH; return -1; }
    if (info.pbi_uid != geteuid() || info.pbi_ruid != getuid()) { errno = EPERM; return -1; }
    *out = (vpg_process_identity){pid, info.pbi_start_tvsec, info.pbi_start_tvusec};
    return 0;
}

int vpg_signal_identity(vpg_process_identity identity, int signal_number, int group) {
    if (signal_number < 0 || signal_number >= NSIG || (group != 0 && group != 1)) { errno = EINVAL; return -1; }
    vpg_process_identity current;
    if (vpg_process_identity_read(identity.pid, &current) < 0) return -1;
    if (current.seconds != identity.seconds || current.microseconds != identity.microseconds) { errno = ESRCH; return -1; }
    if (group && getpgid(identity.pid) != identity.pid) { errno = EPERM; return -1; }
    return kill(group ? -identity.pid : identity.pid, signal_number);
}
