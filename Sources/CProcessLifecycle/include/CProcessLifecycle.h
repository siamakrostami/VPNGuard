#ifndef VPG_PROCESS_LIFECYCLE_H
#define VPG_PROCESS_LIFECYCLE_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct vpg_process_identity {
    int32_t pid;
    uint64_t seconds;
    uint64_t microseconds;
} vpg_process_identity;

/* Return 0 on success, -1 with errno on failure. Only the caller's own real
 * and effective UID are accepted. The start time guards against stale PIDs.
 * macOS may withhold BSD information for zombies; those fail closed. */
int vpg_process_identity_read(int32_t pid, vpg_process_identity *out);
/* group requires pid to remain a process-group leader. The host reserves its
 * child's identity by keeping the leader unreaped until group cleanup ends.
 * General callers must supply their own lifetime/ownership synchronization.
 * This is not an atomic kernel PID handle: callers must not use group signalling
 * for arbitrary journal records or reap the leader before group cleanup.
 * Supervision covers members of the child's process group, not a malicious
 * setsid()/setpgid() escape, unrelated services, or SIGKILL of the supervisor. */
int vpg_signal_identity(vpg_process_identity identity, int signal_number, int group);

#ifdef __cplusplus
}
#endif
#endif
