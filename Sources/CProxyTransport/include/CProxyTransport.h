#ifndef CPROXYTRANSPORT_H
#define CPROXYTRANSPORT_H
#include <stddef.h>
typedef struct vpg_channel vpg_channel;
vpg_channel *vpg_connect(const char *proxy, const char *target, const char *user, const char *password, int *error);
int vpg_descriptor(vpg_channel *channel);
int vpg_send(vpg_channel *channel, const void *bytes, size_t count);
int vpg_receive(vpg_channel *channel, void *bytes, size_t count);
void vpg_close(vpg_channel *channel);
int vpg_trace(const char *proxy, const char *user, const char *password, char **output);
void vpg_free(void *pointer);
#endif
