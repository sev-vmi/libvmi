#ifndef TLS_PRIVATE_H
#define TLS_PRIVATE_H

#include <stdint.h>
#include <stdbool.h>
#include <openssl/bio.h>

#include "private.h"
#include "messages.pb-c.h"

#define TLS_MAX_MSG_SIZE 8192 // max number of bytes we can get at once 

//#define TLS_DEBUG_COUNTER 1
#undef TLS_DEBUG_COUNTER

#ifdef TLS_DEBUG_COUNTER
extern unsigned int dbg_send_counter;
extern unsigned int dbg_recv_counter;
#endif

// event-specific struct
typedef struct tls_event_pf 
{
    MsgProto__MemAccessType access_type;
    uint64_t vcpu;
    uint64_t fault_gpa;
    uint64_t fault_gva;
} tls_event_pf_t;

// queue that holds events
typedef struct tls_event 
{
    void *next;
    struct tls_event_pf event;
} tls_event_t;

typedef struct tls_instance 
{
	char *name;		// ip:port
	char *ip;
	char *port;
	int sockfd;
	BIO *bio;

	struct tls_event *events;
	struct tls_event *event_last;
	unsigned int event_count;
	bool events_initialized;

    status_t (*process_event)(vmi_instance_t vmi, struct tls_event *event);
} tls_instance_t;

static inline
tls_instance_t *tls_get_instance(
	vmi_instance_t vmi)
{
	return ((tls_instance_t *) vmi->driver.driver_data);
}

#endif
