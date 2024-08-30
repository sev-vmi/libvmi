#ifndef TLS_EVENTS_H
#define TLS_EVENTS_H

#include "tls_private.h"

status_t tls_events_init(vmi_instance_t vmi);

void tls_events_destroy(vmi_instance_t vmi);

int tls_push_event(tls_instance_t *tls, MsgProto__MonitorPageEvent *msg);

status_t tls_events_listen(vmi_instance_t vmi, uint32_t timeout);

int tls_are_events_pending(vmi_instance_t vmi);

status_t 
tls_set_mem_access(
    vmi_instance_t vmi,
    addr_t gpfn,
    vmi_mem_access_t page_access_flag,
    uint16_t vmm_pagetable_id);

#endif // TLS_EVENTS_H
