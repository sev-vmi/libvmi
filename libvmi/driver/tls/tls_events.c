#include <glib.h>
#include <stdbool.h>
#include <poll.h>
#include <assert.h>

#include "private.h"
#include "driver/tls/tls.h"
#include "driver/tls/tls_private.h"
#include "driver/tls/tls_events.h"
#include "driver/tls/messages.pb-c.h"
#include "driver/tls/handle_pb_msg.h"

#define MAX_QUEUED_EVENTS 16384

int tls_push_event(tls_instance_t *tls, MsgProto__MonitorPageEvent *msg) 
{
    if(!msg)
        return -1;

    struct tls_event *new_event;
    new_event = calloc(1, sizeof(tls_event_t));
    if(!new_event)
        return -1;

    new_event->next = NULL;
    new_event->event.access_type = msg->access_type;
    new_event->event.vcpu = msg->vcpu;
    new_event->event.fault_gpa = msg->fault_gpa;
    new_event->event.fault_gva = msg->fault_gva;
    if(tls->event_count < MAX_QUEUED_EVENTS) {
        if(tls->event_last)
            tls->event_last->next = new_event;
        else 
            tls->events = new_event;
        
        tls->event_last = new_event;
        tls->event_count++;
    } else {
        free(new_event);
        errno = ENOMEM;
        return -1;
    }

    return 0;
}

static int 
tls_pop_event(
    tls_instance_t *tls, 
    struct tls_event **event) 
{
    *event = tls->events;
    if(*event) {
        tls->events = (*event)->next;

        if( --tls->event_count == 0)
            tls->event_last = NULL;

        (*event)->next = NULL;
    }

    if(*event == NULL) {
        errno = EAGAIN;
        return -1;
    }

    return 0;
}

static status_t
process_cb_response(
    vmi_instance_t vmi, 
    event_response_t response,
    vmi_event_t *libvmi_event,
    struct tls_event *tls_event) 
{
    tls_instance_t *tls = tls_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if(!tls) {
        errprint("%s: invalid tls handle\n", __func__);
        return VMI_FAILURE;
    }
#endif

    dbprint(VMI_DEBUG_DRIVER, "process_cb_response\n");

    uint64_t vcpu = tls_event->event.vcpu;
    assert(vcpu < vmi->num_vcpus);

    // loop over all possible responses
    for(uint32_t i = VMI_EVENT_RESPONSE_NONE+1; i < __VMI_EVENT_RESPONSE_MAX; i++) {
        event_response_t candidate = 1u << i;
        if(candidate == VMI_EVENT_RESPONSE_EMULATE)
            continue;
        if(response & candidate) errprint("%s: TLS - unhandled event response %u\n", __func__, candidate);
    }

    dbprint(VMI_DEBUG_DRIVER, "going to send monitor resume message to agent\n");

    send_monitor_resume_req(tls, libvmi_event->vcpu_id);
    return recv_monitor_resume_reply(tls);
}

static event_response_t 
call_event_callback(
    vmi_instance_t vmi, 
    vmi_event_t *libvmi_event) 
{
    event_response_t response;
    vmi->event_callback = 1;
    dbprint(VMI_DEBUG_DRIVER, "call_event_callback\n");
    response = libvmi_event->callback(vmi, libvmi_event);
    vmi->event_callback = 0;
    return response;
}

static status_t 
process_pagefault(
    vmi_instance_t vmi, 
    struct tls_event *tls_event) 
{
#ifdef ENABLE_SAFETY_CHECKS
    if(!vmi)
        return VMI_FAILURE;
#endif

    dbprint(VMI_DEBUG_DRIVER, "process_pagefault\n");

    // build out_access
    vmi_mem_access_t out_access = VMI_MEMACCESS_INVALID;
    switch (tls_event->event.access_type)
    {
        case MSG_PROTO__MEM_ACCESS_TYPE__READ:
            out_access = VMI_MEMACCESS_R;
            break;
        case MSG_PROTO__MEM_ACCESS_TYPE__WRITE:
            out_access = VMI_MEMACCESS_W;
            break;
        case MSG_PROTO__MEM_ACCESS_TYPE__READ_WRITE:
            out_access = VMI_MEMACCESS_RW;
            break;
        default:
            break;
    }

    vmi_event_t *libvmi_event;
    addr_t gfn = tls_event->event.fault_gpa >> vmi->page_shift;

    dbprint(VMI_DEBUG_DRIVER, "process_pagefault: next doing hash table lookup\n");

    // lookup vmi_event
    //      standard ?
    if(g_hash_table_size(vmi->mem_events_on_gfn)) {
        libvmi_event = g_hash_table_lookup(vmi->mem_events_on_gfn, GSIZE_TO_POINTER(gfn));
        if(libvmi_event && (libvmi_event->mem_event.in_access & out_access)) {
            // fill libvmi_event struct
            x86_registers_t regs = {0};
            libvmi_event->x86_regs = &regs;
            // arch.regs
            // arch.sregs
            libvmi_event->vcpu_id = tls_event->event.vcpu;
            // mem_event
            libvmi_event->mem_event.gfn = gfn;
            libvmi_event->mem_event.out_access = out_access;
            libvmi_event->mem_event.gla = tls_event->event.fault_gva;
            libvmi_event->mem_event.offset = tls_event->event.fault_gpa & VMI_BIT_MASK(0, 11);

            // call user callback
            event_response_t response = call_event_callback(vmi, libvmi_event);
            
            return process_cb_response(vmi, response, libvmi_event, tls_event);
        }
    }

    dbprint(VMI_DEBUG_DRIVER, "process_pagefault: next checking generic memory events\n");

    // generic ?
    if(g_hash_table_size(vmi->mem_events_generic)) {
        dbprint(VMI_DEBUG_DRIVER, "process_pagefault: using vmi->mem_events_generic\n");
        GHashTableIter i;
        vmi_mem_access_t *key = NULL;
        bool cb_issued = 0;

        ghashtable_foreach(vmi->mem_events_generic, i, &key, &libvmi_event) {
            if( GPOINTER_TO_UINT(key) & out_access) {
                // fill libvmi_event struct
                x86_registers_t regs = {0};
                libvmi_event->x86_regs = &regs;
                // arch.regs
                // arch.sregs
                libvmi_event->vcpu_id = tls_event->event.vcpu;
                // mem_event
                libvmi_event->mem_event.gfn = gfn;
                libvmi_event->mem_event.out_access = out_access;
                libvmi_event->mem_event.gla = tls_event->event.fault_gva;
                libvmi_event->mem_event.offset = tls_event->event.fault_gpa & VMI_BIT_MASK(0, 11);

                // call user callback
                event_response_t response = call_event_callback(vmi, libvmi_event);

                if(VMI_FAILURE == process_cb_response(vmi, response, libvmi_event, tls_event))
                    return VMI_FAILURE;
                    
                cb_issued = 1;
            }
        }
        if(cb_issued)
            return VMI_SUCCESS;
    }
    errprint("%s: Caught a memory event that had no handler registered in LibVMI @ GFN 0x%" PRIx64 " (0x%" PRIx64 "), access: %u\n",
            __func__, gfn, (addr_t)tls_event->event.fault_gpa, out_access);
    return VMI_FAILURE;
} 

// TODO: calling poll() on a blocking BIO (esp. SSL BIO) is incompatible, because
//      it might only be control data and then the call blocks;
//      also seems to miss internal data and BIO_pending() variants didn't seem to
//      catch that data reliably;
#ifndef ENABLE_TLS
static int do_wait(tls_instance_t *tls, uint32_t timeout) 
{
    int err;
    struct pollfd pfd[1] = {};

    pfd[0].fd = tls->sockfd;
    pfd[0].events = POLLIN;

    do {
        err = poll(pfd, 1, timeout);
    } while(err < 0 && errno == EINTR);

    if(!err) {
        errno = ETIMEDOUT;
        return -1;
    }

    if(err < 0)
        return -1;
    
    if(pfd[0].revents & POLLHUP) {
        errno = EPIPE;
        return -1;
    }

    return 0;
}
#endif


static int tls_wait_event(tls_instance_t *tls, int timeout) 
{
    int err;

    if(tls->events != NULL)
        return 0;

#ifdef ENABLE_TLS
    // poll does not work well with blocking recv anyway, so temporarily just block directly
    (void)timeout;
    err = recv_agent_push_msg(tls);
#else
    err = do_wait(tls, timeout);

    if(!err)
        err = recv_agent_push_msg(tls);
#endif

    return err;
}

// helper function to wait and pop the next event from the queue
static status_t 
tls_get_next_event(
    tls_instance_t *tls, 
    struct tls_event **event, 
    uint32_t timeout) 
{
    // first check if we can pop from queue (if already enqueued, can avoid 500ms poll)
    if(tls_pop_event(tls, event) == 0) {
        return VMI_SUCCESS;
    }

    // wait next event 
    if(tls_wait_event(tls, timeout)) {
        if(errno == ETIMEDOUT)
            // no events
            return VMI_SUCCESS;

        errprint("%s: tls_wait_event failed: %s\n", __func__, strerror(errno));
        return VMI_FAILURE;
    }

    // pop event from queue
    if(tls_pop_event(tls, event)) {
        errprint("%s: tls_pop_event failed: %s\n", __func__, strerror(errno));
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}

// we currently only support the page fault event
static status_t 
process_single_event(
    vmi_instance_t vmi, 
    struct tls_event **event) 
{
    status_t status = VMI_SUCCESS;
    tls_instance_t *tls = tls_get_instance(vmi);

    dbprint(VMI_DEBUG_DRIVER, "process_single_event\n");

#ifdef ENABLE_SAFETY_CHECKS
    if(!tls->process_event) 
        return VMI_FAILURE;
#endif

    if(!vmi->shutting_down) {
        // call handler
        if(VMI_FAILURE == tls->process_event(vmi, (*event)))
            status = VMI_FAILURE;
    }

    free((*event));
    (*event) = NULL;
    return status;
}

static status_t process_pending_events(vmi_instance_t vmi) 
{
    tls_instance_t *tls = tls_get_instance(vmi);
    struct tls_event *event = NULL;

    dbprint(VMI_DEBUG_DRIVER, "process_pending_events\n");

    while(tls_are_events_pending(vmi) > 0) {
        if(tls_pop_event(tls, &event)) {
            errprint("%s: tls_pop_event failed: %s\n", __func__, strerror(errno));
            return VMI_FAILURE;
        }

        process_single_event(vmi, &event);
    }

    return VMI_SUCCESS;
}

static status_t 
tls_process_events_with_timeout(
    vmi_instance_t vmi, 
    uint32_t timeout) 
{
    tls_instance_t *tls = tls_get_instance(vmi);
    struct tls_event *event = NULL;

    dbprint(VMI_DEBUG_DRIVER, "tls_process_events_with_timeout\n");

    if(VMI_FAILURE == tls_get_next_event(tls, &event, timeout)) {
        errprint("%s: Failed to get next TLS event: %s\n", __func__, strerror(errno));
        return VMI_FAILURE;
    }
    if(!event) return VMI_SUCCESS;

    process_single_event(vmi, &event);

    // make sure that all pending events are processed
    return process_pending_events(vmi);
}

status_t tls_events_listen(vmi_instance_t vmi, uint32_t timeout) 
{
#ifdef ENABLE_SAFETY_CHECKS
    if(!vmi)
        return VMI_FAILURE;
#endif
    return tls_process_events_with_timeout(vmi, timeout);
}

int tls_are_events_pending(vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if(!vmi) {
        errprint("Invalid VMI handle\n");
        return VMI_FAILURE;
    }
#endif
    return tls_get_instance(vmi)->event_count;
}

status_t 
tls_set_mem_access(
    vmi_instance_t vmi,
    addr_t gpfn,
    vmi_mem_access_t page_access_flag,
    uint16_t UNUSED(vmm_pagetable_id))
{
#ifdef ENABLE_SAFETY_CHECKS
    if(!vmi) {
        errprint("%s: invalid vmi handle\n", __func__);
        return VMI_FAILURE;
    }
#endif

    tls_instance_t *tls = tls_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if(!tls) {
        errprint("%s: invalid tls handle\n", __func__);
        return VMI_FAILURE;
    }
#endif

    send_monitor_page_req(tls, gpfn, page_access_flag);

    return recv_monitor_page_reply(tls);
}

status_t tls_events_init(vmi_instance_t vmi) 
{
    tls_instance_t *tls = tls_get_instance(vmi);
#ifdef ENABLE_SAFETY_CHECKS
    if(!tls) {
        errprint("%s: Invalid tls handle\n", __func__);
        return VMI_FAILURE;
    }
#endif

    // bind driver functions
    vmi->driver.set_mem_access_ptr = &tls_set_mem_access;
    vmi->driver.events_listen_ptr = &tls_events_listen;
    vmi->driver.are_events_pending_ptr = &tls_are_events_pending;

    // fill event dispatcher
    tls->process_event = &process_pagefault;
    
    return VMI_SUCCESS;
}

void tls_events_destroy(vmi_instance_t vmi) 
{
    if(VMI_FAILURE == tls_pause_vm(vmi)) 
        errprint("--Failed to pause VM while destroying events\n");

    // clean event queue
    if(tls_are_events_pending(vmi)) {
        if(VMI_FAILURE == tls_events_listen(vmi, 0))
            errprint("--Failed to clean event queue\n");
    }

    tls_get_instance(vmi)->events_initialized = false;

    // resume VM
    if(VMI_FAILURE == tls_resume_vm(vmi))
        errprint("--Failed to resume VM while destroying events\n");
}
