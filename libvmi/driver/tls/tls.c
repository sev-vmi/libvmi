#include <stdint.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "private.h"
#include "glib_compat.h"
#include "driver/driver_wrapper.h"
#include "driver/memory_cache.h"
#include "driver/tls/tls.h"
#include "driver/tls/tls_private.h"
#include "driver/tls/tls_events.h"
#include "driver/tls/messages.pb-c.h"
#include "driver/tls/handle_pb_msg.h"

#ifdef TLS_DEBUG_COUNTER
#include "driver/tls/tls_private.h"
unsigned int dbg_send_counter = 0;
unsigned int dbg_recv_counter = 0;
#endif

//-------------------------------------------------
// Helper Functions

status_t 
get_register(
    reg_t reg, 
    MsgProto__RegisterID *msg_proto_reg) 
{
    switch (reg) {
        case RAX:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__RAX;
            break;
        case RBX:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__RBX;
            break;
        case RCX:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__RCX;
            break;
        case RDX:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__RDX;
            break;
        case RBP:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__RBP;
            break;
        case RSI:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__RSI;
            break;
        case RDI:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__RDI;
            break;
        case RSP:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__RSP;
            break;
        case RIP:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__RIP;
            break;
        case RFLAGS:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__RFLAGS;
            break;
        case R8:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__R8;
            break;
        case R9:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__R9;
            break;
        case R10:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__R10;
            break;
        case R11:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__R11;
            break;
        case R12:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__R12;
            break;
        case R13:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__R13;
            break;
        case R14:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__R14;
            break;
        case R15:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__R15;
            break;
        case CR0:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__CR0;
            break;
        case CR2:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__CR2;
            break;
        case CR3:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__CR3;
            break;
        case CR4:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__CR4;
            break;
        case XCR0:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__XCR0;
            break;
        case DR0:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__DR0;
            break;
        case DR1:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__DR1;
            break;
        case DR2:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__DR2;
            break;
        case DR3:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__DR3;
            break;
        case DR6:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__DR6;
            break;
        case DR7:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__DR7;
            break;
        case CS_SEL:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__CS_SEL;
            break;
        case DS_SEL:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__DS_SEL;
            break;
        case ES_SEL:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__ES_SEL;
            break;
        case FS_SEL:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__FS_SEL;
            break;
        case GS_SEL:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__GS_SEL;
            break;
        case SS_SEL:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__SS_SEL;
            break;
        case TR_SEL:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__TR_SEL;
            break;
        case LDTR_SEL:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__LDTR_SEL;
            break;
        case CS_LIMIT:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__CS_LIMIT;
            break;
        case DS_LIMIT:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__DS_LIMIT;
            break;
        case ES_LIMIT:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__ES_LIMIT;
            break;
        case FS_LIMIT:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__FS_LIMIT;
            break;
        case GS_LIMIT:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__GS_LIMIT;
            break;
        case SS_LIMIT:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__SS_LIMIT;
            break;
        case TR_LIMIT:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__TR_LIMIT;
            break;
        case LDTR_LIMIT:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__LDTR_LIMIT;
            break;
        case IDTR_LIMIT:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__IDTR_LIMIT;
            break;
        case GDTR_LIMIT:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__GDTR_LIMIT;
            break;
        case CS_BASE:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__CS_BASE;
            break;
        case DS_BASE:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__DS_BASE;
            break;
        case ES_BASE:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__ES_BASE;
            break;
        case FS_BASE:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__FS_BASE;
            break;
        case GS_BASE:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__GS_BASE;
            break;
        case SS_BASE:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__SS_BASE;
            break;
        case TR_BASE:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__TR_BASE;
            break;
        case LDTR_BASE:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__LDTR_BASE;
            break;
        case IDTR_BASE:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__IDTR_BASE;
            break;
        case GDTR_BASE:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__GDTR_BASE;
            break;
        case SYSENTER_CS:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__SYSENTER_CS;
            break;
        case SYSENTER_ESP:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__SYSENTER_ESP;
            break;
        case SYSENTER_EIP:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__SYSENTER_EIP;
            break;
        case MSR_EFER:
            *msg_proto_reg = MSG_PROTO__REGISTER_ID__MSR_EFER;
            break;
        default:
            errprint("--Reading register %"PRIu64" not implemented\n", reg);
            return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}


// Internal for attestation report query
static void *tls_request_report(tls_instance_t *tls)
{
    send_attest_report_req(tls);
    return recv_attest_report_reply(tls);
}


//-------------------------------------------------
// TLS-Specific Interface Functions (no direct mapping to driver_*)

void *
tls_get_memory(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t UNUSED(length))
{
    tls_instance_t *tls = tls_get_instance(vmi);

    send_page_read_req(tls, paddr >> vmi->page_shift);

    return recv_page_read_reply(tls);
}

void 
tls_release_memory(
    vmi_instance_t UNUSED(vmi),
    void *memory,
    size_t UNUSED(length))
{
    if(memory) {
        free(memory); 
    }
}


//-------------------------------------------------
// General Interface Functions (1-1 mapping to driver_* function)

status_t 
tls_init(
    vmi_instance_t vmi,
    uint32_t UNUSED(init_flags),
    vmi_init_data_t *UNUSED(init_data))
{
    tls_instance_t *tls = g_try_malloc0(sizeof(tls_instance_t));

    if (!tls)
        return VMI_FAILURE;

    vmi->driver.driver_data = (void *)tls;

    dbprint(VMI_DEBUG_DRIVER, "finished tls_init\n");

    return VMI_SUCCESS;
}

status_t 
tls_init_vmi(
    vmi_instance_t vmi,
    uint32_t init_flags,
    vmi_init_data_t* UNUSED(init_data))
{
    tls_instance_t *tls = tls_get_instance(vmi);
    int ret;

#ifdef ENABLE_TLS
    SSL_load_error_strings();
    ERR_load_crypto_strings();

    OpenSSL_add_all_algorithms();
    SSL_library_init();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    assert(ctx != NULL);

    tls->bio = BIO_new_ssl_connect(ctx);
    assert(tls->bio != NULL);

    SSL *ssl;
    BIO_get_ssl(tls->bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    char hostname[255];
    ret = snprintf(hostname, sizeof(hostname), "%s:%s", tls->ip, tls->port);
    assert(ret > 0);
    BIO_set_conn_hostname(tls->bio, hostname);

    dbprint(VMI_DEBUG_DRIVER, "try to connect to agent\n");

    if (BIO_do_connect(tls->bio) <= 0) {
        BIO_free_all(tls->bio);
        tls->bio = NULL;
        errprint("client failed to connect\n");
        ERR_print_errors_fp(stderr);
        return VMI_FAILURE;
    }
#else
    struct addrinfo hints, *servinfo, *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    dbprint(VMI_DEBUG_DRIVER, "try to resolve address of agent\n");

    if ((ret = getaddrinfo(tls->ip, tls->port, &hints, &servinfo)) != 0) {
        errprint("getaddrinfo: %s\n", gai_strerror(ret));
        return VMI_FAILURE;
    }

    dbprint(VMI_DEBUG_DRIVER, "try to connect to agent\n");

    // loop through all the results and connect to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((tls->sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            continue;
        }

        if (connect(tls->sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(tls->sockfd);
            tls->sockfd = -1; // 0;
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        errprint("client failed to connect\n");
        return VMI_FAILURE;
    }

    freeaddrinfo(servinfo);
#endif

    dbprint(VMI_DEBUG_DRIVER, "successful connect to agent\n");

    /* Check Attestation (TODO: incorporate into x509 certificate instead)*/
    struct SevSnpAttestationReport *attest_report = tls_request_report(tls);

    if (!attest_report) {
        errprint("Failed querying attestation report\n");
        // TODO: shut down
    } else {
        dbprint(VMI_DEBUG_DRIVER, "successfully queried attestation report\n");

/*
        // TODO: check valid report, vmpl == 0, attestation report == server public key
        dbprint(VMI_DEBUG_DRIVER, "report vmpl: %u, report_data (user data): ", attest_report->vmpl);
        for (unsigned int i=0; i < sizeof(attest_report->report_data); i++) {
            dbprint(VMI_DEBUG_DRIVER, "%#x,\n", attest_report->report_data[i]);
        }
        errprint("\n");
 */

        free(attest_report);
    }

    // ---

    memory_cache_init(vmi, tls_get_memory, tls_release_memory, 1);

    vmi->num_vcpus = 4; // TODO placeholder

    vmi->vm_type = NORMAL; // TODO: could add SEV(-SNP) type
    
    if(init_flags & VMI_INIT_EVENTS) {
        if(VMI_FAILURE == tls_events_init(vmi))
            return VMI_FAILURE;
        tls->events_initialized = true;
    } 

    return VMI_SUCCESS;
}

void tls_destroy(vmi_instance_t vmi)
{
    tls_instance_t *tls = tls_get_instance(vmi);

    if(tls->events_initialized) tls_events_destroy(vmi);

    if (tls)
    {
#ifdef ENABLE_TLS   
        if(tls->bio != NULL) BIO_free_all(tls->bio);
#else
        if(tls->sockfd >= 0) close(tls->sockfd);
//        if(tls->sockfd != 0) close(tls->sockfd);
#endif
        g_free(tls);
        vmi->driver.driver_data = NULL;
    }

#ifdef TLS_DEBUG_COUNTER
    dbprint(VMI_DEBUG_DRIVER, "#send: %u, #recv: %u\n", dbg_send_counter, dbg_recv_counter);
#endif
}

status_t tls_get_name(vmi_instance_t vmi, char **name)
{
    *name = strndup(tls_get_instance(vmi)->ip, 300); // TODO: should be `->name`

    dbprint(VMI_DEBUG_DRIVER, "tls_get_name extracted: %s\n", *name);

    return VMI_SUCCESS;
}

void tls_set_name(vmi_instance_t vmi, const char *name)
{
    dbprint(VMI_DEBUG_DRIVER, "tls_set_name called with: %s\n", name);

    tls_get_instance(vmi)->name = strndup(name, 300);

    // assume that name has correct format, i.e ip:port
    char *copy = strndup(name, 300);

    // get the ip addr
    tls_get_instance(vmi)->ip = strtok(copy, ":");

    // get port and convert to number
    tls_get_instance(vmi)->port = strtok(NULL, ":");

    dbprint(VMI_DEBUG_DRIVER, "name: %s\n", tls_get_instance(vmi)->name);
    dbprint(VMI_DEBUG_DRIVER, "ip: %s\n", tls_get_instance(vmi)->ip);
    dbprint(VMI_DEBUG_DRIVER, "port: %s\n", tls_get_instance(vmi)->port);
}

status_t 
tls_get_memsize(
    vmi_instance_t vmi,
    uint64_t *allocated_ram_size,
    addr_t *maximum_physical_address)
{
#ifdef ENABLE_SAFETY_CHECKS
    if(!allocated_ram_size || !maximum_physical_address)
        return VMI_FAILURE;
#endif
    tls_instance_t *tls = tls_get_instance(vmi);
    *allocated_ram_size = 0x100000000; // 4 GB

    send_mem_boundary_req(tls);

    return recv_mem_boundary_reply(tls, maximum_physical_address);
}

status_t 
tls_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu)
{
    if (!value)
    {
        errprint("%s: value is invalid\n", __func__);
        return VMI_FAILURE;
    }

    MsgProto__RegisterID msg_proto_reg;
    tls_instance_t *tls = tls_get_instance(vmi);

    if(VMI_FAILURE == get_register(reg, &msg_proto_reg)) return VMI_FAILURE;

    send_register_read_req(tls, msg_proto_reg, vcpu);

    return recv_register_read_reply(tls, value);
}

// only gets x86 registers and only the ones defined in messages.proto
status_t 
tls_get_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu)
{
    status_t status = VMI_FAILURE;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.rax, RAX, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.rbx, RBX, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.rcx, RCX, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.rdx, RDX, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.rbp, RBP, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.rsi, RSI, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.rdi, RDI, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.rsp, RSP, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.rip, RIP, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.rflags, RFLAGS, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.dr6, DR6, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.dr7, DR7, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.r8, R8, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.r9, R9, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.r10, R10, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.r11, R11, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.r12, R12, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.r13, R13, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.r14, R14, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.r15, R15, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.cr0, CR0, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.cr2, CR2, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.cr3, CR3, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.cr4, CR4, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.sysenter_cs, SYSENTER_CS, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.sysenter_esp, SYSENTER_ESP, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.sysenter_eip, SYSENTER_EIP, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.fs_base, FS_BASE, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.fs_limit, FS_LIMIT, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.fs_sel, FS_SEL, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.gs_base, GS_BASE, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.gs_limit, GS_LIMIT, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.gs_sel, GS_SEL, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.cs_base, CS_BASE, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.cs_limit, CS_LIMIT, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.cs_sel, CS_SEL, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.ss_base, SS_BASE, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.ss_limit, SS_LIMIT, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.ss_sel, SS_SEL, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.ds_base, DS_BASE, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.ds_limit, DS_LIMIT, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.ds_sel, DS_SEL, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.es_base, ES_BASE, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.es_limit, ES_LIMIT, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.es_sel, ES_SEL, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.idtr_base, IDTR_BASE, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.idtr_limit, IDTR_LIMIT, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.gdtr_base, GDTR_BASE, vcpu)) return status;
    if(VMI_FAILURE == tls_get_vcpureg(vmi, &regs->x86.gdtr_limit, GDTR_LIMIT, vcpu)) return status;

    return VMI_SUCCESS;
}

status_t 
tls_set_vcpureg(
    vmi_instance_t vmi,
    uint64_t value,
    reg_t reg,
    unsigned long vcpu)
{
    tls_instance_t *tls = tls_get_instance(vmi);

    MsgProto__RegisterID msg_proto_reg;

    if(VMI_FAILURE == get_register(reg, &msg_proto_reg)) return VMI_FAILURE;

    send_register_write_req(tls, value, msg_proto_reg, vcpu);

    return recv_register_write_reply(tls);
}

// only set x86 registers and only the ones defined in messages.proto
status_t 
tls_set_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu)
{
    status_t status = VMI_FAILURE;

    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.rax, RAX, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.rbx, RBX, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.rcx, RCX, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.rdx, RDX, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.rbp, RBP, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.rsi, RSI, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.rdi, RDI, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.rsp, RSP, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.rip, RIP, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.rflags, RFLAGS, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.dr6, DR6, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.dr7, DR7, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.r8, R8, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.r9, R9, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.r10, R10, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.r11, R11, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.r12, R12, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.r13, R13, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.r14, R14, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.r15, R15, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.cr0, CR0, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.cr2, CR2, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.cr3, CR3, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.cr4, CR4, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.sysenter_cs, SYSENTER_CS, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.sysenter_esp, SYSENTER_ESP, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.sysenter_eip, SYSENTER_EIP, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.fs_base, FS_BASE, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.fs_limit, FS_LIMIT, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.fs_sel, FS_SEL, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.gs_base, GS_BASE, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.gs_limit, GS_LIMIT, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.gs_sel, GS_SEL, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.cs_base, CS_BASE, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.cs_limit, CS_LIMIT, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.cs_sel, CS_SEL, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.ss_base, SS_BASE, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.ss_limit, SS_LIMIT, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.ss_sel, SS_SEL, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.ds_base, DS_BASE, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.ds_limit, DS_LIMIT, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.ds_sel, DS_SEL, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.es_base, ES_BASE, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.es_limit, ES_LIMIT, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.es_sel, ES_SEL, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.idtr_base, IDTR_BASE, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.idtr_limit, IDTR_LIMIT, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.gdtr_base, GDTR_BASE, vcpu)) return status;
    if(VMI_FAILURE == tls_set_vcpureg(vmi, regs->x86.gdtr_limit, GDTR_LIMIT, vcpu)) return status;

    return VMI_SUCCESS;
}

void *tls_read_page(vmi_instance_t vmi, addr_t page)
{
    addr_t paddr = page << vmi->page_shift;
    
    return memory_cache_insert(vmi, paddr);
}

status_t 
tls_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length)
{
    tls_instance_t *tls = tls_get_instance(vmi);

    send_page_write_req(tls, paddr, buf, length);
    return recv_page_write_reply(tls);
}

int tls_is_pv(vmi_instance_t UNUSED(vmi))
{
    return 0;
}

status_t tls_pause_vm(vmi_instance_t vmi)
{
    tls_instance_t *tls = tls_get_instance(vmi);

    send_pause_req(tls);

    return recv_pause_reply(tls);
}

status_t tls_resume_vm(vmi_instance_t vmi)
{
    tls_instance_t *tls = tls_get_instance(vmi);

    send_resume_req(tls);

    return recv_resume_reply(tls);
}

status_t
tls_test(
    uint64_t UNUSED(domainid),
    const char* UNUSED(name),
    uint64_t UNUSED(init_flags),
    vmi_init_data_t* UNUSED(init_data))
{
    return VMI_SUCCESS;
}
