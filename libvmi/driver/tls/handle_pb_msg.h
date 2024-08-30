#ifndef SYSSEC_HANDLE_MSG_H 
#define SYSSEC_HANDLE_MSG_H

#include <stdint.h>

#include "tls_private.h"
#include "driver/tls/messages.pb-c.h"

enum request
{
    PauseReq = 0,
    ResumeReq = 1,
    MemBoundaryReq = 2,
    RegisterReadReq = 3,
    RegisterWriteReq = 4,
    PageReadReq = 5,
    PageWriteReq = 6,
    MonitorPageReq = 7,
    MonitorResumeReq = 8,

    AttestReportReq = 9
};

enum reply
{
    PauseReply = 0,
    ResumeReply = 1,
    MemBoundaryReply = 2,
    RegisterReadReply = 3,
    RegisterWriteReply = 4,
    PageReadReply = 5,
    PageWriteReply = 6,
    MonitorPageReply = 7,
    MonitorResumeReply = 8,
    AgentPush = 9,

    AttestReportReply = 10
};

status_t send_msg(tls_instance_t *tls, enum request req, void *to_send);

//int recv_msg(tls_instance_t *tls, enum reply repl, void *to_save);
status_t recv_msg(tls_instance_t *tls, enum reply repl, MsgProto__AccessReply **msg_out);

status_t send_pause_req(tls_instance_t *tls);

status_t send_resume_req(tls_instance_t *tls);

status_t send_mem_boundary_req(tls_instance_t *tls);

status_t send_register_read_req(tls_instance_t *tls, MsgProto__RegisterID reg, unsigned long vcpu);

status_t send_register_write_req(tls_instance_t *tls, uint64_t value, MsgProto__RegisterID reg, unsigned long vcpu);

status_t send_page_read_req(tls_instance_t *tls, addr_t page);

status_t send_page_write_req(tls_instance_t *tls, addr_t paddr, void *buf, uint32_t length);

status_t send_monitor_page_req(tls_instance_t *tls, addr_t gpfn, vmi_mem_access_t page_access_flag);

status_t send_monitor_resume_req(tls_instance_t *tls, uint64_t vcpu);

status_t send_attest_report_req(tls_instance_t *tls);

status_t recv_pause_reply(tls_instance_t *tls);

status_t recv_resume_reply(tls_instance_t *tls);

status_t recv_mem_boundary_reply(tls_instance_t *tls, addr_t *maximum_physical_address);

status_t recv_register_read_reply(tls_instance_t *tls, uint64_t *value);

status_t recv_register_write_reply(tls_instance_t *tls);

void *recv_page_read_reply(tls_instance_t *tls);

status_t recv_page_write_reply(tls_instance_t *tls);

status_t recv_monitor_page_reply(tls_instance_t *tls);

status_t recv_monitor_resume_reply(tls_instance_t *tls);

int recv_agent_push_msg(tls_instance_t *tls);

void *recv_attest_report_reply(tls_instance_t *tls);

#endif // SYSSEC_HANDLE_MSG_H
