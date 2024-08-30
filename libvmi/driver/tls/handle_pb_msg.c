#include <stdint.h>
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
#include "driver/tls/tls_events.h"
#include "driver/tls/messages.pb-c.h"
#include "driver/tls/handle_pb_msg.h"
#include "driver/tls/handle_pb_prefix.h"

status_t send_msg(tls_instance_t *tls, enum request req, void *to_send)
{
    status_t status = VMI_FAILURE;
    MsgProto__AccessRequest msg = MSG_PROTO__ACCESS_REQUEST__INIT;

    dbprint(VMI_DEBUG_DRIVER, "Going to send msg (type: %d)\n", req);

    uint8_t *buf;
    uint8_t msg_len;
    uint64_t prefix_len;

#ifdef TLS_DEBUG_COUNTER
    dbg_send_counter++;
#endif

    switch (req) {
        case PauseReq:
            msg.request_case = MSG_PROTO__ACCESS_REQUEST__REQUEST_PAUSE_REQ;
            msg.pause_req = to_send;
            break;
        case ResumeReq:
            msg.request_case = MSG_PROTO__ACCESS_REQUEST__REQUEST_RESUME_REQ;
            msg.resume_req = to_send;
            break;
        case MemBoundaryReq:
            msg.request_case = MSG_PROTO__ACCESS_REQUEST__REQUEST_MEMBD_REQ;
            msg.membd_req = to_send;
            break;
        case RegisterReadReq:
            msg.request_case = MSG_PROTO__ACCESS_REQUEST__REQUEST_RREG_REQ;
            msg.rreg_req = to_send;
            break;
        case RegisterWriteReq:
            msg.request_case = MSG_PROTO__ACCESS_REQUEST__REQUEST_WREG_REQ;
            msg.wreg_req = to_send;
            break;
        case PageReadReq:
            msg.request_case = MSG_PROTO__ACCESS_REQUEST__REQUEST_RPAGE_REQ;
            msg.rpage_req = to_send;
            break;
        case PageWriteReq:
            msg.request_case = MSG_PROTO__ACCESS_REQUEST__REQUEST_WPAGE_REQ;
            msg.wpage_req = to_send;
            break;
        case MonitorPageReq:
            msg.request_case = MSG_PROTO__ACCESS_REQUEST__REQUEST_MNTR_PAGE_REQ;
            msg.mntr_page_req = to_send;
            break;
        case MonitorResumeReq:
            msg.request_case = MSG_PROTO__ACCESS_REQUEST__REQUEST_MNTR_RESUME_REQ;
            msg.mntr_resume_req = to_send;
            break;
        case AttestReportReq:
            msg.request_case = MSG_PROTO__ACCESS_REQUEST__REQUEST_ATTEST_REPORT_REQ;
            msg.attest_report_req = to_send;
            break;
        default:
            errprint("unsupported request type\n");
            return status;
    }

    msg_len = msg_proto__access_request__get_packed_size(&msg);
    prefix_len = calc_prefix_len(msg_len);

    buf = malloc(msg_len + prefix_len);
    assert(buf != NULL);

    if(!write_varint(buf, msg_len + prefix_len, msg_len).success) goto err_exit;

    msg_proto__access_request__pack(&msg, &buf[prefix_len]);

    // send loop
    ssize_t nsent = 0, nremain = msg_len + prefix_len;
    uint8_t *send_buf = buf;

    dbprint(VMI_DEBUG_DRIVER, "will send %lu bytes\n", nremain);

    while (nremain > 0) {
#ifdef ENABLE_TLS
        nsent = BIO_write(tls->bio, send_buf, nremain); 
        if(nsent == -2) {
            errprint("write operation is not implemented by BIO\n");
            ERR_print_errors_fp(stderr);
            goto err_exit;
        }
#else
        nsent = send(tls->sockfd, send_buf, nremain, 0);
#endif
        if (nsent < 0) {
            errprint("error occured when sending msg\n");
            goto err_exit;
        }
        nremain -= nsent;
        send_buf += nsent;
        if (nremain > 0) {
            dbprint(VMI_DEBUG_DRIVER, "will do partial msg send\n");
        }
    }

    status = VMI_SUCCESS;

err_exit:
    free(buf);
    dbprint(VMI_DEBUG_DRIVER, "Finished sending msg (status: %d)\n", status);
    return status;
}

// Tricky aspects: partial message receive, or multi-message receive (e.g., Trap notify at any point)
// TODO: this does not yet handle all cases, e.g., receive buffer wrap around
status_t recv_msg(tls_instance_t *tls, enum reply repl, MsgProto__AccessReply **msg_out)
{
    status_t status = VMI_FAILURE;
    uint8_t *buf = malloc(TLS_MAX_MSG_SIZE);
    uint8_t *msg_begin = NULL; // will be set to point into buf, after length prefix

    ssize_t nrecv;
    size_t not_processed_recv; // how much unprocessed bytes we have received
    uint8_t *curr_buf_pos; // current start of unprocessed buffer bytes

    assert(buf != NULL);
    assert(tls != NULL);
    assert(msg_out != NULL);
    assert(*msg_out == NULL);

    dbprint(VMI_DEBUG_DRIVER, "Going to receive msg (type: %d)\n", repl);

#ifdef TLS_DEBUG_COUNTER
    dbg_recv_counter++;
#endif

    // We need to do a receive, then handle as many messages as we have partially received,
    // potentially in multiple loop iterations. The expected message types are the requested
    // one ++ and an arbitrary number of TrapNotify messages (max-limited by number of VM vCPUs).

repeat_receive:
    memset(buf, 0, TLS_MAX_MSG_SIZE);
    nrecv = 0;
    curr_buf_pos = buf;
    not_processed_recv = 0;

    // Try to receive partial messages (we asume it receives at least prefix-size)
#ifdef ENABLE_TLS
    nrecv = BIO_read(tls->bio, buf, TLS_MAX_MSG_SIZE);
#else 
    nrecv = recv(tls->sockfd, buf, TLS_MAX_MSG_SIZE, 0);
#endif

    // e.g., ctrl+C (TODO: check reason)
    if (nrecv == 0) {
        errprint("nrecv == 0 (expected type: %d)\n", repl);
        return VMI_FAILURE;
    }

    if(nrecv < 0) {
#ifdef ENABLE_TLS
        if(nrecv == -2) {
            errprint("read operation is not implemented by BIO\n");
            goto err_exit;
        }
        //if(BIO_should_retry(tls->bio)) goto repeat_receive;
        ERR_print_errors_fp(stderr);
#endif
        errprint("error when receiving message\n");
        goto err_exit;
    }
    not_processed_recv += nrecv;
    dbprint(VMI_DEBUG_DRIVER, "Received %lu bytes\n", nrecv);

    prefix_res_t result;
process_msg_loop:
    // Read prefix of next message
    result = read_pb_prefix(curr_buf_pos, not_processed_recv /*nrecv*/, &msg_begin);
    if(!result.success) {
        errprint("failed to read protobuf prefix\n");
        goto err_exit;
    }
    size_t msg_len = result.prefix;
    size_t prefix_len = msg_begin - curr_buf_pos;
    assert(not_processed_recv >= prefix_len);
    not_processed_recv -= prefix_len;

    curr_buf_pos = msg_begin;

    // must make sure that we received a full message
    uint8_t *partial_recv_buf = curr_buf_pos + not_processed_recv;

    while (not_processed_recv < msg_len) {
        dbprint(VMI_DEBUG_DRIVER, "partial msg receive\n");

        // enough size left in buffer?
        assert((partial_recv_buf + (msg_len - not_processed_recv)) <= (buf + TLS_MAX_MSG_SIZE));

#ifdef ENABLE_TLS
        nrecv = BIO_read(tls->bio, partial_recv_buf, (msg_len - not_processed_recv));
#else
        nrecv = recv(tls->sockfd, partial_recv_buf, (msg_len - not_processed_recv), 0);
#endif
        if (nrecv < 0) {
            errprint("failed partial msg receive\n");
            goto err_exit;
        }

        not_processed_recv += nrecv; // might become bigger than msg_len
        partial_recv_buf += nrecv;
        dbprint(VMI_DEBUG_DRIVER, "partial msg receive\n");
    }

    // Unpack new message into malloc() region (NULL->system alloactor)
    MsgProto__AccessReply *msg = msg_proto__access_reply__unpack(NULL, msg_len, curr_buf_pos);
    if (msg == NULL) {
        errprint("error unpacking incoming message\n");
        goto err_exit;
    }
    curr_buf_pos += msg_len;
    assert(not_processed_recv >= msg_len);
    not_processed_recv -= msg_len;

    bool invalid_msg = false;
    switch (msg->reply_case) {
        case MSG_PROTO__ACCESS_REPLY__REPLY_PAUSE_REPLY:
            if(repl != PauseReply) invalid_msg = true;
            break;
        case MSG_PROTO__ACCESS_REPLY__REPLY_RESUME_REPLY:
            if(repl != ResumeReply) invalid_msg = true;
            break;
        case MSG_PROTO__ACCESS_REPLY__REPLY_MEMBD_REPLY:
            if(repl != MemBoundaryReply) invalid_msg = true;
            break;
        case MSG_PROTO__ACCESS_REPLY__REPLY_RREG_REPLY:
            if(repl != RegisterReadReply) invalid_msg = true;
            break;
        case MSG_PROTO__ACCESS_REPLY__REPLY_WREG_REPLY:
            if(repl != RegisterWriteReply) invalid_msg = true;
            break;
        case MSG_PROTO__ACCESS_REPLY__REPLY_RPAGE_REPLY:
            if(repl != PageReadReply) invalid_msg = true;
            break;
        case MSG_PROTO__ACCESS_REPLY__REPLY_WPAGE_REPLY:
            if(repl != PageWriteReply) invalid_msg = true;
            break;
        case MSG_PROTO__ACCESS_REPLY__REPLY_MNTR_PAGE_REPLY:
            if(repl != MonitorPageReply) invalid_msg = true;
            break;
        case MSG_PROTO__ACCESS_REPLY__REPLY_MNTR_RESUME_REPLY:
            if(repl != MonitorResumeReply) invalid_msg = true;
            break;
        case MSG_PROTO__ACCESS_REPLY__REPLY_ATTEST_REPORT_REPLY:
            if(repl != AttestReportReply) invalid_msg = true;
            break;
        case MSG_PROTO__ACCESS_REPLY__REPLY_AGENT_PUSH_MSG:
            if ( tls_push_event(tls, msg->agent_push_msg->mntr_page_event) != 0) {
                errprint("Failed pushing event message to queue\n");
                goto err_exit;
            }

            // Do we want/need this message?
            if (repl == AgentPush) {
                if (status != VMI_SUCCESS) break; // not yet received
                else msg_proto__access_reply__free_unpacked(msg, NULL);
            } else {
                msg_proto__access_reply__free_unpacked(msg, NULL);
            }

            // No fall-through yet; Do we want to continue?
            if (not_processed_recv > 0) goto process_msg_loop; // process remaining bytes
            if (status != VMI_SUCCESS) goto repeat_receive; // need full new receive

            goto exit; // we are done
        default:
            invalid_msg = true;
            break;
    }

    if (invalid_msg) {
        errprint("Unexpected reply msg (type: %u)\n", msg->reply_case);
        msg_proto__access_reply__free_unpacked(msg, NULL);
        goto err_exit;
    } else {
        *msg_out = msg;
        msg = NULL;
        status = VMI_SUCCESS;
    }

    // remaining receive bytes to process? (e.g., trap notify msg)
    if (not_processed_recv > 0) {
        dbprint(VMI_DEBUG_DRIVER, "continue processing received bytes\n");
        goto process_msg_loop;
    }

exit:
    free(buf);
    dbprint(VMI_DEBUG_DRIVER, "Finished receiving msg (status: %d)\n", status);
    return status;

err_exit:
    free(buf);
    if (*msg_out != NULL) {
        msg_proto__access_reply__free_unpacked(*msg_out, NULL);
        *msg_out = NULL;
    }
    errprint("error receive (type: %d)\n", repl);
    dbprint(VMI_DEBUG_DRIVER, "Failed receiving msg\n");
    return VMI_FAILURE;
}

status_t send_pause_req(tls_instance_t *tls)
{
    MsgProto__PauseReq to_send = MSG_PROTO__PAUSE_REQ__INIT;

    return send_msg(tls, PauseReq, &to_send);
}

status_t send_resume_req(tls_instance_t *tls)
{
    MsgProto__ResumeReq to_send = MSG_PROTO__RESUME_REQ__INIT;

    return send_msg(tls, ResumeReq, &to_send);
}

status_t send_mem_boundary_req(tls_instance_t *tls)
{
    MsgProto__MemBoundaryReq to_send = MSG_PROTO__MEM_BOUNDARY_REQ__INIT;

    return send_msg(tls, MemBoundaryReq, &to_send);
}

status_t 
send_register_read_req(
    tls_instance_t *tls, 
    MsgProto__RegisterID reg, 
    unsigned long vcpu)
{
    MsgProto__RegisterReadReq to_send = MSG_PROTO__REGISTER_READ_REQ__INIT;

    to_send.vcpu = vcpu;
    to_send.register_ = reg;

    return send_msg(tls, RegisterReadReq, &to_send);
}

status_t 
send_register_write_req(
    tls_instance_t *tls, 
    uint64_t value, 
    MsgProto__RegisterID reg, 
    unsigned long vcpu)
{
    MsgProto__RegisterWriteReq to_send = MSG_PROTO__REGISTER_WRITE_REQ__INIT;

    to_send.value = value;
    to_send.register_ = reg;
    to_send.vcpu = vcpu;

    return send_msg(tls, RegisterWriteReq, &to_send);
}

status_t send_page_read_req(tls_instance_t *tls, addr_t page)
{
    MsgProto__PageReadReq to_send = MSG_PROTO__PAGE_READ_REQ__INIT;

    to_send.frame_num = page;

    return send_msg(tls, PageReadReq, &to_send);
}

status_t 
send_page_write_req(
    tls_instance_t *tls, 
    addr_t paddr, 
    void *buf, 
    uint32_t length)
{
    MsgProto__PageWriteReq to_send = MSG_PROTO__PAGE_WRITE_REQ__INIT;

    to_send.paddr = paddr;
    ProtobufCBinaryData write_buf;
    write_buf.len = length;
    write_buf.data = buf;
    to_send.write_buffer = write_buf;

    return send_msg(tls, PageWriteReq, &to_send);
}

status_t 
send_monitor_page_req(
    tls_instance_t *tls, 
    addr_t gpfn, 
    vmi_mem_access_t page_access_flag)
{
    MsgProto__MonitorPageReq to_send = MSG_PROTO__MONITOR_PAGE_REQ__INIT;

    to_send.frame_num = gpfn;
    switch (page_access_flag)
    {
    case VMI_MEMACCESS_N:
        to_send.access_type = MSG_PROTO__MEM_ACCESS_TYPE__DISABLE;
        break;
    case VMI_MEMACCESS_R:
        to_send.access_type = MSG_PROTO__MEM_ACCESS_TYPE__READ;
        break;
    case VMI_MEMACCESS_W:
        to_send.access_type = MSG_PROTO__MEM_ACCESS_TYPE__WRITE;
        break;
    case VMI_MEMACCESS_RW:
        to_send.access_type = MSG_PROTO__MEM_ACCESS_TYPE__READ_WRITE;
        break;
    default:
        errprint("Unknown memory access type specified (%u)\n", page_access_flag);
        return VMI_FAILURE;
    }

    return send_msg(tls, MonitorPageReq, &to_send);
}

status_t send_monitor_resume_req(tls_instance_t *tls, uint64_t vcpu)
{
    MsgProto__MonitorResumeReq to_send = MSG_PROTO__MONITOR_RESUME_REQ__INIT;

    to_send.vcpu = vcpu;

    return send_msg(tls, MonitorResumeReq, &to_send);
}

status_t send_attest_report_req(tls_instance_t *tls)
{
    MsgProto__PageReadReq to_send = MSG_PROTO__ATTEST_REPORT_REQ__INIT;

    return send_msg(tls, AttestReportReq, &to_send);
}

status_t recv_pause_reply(tls_instance_t *tls)
{
    status_t status = VMI_FAILURE;
    MsgProto__AccessReply *msg = NULL;

    if (recv_msg(tls, PauseReply, &msg))
        goto err_exit;

    assert(msg->reply_case == MSG_PROTO__ACCESS_REPLY__REPLY_PAUSE_REPLY);
    MsgProto__PauseReply *pause_reply = msg->pause_reply;

    if (pause_reply->status == MSG_PROTO__REQUEST_STATUS__REQUEST_SUCCESS)
        status = VMI_SUCCESS;

err_exit:
    if (msg != NULL) msg_proto__access_reply__free_unpacked(msg, NULL);
    return status;
}

status_t recv_resume_reply(tls_instance_t *tls)
{
    status_t status = VMI_FAILURE;
    MsgProto__AccessReply *msg = NULL;

    if (recv_msg(tls, ResumeReply, &msg))
        goto err_exit;

    assert(msg->reply_case == MSG_PROTO__ACCESS_REPLY__REPLY_RESUME_REPLY);
    MsgProto__ResumeReply *resume_reply = msg->resume_reply;

    if (resume_reply->status == MSG_PROTO__REQUEST_STATUS__REQUEST_SUCCESS)
        status = VMI_SUCCESS;

err_exit:
    if (msg != NULL) msg_proto__access_reply__free_unpacked(msg, NULL);
    return status;
}

status_t 
recv_mem_boundary_reply(
    tls_instance_t *tls, 
    addr_t *maximum_physical_address)
{
    status_t status = VMI_FAILURE;
    MsgProto__AccessReply *msg = NULL;

    if (recv_msg(tls, MemBoundaryReply, &msg))
        goto err_exit;

    assert(msg->reply_case == MSG_PROTO__ACCESS_REPLY__REPLY_MEMBD_REPLY);
    MsgProto__MemBoundaryReply *membd_reply = msg->membd_reply;

    if (membd_reply->status == MSG_PROTO__REQUEST_STATUS__REQUEST_SUCCESS) {
        memcpy(maximum_physical_address, &membd_reply->vmpl0_begin_gpa, sizeof(uint64_t));
        status = VMI_SUCCESS;
    }

err_exit:
    if (msg != NULL) msg_proto__access_reply__free_unpacked(msg, NULL);
    return status;
}

status_t recv_register_read_reply(tls_instance_t *tls, uint64_t *value)
{
    status_t status = VMI_FAILURE;
    MsgProto__AccessReply *msg = NULL;

    if (recv_msg(tls, RegisterReadReply, &msg))
        goto err_exit;

    assert(msg->reply_case == MSG_PROTO__ACCESS_REPLY__REPLY_RREG_REPLY);
    MsgProto__RegisterReadReply *rreg_reply = msg->rreg_reply;

    if (rreg_reply->status == MSG_PROTO__REQUEST_STATUS__REQUEST_SUCCESS) {
        memcpy(value, &rreg_reply->value, sizeof(uint64_t));
        status = VMI_SUCCESS;
    }

err_exit:
    if (msg != NULL) msg_proto__access_reply__free_unpacked(msg, NULL);
    return status;
}

status_t recv_register_write_reply(tls_instance_t *tls)
{
    status_t status = VMI_FAILURE;
    MsgProto__AccessReply *msg = NULL;

    if (recv_msg(tls, RegisterWriteReply, &msg))
        goto err_exit;

    assert(msg->reply_case == MSG_PROTO__ACCESS_REPLY__REPLY_WREG_REPLY);
    MsgProto__RegisterWriteReply *wreg_reply = msg->wreg_reply;

    if (wreg_reply->status == MSG_PROTO__REQUEST_STATUS__REQUEST_SUCCESS)
        status = VMI_SUCCESS;

err_exit:
    if (msg != NULL) msg_proto__access_reply__free_unpacked(msg, NULL);
    return status;
}

void *recv_page_read_reply(tls_instance_t *tls)
{
    void *ret = NULL;
    MsgProto__AccessReply *msg = NULL;

    if (recv_msg(tls, PageReadReply, &msg))
        goto err_exit;

    assert(msg->reply_case == MSG_PROTO__ACCESS_REPLY__REPLY_RPAGE_REPLY);
    MsgProto__PageReadReply *rpage_reply = msg->rpage_reply;

    if (rpage_reply->status == MSG_PROTO__REQUEST_STATUS__REQUEST_SUCCESS) {
        ret = malloc(rpage_reply->page.len);
        assert(ret != NULL);
        memcpy(ret, rpage_reply->page.data, rpage_reply->page.len);
    }

err_exit:
    if (msg != NULL) msg_proto__access_reply__free_unpacked(msg, NULL);
    return ret;
}

status_t recv_page_write_reply(tls_instance_t *tls)
{
    status_t status = VMI_FAILURE;
    MsgProto__AccessReply *msg = NULL;

    if (recv_msg(tls, PageWriteReply, &msg))
        goto err_exit;

    assert(msg->reply_case == MSG_PROTO__ACCESS_REPLY__REPLY_WPAGE_REPLY);
    MsgProto__PageWriteReply *wpage_reply = msg->wpage_reply;

    if (wpage_reply->status == MSG_PROTO__REQUEST_STATUS__REQUEST_SUCCESS)
        status = VMI_SUCCESS;

err_exit:
    if (msg != NULL) msg_proto__access_reply__free_unpacked(msg, NULL);
    return status;
}

status_t recv_monitor_page_reply(tls_instance_t *tls)
{
    status_t status = VMI_FAILURE;
    MsgProto__AccessReply *msg = NULL;

    if (recv_msg(tls, MonitorPageReply, &msg))
        goto err_exit;

    assert(msg->reply_case == MSG_PROTO__ACCESS_REPLY__REPLY_MNTR_PAGE_REPLY);
    MsgProto__MonitorPageReply *mntr_page_reply = msg->mntr_page_reply;

    if (mntr_page_reply->status == MSG_PROTO__REQUEST_STATUS__REQUEST_SUCCESS)
        status = VMI_SUCCESS;

err_exit:
    if (msg != NULL) msg_proto__access_reply__free_unpacked(msg, NULL);
    return status;
}

status_t recv_monitor_resume_reply(tls_instance_t *tls)
{
    status_t status = VMI_FAILURE;
    MsgProto__AccessReply *msg = NULL;

    if (recv_msg(tls, MonitorResumeReply, &msg))
        goto err_exit;

    assert(msg->reply_case == MSG_PROTO__ACCESS_REPLY__REPLY_MNTR_RESUME_REPLY);
    MsgProto__MonitorResumeReply *mntr_resume_reply = msg->mntr_resume_reply;

    if (mntr_resume_reply->status == MSG_PROTO__REQUEST_STATUS__REQUEST_SUCCESS)
        status = VMI_SUCCESS;

err_exit:
    if (msg != NULL) msg_proto__access_reply__free_unpacked(msg, NULL);
    return status;
}

int recv_agent_push_msg(tls_instance_t *tls) 
{
    status_t status = VMI_FAILURE;
    MsgProto__AccessReply *msg = NULL;

    if (recv_msg(tls, AgentPush, &msg))
        goto err_exit;

    assert(msg->reply_case == MSG_PROTO__ACCESS_REPLY__REPLY_AGENT_PUSH_MSG);
    // we do not proccess the reply here, because it gets enqueued inside recv_msg() already
    status = VMI_SUCCESS;

err_exit:
    if (msg != NULL) msg_proto__access_reply__free_unpacked(msg, NULL);
    return status;
}

void *recv_attest_report_reply(tls_instance_t *tls)
{
    void *ret = NULL;
    MsgProto__AccessReply *msg = NULL;

    if (recv_msg(tls, AttestReportReply, &msg))
        goto err_exit;

    assert(msg->reply_case == MSG_PROTO__ACCESS_REPLY__REPLY_ATTEST_REPORT_REPLY);
    MsgProto__AttestReportReply *att_reply = msg->attest_report_reply;

    if (att_reply->status == MSG_PROTO__REQUEST_STATUS__REQUEST_SUCCESS) {
        dbprint(VMI_DEBUG_DRIVER, "received attestation report reply of length: %ld (ptr: %p)\n", att_reply->report.len, att_reply->report.data);
        
        ret = malloc(att_reply->report.len);
        assert(ret != NULL);
        memcpy(ret, att_reply->report.data, att_reply->report.len);
    }

err_exit:
    if (msg != NULL) msg_proto__access_reply__free_unpacked(msg, NULL);
    return ret;
}