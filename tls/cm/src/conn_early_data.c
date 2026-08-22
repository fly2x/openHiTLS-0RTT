/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "hitls_build.h"
#if defined(HITLS_TLS_FEATURE_EARLY_DATA) && defined(HITLS_TLS_PROTO_TLS13_FAMILY)
#include "bsl_log_internal.h"
#include "tls_binlog_id.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "hitls.h"
#include "tls.h"
#include "rec.h"
#include "record.h"
#include "app.h"
#include "hs_ctx.h"
#include "session.h"
#include "conn_common.h"
#ifdef HITLS_TLS_FEATURE_QUIC_TLS
#include "quic_tls_internal.h"
#endif

int32_t HITLS_GetEarlyDataStatus(const HITLS_Ctx *ctx, uint32_t *status)
{
    if (ctx == NULL || status == NULL) {
        return HITLS_NULL_INPUT;
    }
    switch (ctx->earlyDataState) {
        case TLS_EARLY_DATA_ACCEPTED:
            *status = HITLS_EARLY_DATA_ACCEPTED;
            break;
        case TLS_EARLY_DATA_REJECTED:
            *status = HITLS_EARLY_DATA_REJECTED;
            break;
        default:
            /* SENDING is not final yet; report NOT_SENT until the peer's verdict arrives */
            *status = HITLS_EARLY_DATA_NOT_SENT;
            break;
    }
    return HITLS_SUCCESS;
}

int32_t HITLS_SetMaxEarlyDataSize(HITLS_Ctx *ctx, uint32_t maxEarlyDataSize)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetMaxEarlyDataSize(&ctx->config.tlsConfig, maxEarlyDataSize);
}

int32_t HITLS_GetMaxEarlyDataSize(const HITLS_Ctx *ctx, uint32_t *maxEarlyDataSize)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_GetMaxEarlyDataSize(&ctx->config.tlsConfig, maxEarlyDataSize);
}

/* The client may keep writing early data while the offer is pending or accepted and the
 * early write keys are still active. */
static bool ClientCanWriteEarlyData(const HITLS_Ctx *ctx)
{
    if (GetConnState(ctx) != CM_STATE_HANDSHAKING || ctx->hsCtx == NULL) {
        return false;
    }
    const HS_Ctx *hsCtx = ctx->hsCtx;
    if (!hsCtx->earlyDataOffered) {
        return false;
    }
#ifdef HITLS_TLS_PROTO_DTLS13
    /* DTLS 1.3: receipt of the ServerHello switches the write state to the handshake epoch,
     * so early data (epoch 1) can only be written while the ServerHello is still expected */
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        return ctx->earlyDataState == TLS_EARLY_DATA_SENDING && hsCtx->state == TRY_RECV_SERVER_HELLO;
    }
#endif
    if (ctx->earlyDataState == TLS_EARLY_DATA_SENDING) {
        return true;
    }
    /* Accepted: the early key stays active until EndOfEarlyData goes out with the second flight */
    return ctx->earlyDataState == TLS_EARLY_DATA_ACCEPTED &&
        (hsCtx->state == TRY_RECV_ENCRYPTED_EXTENSIONS || hsCtx->state == TRY_RECV_CERTIFICATE_REQUEST ||
         hsCtx->state == TRY_RECV_FINISH);
}

int32_t HITLS_WriteEarlyData(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen)
{
    if (ctx == NULL || data == NULL || dataLen == 0 || writeLen == NULL) {
        return HITLS_NULL_INPUT;
    }
#ifdef HITLS_TLS_FEATURE_QUIC_TLS
    if (QUIC_TLS_IsMode(ctx)) {
        /* 0-RTT application data belongs to the QUIC stack, not to TLS */
        return HITLS_CONFIG_UNSUPPORT;
    }
#endif
    *writeLen = 0;
    /* The offer is only made when the application expressed the intent; a plain HITLS_Connect
     * resumption never adds the early_data extension. */
    ctx->earlyDataIntent = true;

    /* The first call starts the handshake (resolving an undefined endpoint to client) so the
     * ClientHello with the early_data extension and the early keys go out; a want-read result
     * while waiting for the server is expected. */
    if (GetConnState(ctx) == CM_STATE_IDLE ||
        (GetConnState(ctx) == CM_STATE_HANDSHAKING && ctx->isClient && ctx->hsCtx != NULL &&
         ctx->hsCtx->state == TRY_SEND_CLIENT_HELLO)) {
        if (GetConnState(ctx) == CM_STATE_IDLE && ctx->config.tlsConfig.endpoint == HITLS_ENDPOINT_SERVER) {
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_EARLY_DATA_NOT_ALLOWED);
            return HITLS_MSG_HANDLE_EARLY_DATA_NOT_ALLOWED;
        }
        int32_t ret = HITLS_Connect(ctx);
        if (ret != HITLS_SUCCESS && ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY &&
            ret != HITLS_REC_NORMAL_IO_BUSY) {
            return ret;
        }
    }
    if (!ctx->isClient) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_EARLY_DATA_NOT_ALLOWED);
        return HITLS_MSG_HANDLE_EARLY_DATA_NOT_ALLOWED;
    }

    /* A large first flight (e.g. a fragmented DTLS ClientHello) may still be draining on a busy
     * transport; the early keys are not active yet, so this is a transient condition: the retry
     * re-drives the handshake above until the flight is out. */
    if (GetConnState(ctx) == CM_STATE_HANDSHAKING && ctx->hsCtx != NULL &&
        ctx->hsCtx->state == TRY_SEND_CLIENT_HELLO && ctx->hsCtx->earlyDataOffered) {
        return HITLS_REC_NORMAL_IO_BUSY;
    }

    RecCtx *recCtx = (RecCtx *)ctx->recCtx;
    if (ctx->earlyPendingData != NULL) {
        /* A previous call already encrypted this data into the record out-buffer or the flight
         * buffer and only the transport flush failed; re-encrypting on retry would put a second
         * copy on the wire. Complete the write flush-only, regardless of how far the handshake
         * moved on (the bytes were already accounted when they were staged). */
        if (ctx->earlyPendingData != data || ctx->earlyPendingLen > dataLen) {
            BSL_ERR_PUSH_ERROR(HITLS_APP_ERR_WRITE_BAD_RETRY);
            return HITLS_APP_ERR_WRITE_BAD_RETRY;
        }
        int32_t flushRet = REC_OutBufFlush(ctx);
#ifdef HITLS_TLS_FEATURE_FLIGHT
        if (flushRet == HITLS_SUCCESS && ctx->config.tlsConfig.isFlightTransmitEnable) {
            flushRet = REC_FlightTransmit(ctx);
        }
#endif
        if (flushRet != HITLS_SUCCESS) {
            return flushRet;
        }
        *writeLen = ctx->earlyPendingLen;
        REC_ClearPendingAppData(ctx);
        ctx->earlyPendingData = NULL;
        ctx->earlyPendingLen = 0;
        return HITLS_SUCCESS;
    }

    if (!ClientCanWriteEarlyData(ctx)) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_EARLY_DATA_NOT_ALLOWED);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15185, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "early data cannot be written in the current state.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_EARLY_DATA_NOT_ALLOWED;
    }

    /* Bounded by the max_early_data_size the ticket advertised */
    uint32_t maxEarlyData = SESS_GetMaxEarlyData(ctx->hsCtx->kxCtx->pskInfo13.resumeSession);
    if (dataLen > maxEarlyData || ctx->earlyDataWritten > maxEarlyData - dataLen) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_EARLY_DATA_LIMIT_EXCEEDED);
        return HITLS_MSG_HANDLE_EARLY_DATA_LIMIT_EXCEEDED;
    }

    /* A record of a previous message (e.g. the compat CCS) may still sit in the record
     * out-buffer on a busy transport; it must be flushed before new data is encrypted so a
     * flush-retry inside the record layer is never mistaken for this write. When THIS data
     * is the pending record, APP_Write itself completes the retry. */
    if (recCtx->pendingData == NULL) {
        int32_t flushRet = REC_OutBufFlush(ctx);
        if (flushRet != HITLS_SUCCESS) {
            return flushRet;
        }
    }

    /* A datagram record cannot be clipped by the record layer retroactively: bound the
     * attempt so the staged-length accounting below matches what was actually encrypted. */
    uint32_t attemptLen = dataLen;
#ifdef HITLS_TLS_PROTO_DTLS
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        uint32_t maxWriteLen = 0;
        if (REC_GetMaxWriteSize(ctx, &maxWriteLen) == HITLS_SUCCESS && attemptLen > maxWriteLen) {
            attemptLen = maxWriteLen;
        }
    }
#endif

    int32_t ret = APP_Write(ctx, REC_TYPE_APP, data, attemptLen, writeLen);
    if (ret == HITLS_SUCCESS) {
        ctx->earlyDataWritten += *writeLen;
        return HITLS_SUCCESS;
    }
    *writeLen = 0;
    /* Stream transports retain the encrypted record (out-buffer or flight buffer) on a busy
     * transport, so it WILL reach the wire with the next successful flush, no matter who
     * flushes: account for it now and remember that the retry must be completed flush-only.
     * Datagram transports drop the record instead (the retry re-encrypts), so nothing is
     * staged for them. */
    if (ret == HITLS_REC_NORMAL_IO_BUSY && recCtx->pendingData == data
#ifdef HITLS_TLS_PROTO_DTLS
        && !IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)
#endif
    ) {
        uint32_t stagedLen = (recCtx->pendingDataSize != 0) ? recCtx->pendingDataSize : attemptLen;
        ctx->earlyPendingData = data;
        ctx->earlyPendingLen = stagedLen;
        ctx->earlyDataWritten += stagedLen;
    }
    return ret;
}

int32_t HITLS_ReadEarlyData(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen)
{
    if (ctx == NULL || data == NULL || bufSize == 0 || readLen == NULL) {
        return HITLS_NULL_INPUT;
    }
#ifdef HITLS_TLS_FEATURE_QUIC_TLS
    if (QUIC_TLS_IsMode(ctx)) {
        return HITLS_CONFIG_UNSUPPORT;
    }
#endif
    if (ctx->isClient) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_EARLY_DATA_NOT_ALLOWED);
        return HITLS_MSG_HANDLE_EARLY_DATA_NOT_ALLOWED;
    }
    *readLen = 0;

    if (GetConnState(ctx) == CM_STATE_IDLE || GetConnState(ctx) == CM_STATE_HANDSHAKING) {
        int32_t ret = HITLS_Accept(ctx);
        if (ret != HITLS_SUCCESS && ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY &&
            ret != HITLS_REC_NORMAL_IO_BUSY && ret != HITLS_REC_NORMAL_RECV_UNEXPECT_MSG) {
            return ret;
        }
    }

    if (ctx->earlyDataState != TLS_EARLY_DATA_ACCEPTED) {
        /* The offer is undecided until the ClientHello was processed */
        if (GetConnState(ctx) == CM_STATE_HANDSHAKING && ctx->hsCtx != NULL &&
            ctx->hsCtx->state == TRY_RECV_CLIENT_HELLO) {
            return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
        }
        return HITLS_READ_EARLY_DATA_FINISH;
    }

    /* End of the early phase: TLS 1.3 after EndOfEarlyData was consumed (the state moved on to
     * the client Finished), DTLS 1.3 / fallback when the handshake completed. */
    bool phaseActive = (GetConnState(ctx) == CM_STATE_HANDSHAKING);
    if (phaseActive && ctx->negotiatedInfo.version == HITLS_VERSION_TLS13 &&
        ctx->hsCtx != NULL && ctx->hsCtx->state == TRY_RECV_FINISH) {
        phaseActive = false;
    }

    /* Once the phase is over, only records buffered DURING the phase may still be delivered;
     * reading fresh records here would hand pipelined 1-RTT data out through the early-data
     * API and misapply the early-data limit to it. */
    if (!phaseActive && RecBufListEmpty(((RecCtx *)ctx->recCtx)->appRecList)) {
        return HITLS_READ_EARLY_DATA_FINISH;
    }

    uint32_t got = 0;
    int32_t ret = REC_Read(ctx, REC_TYPE_APP, data, &got, bufSize);
    if (ret == HITLS_SUCCESS && got > 0) {
        /* Enforce the advertised max_early_data_size on the plaintext actually delivered */
        uint32_t maxEarlyData = SESS_GetMaxEarlyData(ctx->session);
        if (got > maxEarlyData || ctx->earlyDataRead > maxEarlyData - got) {
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_EARLY_DATA_LIMIT_EXCEEDED);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15186, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "received early data exceeds max_early_data_size.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
            return HITLS_MSG_HANDLE_EARLY_DATA_LIMIT_EXCEEDED;
        }
        ctx->earlyDataRead += got;
        *readLen = got;
        return HITLS_SUCCESS;
    }

    if (!phaseActive) {
        return HITLS_READ_EARLY_DATA_FINISH;
    }
    /* Nothing readable yet (or a handshake record was buffered for the next Accept round) */
    return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
}
#endif /* HITLS_TLS_FEATURE_EARLY_DATA && HITLS_TLS_PROTO_TLS13_FAMILY */
