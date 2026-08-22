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

/* BEGIN_HEADER */

#include <string.h>
#include "frame_tls.h"
#include "frame_io.h"
#include "frame_link.h"
#include "simulate_io.h"
#include "session.h"
#include "session_type.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hitls.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "hitls_session.h"
#include "hitls_alpn.h"
#include "hitls_crypt_init.h"

#define EARLY_DATA_TEST_MAX 16384u

static const uint8_t g_earlyPayload[] = "0-rtt early data payload";
static const uint8_t g_appPayload[] = "1-rtt application payload";

/* Build a TLS1.3 config with 0-RTT enabled (maxEarlyData bytes; 0 leaves 0-RTT off). */
static HITLS_Config *NewEarlyDataTls13Config(uint32_t maxEarlyData)
{
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    if (config == NULL) {
        return NULL;
    }
    if (HITLS_CFG_SetMaxEarlyDataSize(config, maxEarlyData) != HITLS_SUCCESS) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }
    return config;
}

/* Run a full first handshake and hand back the client session carrying the 0-RTT ticket. */
static int32_t EarlyDataPrepareSession(HITLS_Config *clientConfig, HITLS_Config *serverConfig, HITLS_Session **session)
{
    FRAME_LinkObj *client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    int32_t ret = HITLS_INTERNAL_EXCEPTION;
    if (client != NULL && server != NULL) {
        ret = FRAME_CreateConnection(client, server, false, HS_STATE_BUTT);
    }
    if (ret == HITLS_SUCCESS) {
        *session = HITLS_GetDupSession(client->ssl);
        if (*session == NULL) {
            ret = HITLS_INTERNAL_EXCEPTION;
        }
    }
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    return ret;
}

/* Drain everything HITLS_ReadEarlyData currently has into earlyOut; returns the last result. */
static int32_t EarlyDataDrainServer(FRAME_LinkObj *server, uint8_t *earlyOut, uint32_t earlyOutSize,
    uint32_t *earlyOutLen)
{
    int32_t ret;
    uint32_t got;
    do {
        got = 0;
        ret = HITLS_ReadEarlyData(server->ssl, earlyOut + *earlyOutLen, earlyOutSize - *earlyOutLen, &got);
        *earlyOutLen += got;
    } while (ret == HITLS_SUCCESS && got > 0);
    return ret;
}

static bool EarlyDataDrainTolerable(int32_t ret)
{
    return ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY || ret == HITLS_READ_EARLY_DATA_FINISH;
}

/*
 * Write the early payload, honouring the retry protocol: the FRAME transport holds a single
 * in-flight message, so the records of the first flight (ClientHello [fragments], CCS, the
 * early record) drain one transfer per retry, with the server absorbing what arrives.
 * Early data the server reads along the way accumulates in earlyOut.
 */
static int32_t EarlyDataWriteWithRetry(FRAME_LinkObj *client, FRAME_LinkObj *server,
    const uint8_t *payload, uint32_t payloadLen,
    uint8_t *earlyOut, uint32_t earlyOutSize, uint32_t *earlyOutLen)
{
    uint32_t writtenLen = 0;
    int32_t ret = HITLS_WriteEarlyData(client->ssl, payload, payloadLen, &writtenLen);
    for (int32_t i = 0; ret == HITLS_REC_NORMAL_IO_BUSY && i < 10; i++) {
        int32_t tRet = FRAME_TrasferMsgBetweenLink(client, server);
        if (tRet != HITLS_SUCCESS) {
            return tRet;
        }
        tRet = EarlyDataDrainServer(server, earlyOut, earlyOutSize, earlyOutLen);
        if (!EarlyDataDrainTolerable(tRet)) {
            return tRet;
        }
        ret = HITLS_WriteEarlyData(client->ssl, payload, payloadLen, &writtenLen);
    }
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return (writtenLen == payloadLen) ? HITLS_SUCCESS : HITLS_INTERNAL_EXCEPTION;
}

/*
 * Ping-pong the two links until both sides report an established connection, reading early
 * data on the server side along the way. One FRAME message travels per direction per round,
 * matching the per-record flushing of the disabled flight-transmit mode.
 */
static int32_t EarlyDataPump(FRAME_LinkObj *client, FRAME_LinkObj *server,
    uint8_t *earlyOut, uint32_t earlyOutSize, uint32_t *earlyOutLen)
{
    int32_t clientRet = HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    int32_t serverRet = HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    FrameUioUserData *cUd = BSL_UIO_GetUserData(client->io);
    FrameUioUserData *sUd = BSL_UIO_GetUserData(server->io);

    for (int32_t i = 0; i < 30; i++) {
        int32_t ret;
        if (cUd->sndMsg.len != 0 && sUd->recMsg.len == 0) {
            ret = FRAME_TrasferMsgBetweenLink(client, server);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
        }
        ret = EarlyDataDrainServer(server, earlyOut, earlyOutSize, earlyOutLen);
        if (!EarlyDataDrainTolerable(ret)) {
            return ret;
        }
        serverRet = HITLS_Accept(server->ssl);
        if (serverRet != HITLS_SUCCESS && serverRet != HITLS_REC_NORMAL_RECV_BUF_EMPTY &&
            serverRet != HITLS_REC_NORMAL_IO_BUSY && serverRet != HITLS_REC_NORMAL_RECV_UNEXPECT_MSG) {
            return serverRet;
        }
        if (sUd->sndMsg.len != 0 && cUd->recMsg.len == 0) {
            ret = FRAME_TrasferMsgBetweenLink(server, client);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
        }
        clientRet = HITLS_Connect(client->ssl);
        if (clientRet != HITLS_SUCCESS && clientRet != HITLS_REC_NORMAL_RECV_BUF_EMPTY &&
            clientRet != HITLS_REC_NORMAL_IO_BUSY) {
            return clientRet;
        }
        if (clientRet == HITLS_SUCCESS && serverRet == HITLS_SUCCESS) {
            return HITLS_SUCCESS;
        }
    }
    return HITLS_INTERNAL_EXCEPTION;
}

/* Move any remaining post-handshake records (NewSessionTickets) over and consume them. */
static int32_t EarlyDataDeliverTickets(FRAME_LinkObj *client, FRAME_LinkObj *server)
{
    FrameUioUserData *cUd = BSL_UIO_GetUserData(client->io);
    FrameUioUserData *sUd = BSL_UIO_GetUserData(server->io);
    for (int32_t i = 0; i < 5; i++) {
        uint8_t tmp[64] = {0};
        uint32_t tmpLen = 0;
        int32_t ret = HITLS_Read(client->ssl, tmp, sizeof(tmp), &tmpLen);
        if (ret != HITLS_SUCCESS && ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
            return ret;
        }
        if (sUd->sndMsg.len == 0 && cUd->recMsg.len == 0) {
            return HITLS_SUCCESS;
        }
        if (sUd->sndMsg.len != 0 && cUd->recMsg.len == 0) {
            ret = FRAME_TrasferMsgBetweenLink(server, client);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
        }
    }
    return HITLS_SUCCESS;
}

/*
 * Drive a complete 0-RTT resumption exchange between two freshly created links.
 * earlyOut/earlyOutLen return what the server read as early data.
 */
static int32_t EarlyDataRunHandshake(FRAME_LinkObj *client, FRAME_LinkObj *server,
    uint8_t *earlyOut, uint32_t earlyOutSize, uint32_t *earlyOutLen)
{
    *earlyOutLen = 0;

    /* 1. Client: the ClientHello flight and then the 0-RTT record go out */
    int32_t ret = EarlyDataWriteWithRetry(client, server, g_earlyPayload, sizeof(g_earlyPayload),
        earlyOut, earlyOutSize, earlyOutLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* 2. Ping-pong to completion; the server reads the early data along the way */
    ret = EarlyDataPump(client, server, earlyOut, earlyOutSize, earlyOutLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* 3. The early phase must be over on the server */
    ret = EarlyDataDrainServer(server, earlyOut, earlyOutSize, earlyOutLen);
    if (ret != HITLS_READ_EARLY_DATA_FINISH) {
        return ret;
    }

    /* 4. NewSessionTickets to the client */
    return EarlyDataDeliverTickets(client, server);
}

/* Server-side ALPN selection: take the client's first offered protocol. */
static int32_t EarlyDataAlpnSelectFirst(HITLS_Ctx *ctx, uint8_t **selectedProto, uint8_t *selectedProtoSize,
    uint8_t *clientAlpnList, uint32_t clientAlpnListSize, void *userData)
{
    (void)ctx;
    (void)userData;
    if (clientAlpnList == NULL || clientAlpnListSize < 2 || clientAlpnList[0] == 0 ||
        (uint32_t)clientAlpnList[0] + 1 > clientAlpnListSize) {
        return HITLS_ALPN_ERR_NOACK;
    }
    *selectedProto = &clientAlpnList[1];
    *selectedProtoSize = clientAlpnList[0];
    return HITLS_ALPN_ERR_OK;
}

/* Scan a raw flight for an extension header of the given type inside the first ClientHello. */
static bool FlightContainsEmptyExtension(const uint8_t *buf, uint32_t len, uint16_t extType)
{
    if (len < 4) {
        return false;
    }
    for (uint32_t i = 0; i + 4 <= len; i++) {
        if (buf[i] == (uint8_t)(extType >> 8) && buf[i + 1] == (uint8_t)(extType & 0xff) &&
            buf[i + 2] == 0 && buf[i + 3] == 0) {
            return true;
        }
    }
    return false;
}

/* END_HEADER */

/** @
* @test     UT_TLS13_EARLY_DATA_ACCEPT_FUNC_TC001
* @title    TLS1.3 0-RTT accept: early data is delivered and the connection completes.
* @brief    1. Full handshake with maxEarlyDataSize=16384; take the client session. Expect result 1.
*           2. Resume with HITLS_WriteEarlyData / HITLS_ReadEarlyData. Expect result 2.
*           3. Exchange 1-RTT data after the handshake. Expect result 3.
* @expect   1. The session's ticket advertises max_early_data_size 16384.
*           2. The server reads exactly the early payload; both sides report HITLS_EARLY_DATA_ACCEPTED
*              and the session is reused.
*           3. 1-RTT application data flows in both directions.
@ */
/* BEGIN_CASE */
void UT_TLS13_EARLY_DATA_ACCEPT_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NewEarlyDataTls13Config(EARLY_DATA_TEST_MAX);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    uint8_t earlyBuf[256] = {0};
    uint32_t earlyLen = 0;
    uint32_t status = HITLS_EARLY_DATA_NOT_SENT;
    ASSERT_TRUE(config != NULL);

    ASSERT_EQ(EarlyDataPrepareSession(config, config, &session), HITLS_SUCCESS);
    uint32_t sessMax = 0;
    ASSERT_EQ(HITLS_SESS_GetMaxEarlyData(session, &sessMax), HITLS_SUCCESS);
    ASSERT_EQ(sessMax, EARLY_DATA_TEST_MAX);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);

    ASSERT_EQ(EarlyDataRunHandshake(client, server, earlyBuf, sizeof(earlyBuf), &earlyLen), HITLS_SUCCESS);
    ASSERT_EQ(earlyLen, sizeof(g_earlyPayload));
    ASSERT_COMPARE("early data payload", earlyBuf, earlyLen, g_earlyPayload, sizeof(g_earlyPayload));

    ASSERT_EQ(HITLS_GetEarlyDataStatus(client->ssl, &status), HITLS_SUCCESS);
    ASSERT_EQ(status, HITLS_EARLY_DATA_ACCEPTED);
    ASSERT_EQ(HITLS_GetEarlyDataStatus(server->ssl, &status), HITLS_SUCCESS);
    ASSERT_EQ(status, HITLS_EARLY_DATA_ACCEPTED);

    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_TRUE(isReused);

    /* 1-RTT traffic still works in both directions */
    uint32_t ioLen = 0;
    uint8_t rdBuf[64] = {0};
    ASSERT_EQ(HITLS_Write(client->ssl, g_appPayload, sizeof(g_appPayload), &ioLen), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, rdBuf, sizeof(rdBuf), &ioLen), HITLS_SUCCESS);
    ASSERT_COMPARE("c2s app data", rdBuf, ioLen, g_appPayload, sizeof(g_appPayload));

    ASSERT_EQ(HITLS_Write(server->ssl, g_appPayload, sizeof(g_appPayload), &ioLen), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(client->ssl, rdBuf, sizeof(rdBuf), &ioLen), HITLS_SUCCESS);
    ASSERT_COMPARE("s2c app data", rdBuf, ioLen, g_appPayload, sizeof(g_appPayload));

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
}
/* END_CASE */

/** @
* @test     UT_TLS13_EARLY_DATA_CH_EXTENSION_FUNC_TC001
* @title    TLS1.3 0-RTT offer: the ClientHello carries an empty early_data extension.
* @brief    1. Establish a 0-RTT-capable session. Expect result 1.
*           2. Resume and call HITLS_WriteEarlyData; inspect the client's first flight. Expect result 2.
*           3. Resume WITHOUT early data; inspect the flight. Expect result 3.
* @expect   1. Session prepared.
*           2. The flight contains the empty early_data(42) extension.
*           3. The flight does not contain the early_data extension.
@ */
/* BEGIN_CASE */
void UT_TLS13_EARLY_DATA_CH_EXTENSION_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NewEarlyDataTls13Config(EARLY_DATA_TEST_MAX);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    uint32_t writtenLen = 0;
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(EarlyDataPrepareSession(config, config, &session), HITLS_SUCCESS);

    /* Offered: early_data extension present. The first call flushes the ClientHello flight and
     * stages the early record behind the busy one-message transport. */
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);
    int32_t wRet = HITLS_WriteEarlyData(client->ssl, g_earlyPayload, sizeof(g_earlyPayload), &writtenLen);
    ASSERT_TRUE(wRet == HITLS_SUCCESS || wRet == HITLS_REC_NORMAL_IO_BUSY);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(ioUserData != NULL && ioUserData->sndMsg.len > 0);
    ASSERT_TRUE(FlightContainsEmptyExtension(ioUserData->sndMsg.msg, ioUserData->sndMsg.len, 42u));
    FRAME_FreeLink(client);
    client = NULL;

    /* Not offered: no early_data extension */
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);
    ioUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(ioUserData != NULL && ioUserData->recMsg.len > 0);
    ASSERT_TRUE(!FlightContainsEmptyExtension(ioUserData->recMsg.msg, ioUserData->recMsg.len, 42u));

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
}
/* END_CASE */

/** @
* @test     UT_TLS13_EARLY_DATA_REJECT_SERVER_DISABLED_FUNC_TC001
* @title    TLS1.3 0-RTT reject: a server with 0-RTT disabled skips early data and completes.
* @brief    1. Establish a 0-RTT-capable session against an enabled server. Expect result 1.
*           2. Resume against a server with maxEarlyDataSize=0 and send early data. Expect result 2.
* @expect   1. Session prepared.
*           2. The handshake completes; early data is skipped; both sides report
*              HITLS_EARLY_DATA_REJECTED; the server reads no early data; 1-RTT data still flows.
@ */
/* BEGIN_CASE */
void UT_TLS13_EARLY_DATA_REJECT_SERVER_DISABLED_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NewEarlyDataTls13Config(EARLY_DATA_TEST_MAX);
    HITLS_Config *serverConfig = NewEarlyDataTls13Config(0);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    uint32_t writtenLen = 0;
    uint32_t status = HITLS_EARLY_DATA_NOT_SENT;
    ASSERT_TRUE(config != NULL && serverConfig != NULL);
    ASSERT_EQ(EarlyDataPrepareSession(config, config, &session), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);

    (void)writtenLen;
    uint8_t earlyBuf[256] = {0};
    uint32_t earlyLen = 0;
    ASSERT_EQ(EarlyDataWriteWithRetry(client, server, g_earlyPayload, sizeof(g_earlyPayload),
        earlyBuf, sizeof(earlyBuf), &earlyLen), HITLS_SUCCESS);

    /* The undecryptable early record must be skipped silently while the handshake completes */
    ASSERT_EQ(EarlyDataPump(client, server, earlyBuf, sizeof(earlyBuf), &earlyLen), HITLS_SUCCESS);
    ASSERT_EQ(earlyLen, 0);
    ASSERT_EQ(EarlyDataDeliverTickets(client, server), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_GetEarlyDataStatus(client->ssl, &status), HITLS_SUCCESS);
    ASSERT_EQ(status, HITLS_EARLY_DATA_REJECTED);
    ASSERT_EQ(HITLS_GetEarlyDataStatus(server->ssl, &status), HITLS_SUCCESS);
    ASSERT_EQ(status, HITLS_EARLY_DATA_REJECTED);

    /* 1-RTT traffic proves the rejected early records were skipped cleanly */
    uint32_t ioLen = 0;
    uint8_t rdBuf[64] = {0};
    ASSERT_EQ(HITLS_Write(client->ssl, g_appPayload, sizeof(g_appPayload), &ioLen), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, rdBuf, sizeof(rdBuf), &ioLen), HITLS_SUCCESS);
    ASSERT_COMPARE("app after reject", rdBuf, ioLen, g_appPayload, sizeof(g_appPayload));

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
}
/* END_CASE */

/** @
* @test     UT_TLS13_EARLY_DATA_NST_NO_TICKET_PERMISSION_FUNC_TC001
* @title    TLS1.3 0-RTT: tickets from a server without 0-RTT carry no early_data permission.
* @brief    1. Full handshake against a server with maxEarlyDataSize=0. Expect result 1.
*           2. Try to write early data when resuming. Expect result 2.
* @expect   1. The stored session reports max_early_data 0.
*           2. HITLS_WriteEarlyData fails with HITLS_MSG_HANDLE_EARLY_DATA_NOT_ALLOWED.
@ */
/* BEGIN_CASE */
void UT_TLS13_EARLY_DATA_NST_NO_TICKET_PERMISSION_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NewEarlyDataTls13Config(EARLY_DATA_TEST_MAX);
    HITLS_Config *plainServer = NewEarlyDataTls13Config(0);
    FRAME_LinkObj *client = NULL;
    HITLS_Session *session = NULL;
    uint32_t writtenLen = 0;
    ASSERT_TRUE(config != NULL && plainServer != NULL);

    ASSERT_EQ(EarlyDataPrepareSession(config, plainServer, &session), HITLS_SUCCESS);
    uint32_t sessMax = 12345;
    ASSERT_EQ(HITLS_SESS_GetMaxEarlyData(session, &sessMax), HITLS_SUCCESS);
    ASSERT_EQ(sessMax, 0);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_WriteEarlyData(client->ssl, g_earlyPayload, sizeof(g_earlyPayload), &writtenLen),
        HITLS_MSG_HANDLE_EARLY_DATA_NOT_ALLOWED);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_CFG_FreeConfig(plainServer);
    FRAME_FreeLink(client);
    HITLS_SESS_Free(session);
}
/* END_CASE */

/** @
* @test     UT_TLS13_EARLY_DATA_LIMIT_FUNC_TC001
* @title    TLS1.3 0-RTT: the client enforces the ticket's max_early_data_size.
* @brief    1. Establish a session whose ticket advertises a small max_early_data_size. Expect result 1.
*           2. Write within the limit, then beyond it. Expect result 2.
* @expect   1. Session prepared with max_early_data 16.
*           2. The first write succeeds; the write exceeding the limit fails with
*              HITLS_MSG_HANDLE_EARLY_DATA_LIMIT_EXCEEDED.
@ */
/* BEGIN_CASE */
void UT_TLS13_EARLY_DATA_LIMIT_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *smallConfig = NewEarlyDataTls13Config(16);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    uint8_t chunk[16] = {0};
    uint32_t writtenLen = 0;
    ASSERT_TRUE(smallConfig != NULL);
    ASSERT_EQ(EarlyDataPrepareSession(smallConfig, smallConfig, &session), HITLS_SUCCESS);

    client = FRAME_CreateLink(smallConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(smallConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);

    /* First call: the ClientHello flight occupies the one-message transport, so the call
     * reports busy and must be retried; the retries then complete the in-limit write. */
    uint8_t scratch[64] = {0};
    uint32_t scratchLen = 0;
    ASSERT_EQ(HITLS_WriteEarlyData(client->ssl, chunk, sizeof(chunk), &writtenLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(writtenLen, 0);
    ASSERT_EQ(EarlyDataWriteWithRetry(client, server, chunk, sizeof(chunk),
        scratch, sizeof(scratch), &scratchLen), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_WriteEarlyData(client->ssl, chunk, 1, &writtenLen),
        HITLS_MSG_HANDLE_EARLY_DATA_LIMIT_EXCEEDED);

EXIT:
    HITLS_CFG_FreeConfig(smallConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
}
/* END_CASE */

/** @
* @test     UT_TLS13_EARLY_DATA_API_MISUSE_FUNC_TC001
* @title    0-RTT API misuse: wrong role, no session, null input.
* @brief    1. Call the APIs with invalid parameters and roles. Expect result 1.
* @expect   1. Each call fails with the documented error code.
@ */
/* BEGIN_CASE */
void UT_TLS13_EARLY_DATA_API_MISUSE_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NewEarlyDataTls13Config(EARLY_DATA_TEST_MAX);
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    uint8_t buf[16] = {0};
    uint32_t outLen = 0;
    uint32_t status = 0;
    ASSERT_TRUE(config != NULL && client != NULL && server != NULL);

    ASSERT_EQ(HITLS_WriteEarlyData(NULL, buf, sizeof(buf), &outLen), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_ReadEarlyData(NULL, buf, sizeof(buf), &outLen), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_GetEarlyDataStatus(NULL, &status), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_GetEarlyDataStatus(client->ssl, NULL), HITLS_NULL_INPUT);

    /* A server cannot write early data; a client cannot read it */
    HITLS_SetEndPoint(server->ssl, false);
    ASSERT_EQ(HITLS_WriteEarlyData(server->ssl, buf, sizeof(buf), &outLen),
        HITLS_MSG_HANDLE_EARLY_DATA_NOT_ALLOWED);
    HITLS_SetEndPoint(client->ssl, true);
    ASSERT_EQ(HITLS_ReadEarlyData(client->ssl, buf, sizeof(buf), &outLen),
        HITLS_MSG_HANDLE_EARLY_DATA_NOT_ALLOWED);

    /* A client without a 0-RTT session cannot write early data */
    ASSERT_EQ(HITLS_WriteEarlyData(client->ssl, buf, sizeof(buf), &outLen),
        HITLS_MSG_HANDLE_EARLY_DATA_NOT_ALLOWED);

    /* Config get/set round-trip */
    uint32_t maxEarlyData = 0;
    ASSERT_EQ(HITLS_SetMaxEarlyDataSize(client->ssl, 4096), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_GetMaxEarlyDataSize(client->ssl, &maxEarlyData), HITLS_SUCCESS);
    ASSERT_EQ(maxEarlyData, 4096);
    ASSERT_EQ(HITLS_CFG_GetMaxEarlyDataSize(config, &maxEarlyData), HITLS_SUCCESS);
    ASSERT_EQ(maxEarlyData, EARLY_DATA_TEST_MAX);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS13_EARLY_DATA_HRR_REJECT_FUNC_TC001
* @title    TLS1.3 0-RTT: a HelloRetryRequest implicitly rejects early data.
* @brief    1. Establish a 0-RTT-capable session. Expect result 1.
*           2. Resume against a server that forces an HRR (disjoint first key-share group)
*              and write early data. Expect result 2.
* @expect   1. Session prepared.
*           2. The handshake completes over the HRR path, early data is rejected, and
*              1-RTT data still flows.
@ */
/* BEGIN_CASE */
void UT_TLS13_EARLY_DATA_HRR_REJECT_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NewEarlyDataTls13Config(EARLY_DATA_TEST_MAX);
    HITLS_Config *hrrServerConfig = NewEarlyDataTls13Config(EARLY_DATA_TEST_MAX);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    uint32_t writtenLen = 0;
    uint32_t status = HITLS_EARLY_DATA_NOT_SENT;
    uint16_t clientGroups[] = {HITLS_EC_GROUP_CURVE25519, HITLS_EC_GROUP_SECP256R1};
    uint16_t serverGroups[] = {HITLS_EC_GROUP_SECP256R1};
    ASSERT_TRUE(config != NULL && hrrServerConfig != NULL);
    ASSERT_EQ(EarlyDataPrepareSession(config, config, &session), HITLS_SUCCESS);

    /* Client key-shares only its first group; the server accepts only the second: HRR */
    ASSERT_EQ(HITLS_CFG_SetGroups(config, clientGroups, sizeof(clientGroups) / sizeof(uint16_t)), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetGroups(hrrServerConfig, serverGroups, sizeof(serverGroups) / sizeof(uint16_t)),
        HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    server = FRAME_CreateLink(hrrServerConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);

    (void)writtenLen;
    uint8_t scratch[256] = {0};
    uint32_t scratchLen = 0;
    ASSERT_EQ(EarlyDataWriteWithRetry(client, server, g_earlyPayload, sizeof(g_earlyPayload),
        scratch, sizeof(scratch), &scratchLen), HITLS_SUCCESS);
    /* The server answered the first ClientHello with an HRR; the early record still on the
     * wire must be dropped in front of the second ClientHello while the pump finishes */
    ASSERT_EQ(EarlyDataPump(client, server, scratch, sizeof(scratch), &scratchLen), HITLS_SUCCESS);
    ASSERT_EQ(scratchLen, 0);
    ASSERT_EQ(EarlyDataDeliverTickets(client, server), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_GetEarlyDataStatus(client->ssl, &status), HITLS_SUCCESS);
    ASSERT_EQ(status, HITLS_EARLY_DATA_REJECTED);
    ASSERT_EQ(HITLS_GetEarlyDataStatus(server->ssl, &status), HITLS_SUCCESS);
    ASSERT_EQ(status, HITLS_EARLY_DATA_REJECTED);

    uint32_t ioLen = 0;
    uint8_t rdBuf[64] = {0};
    ASSERT_EQ(HITLS_Write(client->ssl, g_appPayload, sizeof(g_appPayload), &ioLen), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, rdBuf, sizeof(rdBuf), &ioLen), HITLS_SUCCESS);
    ASSERT_COMPARE("app after HRR reject", rdBuf, ioLen, g_appPayload, sizeof(g_appPayload));

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_CFG_FreeConfig(hrrServerConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
}
/* END_CASE */

/** @
* @test     UT_TLS13_EARLY_DATA_TICKET_AGE_FUNC_TC001
* @title    TLS1.3 0-RTT anti-replay: a stale obfuscated_ticket_age is rejected.
* @brief    1. Establish a 0-RTT-capable session. Expect result 1.
*           2. Shift the client's view of the ticket issue time by 60 seconds and resume with
*              early data. Expect result 2.
* @expect   1. Session prepared.
*           2. The server rejects the early data (freshness window exceeded) but the
*              handshake still completes as a normal resumption.
@ */
/* BEGIN_CASE */
void UT_TLS13_EARLY_DATA_TICKET_AGE_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NewEarlyDataTls13Config(EARLY_DATA_TEST_MAX);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    uint32_t writtenLen = 0;
    uint32_t status = HITLS_EARLY_DATA_NOT_SENT;
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(EarlyDataPrepareSession(config, config, &session), HITLS_SUCCESS);

    /* The client believes the ticket is 60s older than the server does */
    ASSERT_EQ(SESS_SetStartTime(session, SESS_GetStartTime(session) - 60), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);

    (void)writtenLen;
    uint8_t scratch[256] = {0};
    uint32_t scratchLen = 0;
    ASSERT_EQ(EarlyDataWriteWithRetry(client, server, g_earlyPayload, sizeof(g_earlyPayload),
        scratch, sizeof(scratch), &scratchLen), HITLS_SUCCESS);
    /* The server already saw the stale ticket age and rejected; the pump finishes the rest */
    ASSERT_EQ(EarlyDataPump(client, server, scratch, sizeof(scratch), &scratchLen), HITLS_SUCCESS);
    ASSERT_EQ(scratchLen, 0);
    ASSERT_EQ(EarlyDataDeliverTickets(client, server), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_GetEarlyDataStatus(server->ssl, &status), HITLS_SUCCESS);
    ASSERT_EQ(status, HITLS_EARLY_DATA_REJECTED);
    ASSERT_EQ(HITLS_GetEarlyDataStatus(client->ssl, &status), HITLS_SUCCESS);
    ASSERT_EQ(status, HITLS_EARLY_DATA_REJECTED);

    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_TRUE(isReused);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
}
/* END_CASE */

/** @
* @test     UT_TLS13_EARLY_DATA_ALPN_MISMATCH_FUNC_TC001
* @title    TLS1.3 0-RTT: an ALPN change between connections blocks the 0-RTT offer.
* @brief    1. Establish a 0-RTT session with ALPN "h2". Expect result 1.
*           2. Resume with an ALPN list that no longer contains "h2" and try to write
*              early data. Expect result 2.
* @expect   1. Session prepared with ALPN "h2".
*           2. HITLS_WriteEarlyData fails with HITLS_MSG_HANDLE_EARLY_DATA_NOT_ALLOWED.
@ */
/* BEGIN_CASE */
void UT_TLS13_EARLY_DATA_ALPN_MISMATCH_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NewEarlyDataTls13Config(EARLY_DATA_TEST_MAX);
    FRAME_LinkObj *client = NULL;
    HITLS_Session *session = NULL;
    uint32_t writtenLen = 0;
    /* ALPN wire format: 1-byte length + protocol name */
    uint8_t alpnH2[] = {2, 'h', '2'};
    uint8_t alpnHttp11[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetAlpnProtos(config, alpnH2, sizeof(alpnH2)), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetAlpnProtosSelectCb(config, EarlyDataAlpnSelectFirst, NULL), HITLS_SUCCESS);
    ASSERT_EQ(EarlyDataPrepareSession(config, config, &session), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_CFG_SetAlpnProtos(config, alpnHttp11, sizeof(alpnHttp11)), HITLS_SUCCESS);
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_WriteEarlyData(client->ssl, g_earlyPayload, sizeof(g_earlyPayload), &writtenLen),
        HITLS_MSG_HANDLE_EARLY_DATA_NOT_ALLOWED);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    HITLS_SESS_Free(session);
}
/* END_CASE */

/** @
* @test     UT_DTLS13_EARLY_DATA_ACCEPT_FUNC_TC001
* @title    DTLS1.3 0-RTT accept: early data flows at epoch 1 without EndOfEarlyData.
* @brief    1. Full DTLS1.3 handshake with 0-RTT enabled; take the session. Expect result 1.
*           2. Resume, write early data, and drive the exchange manually. Expect result 2.
* @expect   1. The session's ticket advertises max_early_data_size.
*           2. The server reads the early payload, both sides report ACCEPTED, and the
*              handshake completes without an EndOfEarlyData message.
@ */
/* BEGIN_CASE */
void UT_DTLS13_EARLY_DATA_ACCEPT_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    uint8_t earlyBuf[256] = {0};
    uint32_t earlyLen = 0;
    uint32_t got = 0;
    uint32_t writtenLen = 0;
    uint32_t status = HITLS_EARLY_DATA_NOT_SENT;
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetMaxEarlyDataSize(config, EARLY_DATA_TEST_MAX), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL);
    uint32_t sessMax = 0;
    ASSERT_EQ(HITLS_SESS_GetMaxEarlyData(session, &sessMax), HITLS_SUCCESS);
    ASSERT_EQ(sessMax, EARLY_DATA_TEST_MAX);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    client = NULL;
    server = NULL;

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);
    /* The resumption ClientHello (ticket + binder) must fit one datagram of the one-message
     * FRAME transport: raise the MTU so it is not fragmented */
    ASSERT_EQ(HITLS_SetMtu(client->ssl, 16000), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetMtu(server->ssl, 16000), HITLS_SUCCESS);

    /* ClientHello, then the epoch-1 early record */
    (void)writtenLen;
    (void)got;
    ASSERT_EQ(EarlyDataWriteWithRetry(client, server, g_earlyPayload, sizeof(g_earlyPayload),
        earlyBuf, sizeof(earlyBuf), &earlyLen), HITLS_SUCCESS);

    /* Ping-pong to completion; the server reads the epoch-1 data along the way */
    ASSERT_EQ(EarlyDataPump(client, server, earlyBuf, sizeof(earlyBuf), &earlyLen), HITLS_SUCCESS);
    int32_t ret = EarlyDataDrainServer(server, earlyBuf, sizeof(earlyBuf), &earlyLen);
    ASSERT_EQ(ret, HITLS_READ_EARLY_DATA_FINISH);

    ASSERT_EQ(earlyLen, sizeof(g_earlyPayload));
    ASSERT_COMPARE("dtls early data", earlyBuf, earlyLen, g_earlyPayload, sizeof(g_earlyPayload));

    ASSERT_EQ(HITLS_GetEarlyDataStatus(client->ssl, &status), HITLS_SUCCESS);
    ASSERT_EQ(status, HITLS_EARLY_DATA_ACCEPTED);
    ASSERT_EQ(HITLS_GetEarlyDataStatus(server->ssl, &status), HITLS_SUCCESS);
    ASSERT_EQ(status, HITLS_EARLY_DATA_ACCEPTED);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
}
/* END_CASE */

/** @
* @test     UT_DTLS13_EARLY_DATA_REJECT_FUNC_TC001
* @title    DTLS1.3 0-RTT reject: epoch-1 records are dropped silently.
* @brief    1. Establish a DTLS1.3 0-RTT session. Expect result 1.
*           2. Resume against a server with 0-RTT disabled, send early data. Expect result 2.
* @expect   1. Session prepared.
*           2. The handshake completes, both sides report REJECTED, no early data is read.
@ */
/* BEGIN_CASE */
void UT_DTLS13_EARLY_DATA_REJECT_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewDTLS13Config();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    uint32_t writtenLen = 0;
    uint32_t status = HITLS_EARLY_DATA_NOT_SENT;
    ASSERT_TRUE(config != NULL && serverConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetMaxEarlyDataSize(config, EARLY_DATA_TEST_MAX), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetMaxEarlyDataSize(serverConfig, 0), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    client = NULL;
    server = NULL;

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetMtu(client->ssl, 16000), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetMtu(server->ssl, 16000), HITLS_SUCCESS);

    (void)writtenLen;
    uint8_t scratch[256] = {0};
    uint32_t scratchLen = 0;
    ASSERT_EQ(EarlyDataWriteWithRetry(client, server, g_earlyPayload, sizeof(g_earlyPayload),
        scratch, sizeof(scratch), &scratchLen), HITLS_SUCCESS);
    /* The epoch-1 record still on the wire must be discarded silently by the server */
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(scratchLen, 0);

    ASSERT_EQ(HITLS_GetEarlyDataStatus(client->ssl, &status), HITLS_SUCCESS);
    ASSERT_EQ(status, HITLS_EARLY_DATA_REJECTED);
    ASSERT_EQ(HITLS_GetEarlyDataStatus(server->ssl, &status), HITLS_SUCCESS);
    ASSERT_EQ(status, HITLS_EARLY_DATA_REJECTED);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
}
/* END_CASE */
