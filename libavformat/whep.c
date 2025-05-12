/*
 * WebRTC-HTTP Egress protocol (WHEP) demuxer
 * Copyright (c) 2023 The FFmpeg Project
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "libavcodec/avcodec.h"
#include "libavcodec/h264.h"
#include "libavcodec/startcode.h"
#include "libavutil/base64.h"
#include "libavutil/bprint.h"
#include "libavutil/crc.h"
#include "libavutil/hmac.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/lfg.h"
#include "libavutil/opt.h"
#include "libavutil/random_seed.h"
#include "libavutil/time.h"
#include "libavutil/parseutils.h"
#include "avc.h"
#include "avio_internal.h"
#include "http.h"
#include "internal.h"
#include "demux.h"
#include "rtpdec.h"
#include "network.h"
#include "srtp.h"
#include "avformat.h"

/**
 * Maximum size limit of a Session Description Protocol (SDP),
 * be it an offer or answer.
 */
#define MAX_SDP_SIZE 16384

/**
 * Maximum size limit of a certificate and private key size.
 */
#define MAX_CERTIFICATE_SIZE 8192

/**
 * Maximum size of the buffer for sending and receiving UDP packets.
 * Please note that this size does not limit the size of the UDP packet that can be sent.
 * To set the limit for packet size, modify the `pkt_size` parameter.
 * For instance, it is possible to set the UDP buffer to 4096 to send or receive packets,
 * but please keep in mind that the `pkt_size` option limits the packet size to 1400.
 */
#define MAX_UDP_BUFFER_SIZE 40960

/**
 * The size of the Secure Real-time Transport Protocol (SRTP) master key material
 * that is exported by Secure Sockets Layer (SSL) after a successful Datagram
 * Transport Layer Security (DTLS) handshake. This material consists of a key
 * of 16 bytes and a salt of 14 bytes.
 */
#define DTLS_SRTP_KEY_LEN 16
#define DTLS_SRTP_SALT_LEN 14

/**
 * The maximum size of the Secure Real-time Transport Protocol (SRTP) HMAC checksum
 * and padding that is appended to the end of the packet. To calculate the maximum
 * size of the User Datagram Protocol (UDP) packet that can be sent out, subtract
 * this size from the `pkt_size`.
 */
#define DTLS_SRTP_CHECKSUM_LEN 16

/**
 * When sending ICE or DTLS messages, responses are received via UDP. However, the peer
 * may not be ready and return EAGAIN, in which case we should wait for a short duration
 * and retry reading.
 * For instance, if we try to read from UDP and get EAGAIN, we sleep for 5ms and retry.
 * This macro is used to limit the total duration in milliseconds (e.g., 50ms), so we
 * will try at most 5 times.
 * Keep in mind that this macro should have a minimum duration of 5 ms.
 */
#define ICE_DTLS_READ_INTERVAL 50

/* The magic cookie for Session Traversal Utilities for NAT (STUN) messages. */
#define STUN_MAGIC_COOKIE 0x2112A442

/**
 * The DTLS content type.
 * See https://tools.ietf.org/html/rfc2246#section-6.2.1
 * change_cipher_spec(20), alert(21), handshake(22), application_data(23)
 */
#define DTLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC 20

/**
 * The DTLS record layer header has a total size of 13 bytes, consisting of
 * ContentType (1 byte), ProtocolVersion (2 bytes), Epoch (2 bytes),
 * SequenceNumber (6 bytes), and Length (2 bytes).
 * See https://datatracker.ietf.org/doc/html/rfc9147#section-4
 */
#define DTLS_RECORD_LAYER_HEADER_LEN 13

/**
 * The DTLS version number, which is 0xfeff for DTLS 1.0, or 0xfefd for DTLS 1.2.
 * See https://datatracker.ietf.org/doc/html/rfc9147#name-the-dtls-record-layer
 */
#define DTLS_VERSION_10 0xfeff
#define DTLS_VERSION_12 0xfefd

/* Referring to Chrome's definition of RTP payload types. */
#define WHEP_RTP_PAYLOAD_TYPE_H264 106
#define WHEP_RTP_PAYLOAD_TYPE_OPUS 111

/**
 * The STUN message header, which is 20 bytes long, comprises the
 * STUNMessageType (1B), MessageLength (2B), MagicCookie (4B),
 * and TransactionID (12B).
 * See https://datatracker.ietf.org/doc/html/rfc5389#section-6
 */
#define ICE_STUN_HEADER_SIZE 20

/**
 * The RTP header is 12 bytes long, comprising the Version(1B), PT(1B),
 * SequenceNumber(2B), Timestamp(4B), and SSRC(4B).
 * See https://www.rfc-editor.org/rfc/rfc3550#section-5.1
 */
#define WHEP_RTP_HEADER_SIZE 12

/**
 * For RTCP, PT is [128, 223] (or without marker [0, 95]). Literally, RTCP starts
 * from 64 not 0, so PT is [192, 223] (or without marker [64, 95]), see "RTCP Control
 * Packet Types (PT)" at
 * https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml#rtp-parameters-4
 *
 * For RTP, the PT is [96, 127], or [224, 255] with marker. See "RTP Payload Types (PT)
 * for standard audio and video encodings" at
 * https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml#rtp-parameters-1
 */
#define WHEP_RTCP_PT_START 192
#define WHEP_RTCP_PT_END   223

/**
 * In the case of ICE-LITE, these fields are not used; instead, they are defined
 * as constant values.
 */
#define WHEP_SDP_SESSION_ID "4489045141692799359"
#define WHEP_SDP_CREATOR_IP "127.0.0.1"

#define WHEP_DEFAULT_AUDIO_SAMPLERATE 44100

/* Calculate the elapsed time from starttime to endtime in milliseconds. */
#define ELAPSED(starttime, endtime) ((int)(endtime - starttime) / 1000)

/**
 * Read all data from the given URL url and store it in the given buffer bp.
 */
static int url_read_all(AVFormatContext *s, const char *url, AVBPrint *bp)
{
    int ret = 0;
    AVDictionary *opts = NULL;
    URLContext *uc = NULL;
    char buf[MAX_URL_SIZE];

    ret = ffurl_open_whitelist(&uc, url, AVIO_FLAG_READ, &s->interrupt_callback,
        &opts, s->protocol_whitelist, s->protocol_blacklist, NULL);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "WHEP: Failed to open url %s\n", url);
        goto end;
    }

    while (1) {
        ret = ffurl_read(uc, buf, sizeof(buf));
        if (ret == AVERROR_EOF) {
            /* Reset the error because we read all response as answer util EOF. */
            ret = 0;
            break;
        }
        if (ret <= 0) {
            av_log(s, AV_LOG_ERROR, "WHEP: Failed to read from url=%s, key is %s\n", url, bp->str);
            goto end;
        }

        av_bprintf(bp, "%.*s", ret, buf);
        if (!av_bprint_is_complete(bp)) {
            av_log(s, AV_LOG_ERROR, "WHEP: Exceed max size %.*s, %s\n", ret, buf, bp->str);
            ret = AVERROR(EIO);
            goto end;
        }
    }

end:
    ffurl_closep(&uc);
    av_dict_free(&opts);
    return ret;
}

/* STUN Attribute, comprehension-required range (0x0000-0x7FFF) */
enum STUNAttr {
    STUN_ATTR_USERNAME                  = 0x0006, /// shared secret response/bind request
    STUN_ATTR_PRIORITY                  = 0x0024, /// bind request/response
    STUN_ATTR_USE_CANDIDATE             = 0x0025, /// bind request
    STUN_ATTR_MESSAGE_INTEGRITY         = 0x0008, /// bind request/response
    STUN_ATTR_FINGERPRINT               = 0x8028, /// rfc5389
};

enum DTLSState {
    DTLS_STATE_NONE,

    /* Whether DTLS handshake is finished. */
    DTLS_STATE_FINISHED,
    /* Whether DTLS session is closed. */
    DTLS_STATE_CLOSED,
    /* Whether DTLS handshake is failed. */
    DTLS_STATE_FAILED,
};

typedef struct DTLSContext DTLSContext;
typedef int (*DTLSContext_on_state_fn)(DTLSContext *ctx, enum DTLSState state, const char* type, const char* desc);
typedef int (*DTLSContext_on_write_fn)(DTLSContext *ctx, char* data, int size);

typedef struct DTLSContext {
    AVClass *av_class;

    /* For callback. */
    DTLSContext_on_state_fn on_state;
    DTLSContext_on_write_fn on_write;
    void* opaque;

    /* For logging. */
    AVClass *log_avcl;

    /* The DTLS context. */
    SSL_CTX *dtls_ctx;
    SSL *dtls;
    /* The DTLS BIOs. */
    BIO *bio_in;

    /* The private key for DTLS handshake. */
    EVP_PKEY *dtls_pkey;
    /* The EC key for DTLS handshake. */
    EC_KEY* dtls_eckey;
    /* The SSL certificate used for fingerprint in SDP and DTLS handshake. */
    X509 *dtls_cert;
    /* The fingerprint of certificate, used in SDP offer. */
    char *dtls_fingerprint;

    /**
     * This represents the material used to build the SRTP master key. It is
     * generated by DTLS and has the following layout:
     *          16B         16B         14B             14B
     *      client_key | server_key | client_salt | server_salt
     */
    uint8_t dtls_srtp_materials[(DTLS_SRTP_KEY_LEN + DTLS_SRTP_SALT_LEN) * 2];

    /* Whether the DTLS is done at least for us. */
    int dtls_done_for_us;
    /* Whether the SRTP key is exported. */
    int dtls_srtp_key_exported;
    /* The number of packets retransmitted for DTLS. */
    int dtls_arq_packets;
    /**
     * This is the last DTLS content type and handshake type that is used to detect
     * the ARQ packet.
     */
    uint8_t dtls_last_content_type;
    uint8_t dtls_last_handshake_type;

    /* These variables represent timestamps used for calculating and tracking the cost. */
    int64_t dtls_init_starttime;
    int64_t dtls_init_endtime;
    int64_t dtls_handshake_starttime;
    int64_t dtls_handshake_endtime;

    /* Helper for get error code and message. */
    int error_code;
    char error_message[256];

    /* The certificate and private key used for DTLS handshake. */
    char* cert_file;
    char* key_file;
    /**
     * The size of RTP packet, should generally be set to MTU.
     * Note that pion requires a smaller value, for example, 1200.
     */
    int mtu;
} DTLSContext;

/**
 * Whether the packet is a DTLS packet.
 */
static int is_dtls_packet(uint8_t *b, int size) {
    uint16_t version = AV_RB16(&b[1]);
    return size > DTLS_RECORD_LAYER_HEADER_LEN &&
        b[0] >= DTLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC &&
        (version == DTLS_VERSION_10 || version == DTLS_VERSION_12);
}

/**
 * Retrieves the error message for the latest OpenSSL error.
 *
 * This function retrieves the error code from the thread's error queue, converts it
 * to a human-readable string, and stores it in the DTLSContext's error_message field.
 * The error queue is then cleared using ERR_clear_error().
 */
static const char* openssl_get_error(DTLSContext *ctx)
{
    int r2 = ERR_get_error();
    if (r2)
        ERR_error_string_n(r2, ctx->error_message, sizeof(ctx->error_message));
    else
        ctx->error_message[0] = '\0';

    ERR_clear_error();
    return ctx->error_message;
}

/**
 * Get the error code for the given SSL operation result.
 *
 * This function retrieves the error code for the given SSL operation result
 * and stores the error message in the DTLS context if an error occurred.
 * It also clears the error queue.
 */
static int openssl_ssl_get_error(DTLSContext *ctx, int ret)
{
    SSL *dtls = ctx->dtls;
    int r1 = SSL_ERROR_NONE;

    if (ret <= 0)
        r1 = SSL_get_error(dtls, ret);

    openssl_get_error(ctx);
    return r1;
}

/**
 * Callback function to print the OpenSSL SSL status.
 */
static void openssl_dtls_on_info(const SSL *dtls, int where, int r0)
{
    int w, r1, is_fatal, is_warning, is_close_notify;
    const char *method = "undefined", *alert_type, *alert_desc;
    enum DTLSState state;
    DTLSContext *ctx = (DTLSContext*)SSL_get_ex_data(dtls, 0);

    w = where & ~SSL_ST_MASK;
    if (w & SSL_ST_CONNECT)
        method = "SSL_connect";
    else if (w & SSL_ST_ACCEPT)
        method = "SSL_accept";

    r1 = openssl_ssl_get_error(ctx, r0);
    if (where & SSL_CB_LOOP) {
        av_log(ctx, AV_LOG_VERBOSE, "DTLS: Info method=%s state=%s(%s), where=%d, ret=%d, r1=%d\n",
            method, SSL_state_string(dtls), SSL_state_string_long(dtls), where, r0, r1);
    } else if (where & SSL_CB_ALERT) {
        method = (where & SSL_CB_READ) ? "read":"write";

        alert_type = SSL_alert_type_string_long(r0);
        alert_desc = SSL_alert_desc_string(r0);

        if (!av_strcasecmp(alert_type, "warning") && !av_strcasecmp(alert_desc, "CN"))
            av_log(ctx, AV_LOG_WARNING, "DTLS: SSL3 alert method=%s type=%s, desc=%s(%s), where=%d, ret=%d, r1=%d\n",
                method, alert_type, alert_desc, SSL_alert_desc_string_long(r0), where, r0, r1);
        else
            av_log(ctx, AV_LOG_ERROR, "DTLS: SSL3 alert method=%s type=%s, desc=%s(%s), where=%d, ret=%d, r1=%d %s\n",
                method, alert_type, alert_desc, SSL_alert_desc_string_long(r0), where, r0, r1, ctx->error_message);

        /**
         * Notify the DTLS to handle the ALERT message, which maybe means media connection disconnect.
         * CN(Close Notify) is sent when peer close the PeerConnection. fatal, IP(Illegal Parameter)
         * is sent when DTLS failed.
         */
        is_fatal = !av_strncasecmp(alert_type, "fatal", 5);
        is_warning = !av_strncasecmp(alert_type, "warning", 7);
        is_close_notify = !av_strncasecmp(alert_desc, "CN", 2);
        state = is_fatal ? DTLS_STATE_FAILED : (is_warning && is_close_notify ? DTLS_STATE_CLOSED : DTLS_STATE_NONE);
        if (state != DTLS_STATE_NONE && ctx->on_state) {
            av_log(ctx, AV_LOG_INFO, "DTLS: Notify ctx=%p, state=%d, fatal=%d, warning=%d, cn=%d\n",
                ctx, state, is_fatal, is_warning, is_close_notify);
            ctx->on_state(ctx, state, alert_type, alert_desc);
        }
    } else if (where & SSL_CB_EXIT) {
        if (!r0)
            av_log(ctx, AV_LOG_WARNING, "DTLS: Fail method=%s state=%s(%s), where=%d, ret=%d, r1=%d\n",
                method, SSL_state_string(dtls), SSL_state_string_long(dtls), where, r0, r1);
        else if (r0 < 0)
            if (r1 != SSL_ERROR_NONE && r1 != SSL_ERROR_WANT_READ && r1 != SSL_ERROR_WANT_WRITE)
                av_log(ctx, AV_LOG_ERROR, "DTLS: Error method=%s state=%s(%s), where=%d, ret=%d, r1=%d %s\n",
                    method, SSL_state_string(dtls), SSL_state_string_long(dtls), where, r0, r1, ctx->error_message);
            else
                av_log(ctx, AV_LOG_VERBOSE, "DTLS: Info method=%s state=%s(%s), where=%d, ret=%d, r1=%d\n",
                    method, SSL_state_string(dtls), SSL_state_string_long(dtls), where, r0, r1);
    }
}

static void openssl_dtls_state_trace(DTLSContext *ctx, uint8_t *data, int length, int incoming)
{
    uint8_t content_type = 0;
    uint16_t size = 0;
    uint8_t handshake_type = 0;

    /* Change_cipher_spec(20), alert(21), handshake(22), application_data(23) */
    if (length >= 1)
        content_type = AV_RB8(&data[0]);
    if (length >= 13)
        size = AV_RB16(&data[11]);
    if (length >= 14)
        handshake_type = AV_RB8(&data[13]);

    av_log(ctx, AV_LOG_VERBOSE, "DTLS: Trace %s, done=%u, arq=%u, len=%u, cnt=%u, size=%u, hs=%u\n",
        (incoming? "RECV":"SEND"), ctx->dtls_done_for_us, ctx->dtls_arq_packets, length,
        content_type, size, handshake_type);
}

/**
 * Always return 1 to accept any certificate. This is because we allow the peer to
 * use a temporary self-signed certificate for DTLS.
 */
static int openssl_dtls_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    return 1;
}

/**
 * DTLS BIO read callback.
 */
#if OPENSSL_VERSION_NUMBER < 0x30000000L // v3.0.x
static long openssl_dtls_bio_out_callback(BIO* b, int oper, const char* argp, int argi, long argl, long retvalue)
#else
static long openssl_dtls_bio_out_callback_ex(BIO *b, int oper, const char *argp, size_t len, int argi, long argl, int retvalue, size_t *processed)
#endif
{
    int ret, req_size = argi, is_arq = 0;
    uint8_t content_type, handshake_type;
    uint8_t *data = (uint8_t*)argp;
    DTLSContext* ctx = b ? (DTLSContext*)BIO_get_callback_arg(b) : NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L // v3.0.x
    req_size = len;
    av_log(ctx, AV_LOG_DEBUG, "DTLS: BIO callback b=%p, oper=%d, argp=%p, len=%ld, argi=%d, argl=%ld, retvalue=%d, processed=%p, req_size=%d\n",
        b, oper, argp, len, argi, argl, retvalue, processed, req_size);
#else
    av_log(ctx, AV_LOG_DEBUG, "DTLS: BIO callback b=%p, oper=%d, argp=%p, argi=%d, argl=%ld, retvalue=%ld, req_size=%d\n",
        b, oper, argp, argi, argl, retvalue, req_size);
#endif

    if (oper != BIO_CB_WRITE || !argp || req_size <= 0)
        return retvalue;

    openssl_dtls_state_trace(ctx, data, req_size, 0);
    ret = ctx->on_write ? ctx->on_write(ctx, data, req_size) : 0;
    content_type = req_size > 0 ? AV_RB8(&data[0]) : 0;
    handshake_type = req_size > 13 ? AV_RB8(&data[13]) : 0;

    is_arq = ctx->dtls_last_content_type == content_type && ctx->dtls_last_handshake_type == handshake_type;
    ctx->dtls_arq_packets += is_arq;
    ctx->dtls_last_content_type = content_type;
    ctx->dtls_last_handshake_type = handshake_type;

    if (ret < 0) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Send request failed, oper=%d, content=%d, handshake=%d, size=%d, is_arq=%d\n",
            oper, content_type, handshake_type, req_size, is_arq);
        return ret;
    }

    return retvalue;
}

static int openssl_read_certificate(AVFormatContext *s, DTLSContext *ctx)
{
    int ret = 0;
    BIO *key_b = NULL, *cert_b = NULL;
    AVBPrint key_bp, cert_bp;

    /* To prevent a crash during cleanup, always initialize it. */
    av_bprint_init(&key_bp, 1, MAX_CERTIFICATE_SIZE);
    av_bprint_init(&cert_bp, 1, MAX_CERTIFICATE_SIZE);

    /* Read key file. */
    ret = url_read_all(s, ctx->key_file, &key_bp);
    if (ret < 0) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to open key file %s\n", ctx->key_file);
        goto end;
    }

    if ((key_b = BIO_new(BIO_s_mem())) == NULL) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    BIO_write(key_b, key_bp.str, key_bp.len);
    ctx->dtls_pkey = PEM_read_bio_PrivateKey(key_b, NULL, NULL, NULL);
    if (!ctx->dtls_pkey) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to read private key from %s\n", ctx->key_file);
        ret = AVERROR(EIO);
        goto end;
    }

    /* Read certificate. */
    ret = url_read_all(s, ctx->cert_file, &cert_bp);
    if (ret < 0) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to open cert file %s\n", ctx->cert_file);
        goto end;
    }

    if ((cert_b = BIO_new(BIO_s_mem())) == NULL) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    BIO_write(cert_b, cert_bp.str, cert_bp.len);
    ctx->dtls_cert = PEM_read_bio_X509(cert_b, NULL, NULL, NULL);
    if (!ctx->dtls_cert) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to read certificate from %s\n", ctx->cert_file);
        ret = AVERROR(EIO);
        goto end;
    }

end:
    BIO_free(key_b);
    av_bprint_finalize(&key_bp, NULL);
    BIO_free(cert_b);
    av_bprint_finalize(&cert_bp, NULL);
    return ret;
}

static int openssl_dtls_gen_private_key(DTLSContext *ctx)
{
    int ret = 0;

    /**
     * Note that secp256r1 in openssl is called NID_X9_62_prime256v1 or prime256v1 in string,
     * not NID_secp256k1 or secp256k1 in string.
     *
     * TODO: Should choose the curves in ClientHello.supported_groups, for example:
     *      Supported Group: x25519 (0x001d)
     *      Supported Group: secp256r1 (0x0017)
     *      Supported Group: secp384r1 (0x0018)
     */
#if OPENSSL_VERSION_NUMBER < 0x30000000L /* OpenSSL 3.0 */
    EC_GROUP *ecgroup = NULL;
    int curve = NID_X9_62_prime256v1;
#else
    const char *curve = SN_X9_62_prime256v1;
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L /* OpenSSL 3.0 */
    ctx->dtls_pkey = EVP_PKEY_new();
    ctx->dtls_eckey = EC_KEY_new();
    ecgroup = EC_GROUP_new_by_curve_name(curve);
    if (!ecgroup) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Create EC group by curve=%d failed, %s", curve, openssl_get_error(ctx));
        goto einval_end;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L // v1.1.x
    /* For openssl 1.0, we must set the group parameters, so that cert is ok. */
    EC_GROUP_set_asn1_flag(ecgroup, OPENSSL_EC_NAMED_CURVE);
#endif

    if (EC_KEY_set_group(ctx->dtls_eckey, ecgroup) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Generate private key, EC_KEY_set_group failed, %s\n", openssl_get_error(ctx));
        goto einval_end;
    }

    if (EC_KEY_generate_key(ctx->dtls_eckey) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Generate private key, EC_KEY_generate_key failed, %s\n", openssl_get_error(ctx));
        goto einval_end;
    }

    if (EVP_PKEY_set1_EC_KEY(ctx->dtls_pkey, ctx->dtls_eckey) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Generate private key, EVP_PKEY_set1_EC_KEY failed, %s\n", openssl_get_error(ctx));
        goto einval_end;
    }
#else
    ctx->dtls_pkey = EVP_EC_gen(curve);
    if (!ctx->dtls_pkey) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Generate private key, EVP_EC_gen curve=%s failed, %s\n", curve, openssl_get_error(ctx));
        goto einval_end;
    }
#endif
    goto end;

einval_end:
    ret = AVERROR(EINVAL);
end:
#if OPENSSL_VERSION_NUMBER < 0x30000000L /* OpenSSL 3.0 */
    EC_GROUP_free(ecgroup);
#endif
    return ret;
}

static int openssl_dtls_gen_certificate(DTLSContext *ctx)
{
    int ret = 0, serial, expire_day, i, n = 0;
    AVBPrint fingerprint;
    unsigned char md[EVP_MAX_MD_SIZE];
    const char *aor = "lavf";
    X509_NAME* subject = NULL;
    X509 *dtls_cert = NULL;

    /* To prevent a crash during cleanup, always initialize it. */
    av_bprint_init(&fingerprint, 1, MAX_URL_SIZE);

    dtls_cert = ctx->dtls_cert = X509_new();
    if (!dtls_cert) {
        goto enomem_end;
    }

    // TODO: Support non-self-signed certificate, for example, load from a file.
    subject = X509_NAME_new();
    if (!subject) {
        goto enomem_end;
    }

    serial = (int)av_get_random_seed();
    if (ASN1_INTEGER_set(X509_get_serialNumber(dtls_cert), serial) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to set serial, %s\n", openssl_get_error(ctx));
        goto einval_end;
    }

    if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, aor, strlen(aor), -1, 0) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to set CN, %s\n", openssl_get_error(ctx));
        goto einval_end;
    }

    if (X509_set_issuer_name(dtls_cert, subject) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to set issuer, %s\n", openssl_get_error(ctx));
        goto einval_end;
    }
    if (X509_set_subject_name(dtls_cert, subject) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to set subject name, %s\n", openssl_get_error(ctx));
        goto einval_end;
    }

    expire_day = 365;
    if (!X509_gmtime_adj(X509_get_notBefore(dtls_cert), 0)) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to set notBefore, %s\n", openssl_get_error(ctx));
        goto einval_end;
    }
    if (!X509_gmtime_adj(X509_get_notAfter(dtls_cert), 60*60*24*expire_day)) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to set notAfter, %s\n", openssl_get_error(ctx));
        goto einval_end;
    }

    if (X509_set_version(dtls_cert, 2) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to set version, %s\n", openssl_get_error(ctx));
        goto einval_end;
    }

    if (X509_set_pubkey(dtls_cert, ctx->dtls_pkey) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to set public key, %s\n", openssl_get_error(ctx));
        goto einval_end;
    }

    if (!X509_sign(dtls_cert, ctx->dtls_pkey, EVP_sha1())) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to sign certificate, %s\n", openssl_get_error(ctx));
        goto einval_end;
    }

    /* Generate the fingerpint of certficate. */
    if (X509_digest(dtls_cert, EVP_sha256(), md, &n) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to generate fingerprint, %s\n", openssl_get_error(ctx));
        goto eio_end;
    }
    for (i = 0; i < n; i++) {
        av_bprintf(&fingerprint, "%02X", md[i]);
        if (i < n - 1)
            av_bprintf(&fingerprint, ":");
    }
    if (!fingerprint.str || !strlen(fingerprint.str)) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Fingerprint is empty\n");
        goto einval_end;
    }

    ctx->dtls_fingerprint = av_strdup(fingerprint.str);
    if (!ctx->dtls_fingerprint) {
        goto enomem_end;
    }

    goto end;
enomem_end:
    ret = AVERROR(ENOMEM);
    goto end;
eio_end:
    ret = AVERROR(EIO);
    goto end;
einval_end:
    ret = AVERROR(EINVAL);
end:
    X509_NAME_free(subject);
    av_bprint_finalize(&fingerprint, NULL);
    return ret;
}

/**
 * Initializes DTLS context using ECDHE.
 */
static av_cold int openssl_dtls_init_context(DTLSContext *ctx)
{
    int ret = 0;
    EVP_PKEY *dtls_pkey = ctx->dtls_pkey;
    X509 *dtls_cert = ctx->dtls_cert;
    SSL_CTX *dtls_ctx = NULL;
    SSL *dtls = NULL;
    BIO *bio_in = NULL, *bio_out = NULL;
    const char* ciphers = "ALL";
    /**
     * The profile for OpenSSL's SRTP is SRTP_AES128_CM_SHA1_80, see ssl/d1_srtp.c.
     * The profile for FFmpeg's SRTP is SRTP_AES128_CM_HMAC_SHA1_80, see libavformat/srtp.c.
     */
    const char* profiles = "SRTP_AES128_CM_SHA1_80";

    /* Refer to the test cases regarding these curves in the WebRTC code. */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L /* OpenSSL 1.1.0 */
    const char* curves = "X25519:P-256:P-384:P-521";
#elif OPENSSL_VERSION_NUMBER >= 0x10002000L /* OpenSSL 1.0.2 */
    const char* curves = "P-256:P-384:P-521";
#endif
#if OPENSSL_VERSION_NUMBER < 0x10002000L /* OpenSSL v1.0.2 */
    dtls_ctx = ctx->dtls_ctx = SSL_CTX_new(DTLSv1_method());
#else
    dtls_ctx = ctx->dtls_ctx = SSL_CTX_new(DTLS_method());
#endif
    if (!dtls_ctx) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10002000L /* OpenSSL 1.0.2 */
    /* For ECDSA, we could set the curves list. */
    if (SSL_CTX_set1_curves_list(dtls_ctx, curves) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Init SSL_CTX_set1_curves_list failed, curves=%s, %s\n",
            curves, openssl_get_error(ctx));
        ret = AVERROR(EINVAL);
        return ret;
    }
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L // v1.1.x
#if OPENSSL_VERSION_NUMBER < 0x10002000L // v1.0.2
    if (ctx->dtls_eckey)
        SSL_CTX_set_tmp_ecdh(dtls_ctx, ctx->dtls_eckey);
#else
    SSL_CTX_set_ecdh_auto(dtls_ctx, 1);
#endif
#endif

    /**
     * We activate "ALL" cipher suites to align with the peer's capabilities,
     * ensuring maximum compatibility.
     */
    if (SSL_CTX_set_cipher_list(dtls_ctx, ciphers) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Init SSL_CTX_set_cipher_list failed, ciphers=%s, %s\n",
            ciphers, openssl_get_error(ctx));
        ret = AVERROR(EINVAL);
        return ret;
    }
    /* Setup the certificate. */
    if (SSL_CTX_use_certificate(dtls_ctx, dtls_cert) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Init SSL_CTX_use_certificate failed, %s\n", openssl_get_error(ctx));
        ret = AVERROR(EINVAL);
        return ret;
    }
    if (SSL_CTX_use_PrivateKey(dtls_ctx, dtls_pkey) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Init SSL_CTX_use_PrivateKey failed, %s\n", openssl_get_error(ctx));
        ret = AVERROR(EINVAL);
        return ret;
    }

    /* Server will send Certificate Request. */
    SSL_CTX_set_verify(dtls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, openssl_dtls_verify_callback);
    /* The depth count is "level 0:peer certificate", "level 1: CA certificate",
     * "level 2: higher level CA certificate", and so on. */
    SSL_CTX_set_verify_depth(dtls_ctx, 4);
    /* Whether we should read as many input bytes as possible (for non-blocking reads) or not. */
    SSL_CTX_set_read_ahead(dtls_ctx, 1);
    /* Setup the SRTP context */
    if (SSL_CTX_set_tlsext_use_srtp(dtls_ctx, profiles)) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Init SSL_CTX_set_tlsext_use_srtp failed, profiles=%s, %s\n",
            profiles, openssl_get_error(ctx));
        ret = AVERROR(EINVAL);
        return ret;
    }

    /* The dtls should not be created unless the dtls_ctx has been initialized. */
    dtls = ctx->dtls = SSL_new(dtls_ctx);
    if (!dtls) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    /* Setup the callback for logging. */
    SSL_set_ex_data(dtls, 0, ctx);
    SSL_set_info_callback(dtls, openssl_dtls_on_info);

    /**
     * We have set the MTU to fragment the DTLS packet. It is important to note that the
     * packet is split to ensure that each handshake packet is smaller than the MTU.
     */
    SSL_set_options(dtls, SSL_OP_NO_QUERY_MTU);
    SSL_set_mtu(dtls, ctx->mtu);
#if OPENSSL_VERSION_NUMBER >= 0x100010b0L /* OpenSSL 1.0.1k */
    DTLS_set_link_mtu(dtls, ctx->mtu);
#endif

    bio_in = BIO_new(BIO_s_mem());
    if (!bio_in) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    bio_out = BIO_new(BIO_s_mem());
    if (!bio_out) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    /**
     * Please be aware that it is necessary to use a callback to obtain the packet to be written out. It is
     * imperative that BIO_get_mem_data is not used to retrieve the packet, as it returns all the bytes that
     * need to be sent out.
     * For example, if MTU is set to 1200, and we got two DTLS packets to sendout:
     *      ServerHello, 95bytes.
     *      Certificate, 1105+143=1248bytes.
     * If use BIO_get_mem_data, it will return 95+1248=1343bytes, which is larger than MTU 1200.
     * If use callback, it will return two UDP packets:
     *      ServerHello+Certificate(Frament) = 95+1105=1200bytes.
     *      Certificate(Fragment) = 143bytes.
     * Note that there should be more packets in real world, like ServerKeyExchange, CertificateRequest,
     * and ServerHelloDone. Here we just use two packets for example.
     */
#if OPENSSL_VERSION_NUMBER < 0x30000000L // v3.0.x
    BIO_set_callback(bio_out, openssl_dtls_bio_out_callback);
#else
    BIO_set_callback_ex(bio_out, openssl_dtls_bio_out_callback_ex);
#endif
    BIO_set_callback_arg(bio_out, (char*)ctx);

    ctx->bio_in = bio_in;
    SSL_set_bio(dtls, bio_in, bio_out);
    /* Now the bio_in and bio_out are owned by dtls, so we should set them to NULL. */
    bio_in = bio_out = NULL;

end:
    BIO_free(bio_in);
    BIO_free(bio_out);
    return ret;
}

/**
 * Generate a self-signed certificate and private key for DTLS. Please note that the
 * ff_openssl_init in tls_openssl.c has already called SSL_library_init(), and therefore,
 * there is no need to call it again.
 */
static av_cold int dtls_context_init(AVFormatContext *s, DTLSContext *ctx)
{
    int ret = 0;

    ctx->dtls_init_starttime = av_gettime();

    if (ctx->cert_file && ctx->key_file) {
        /* Read the private key and file from the file. */
        if ((ret = openssl_read_certificate(s, ctx)) < 0) {
            av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to read DTLS certificate from cert=%s, key=%s\n",
                ctx->cert_file, ctx->key_file);
            return ret;
        }
    } else {
        /* Generate a private key to ctx->dtls_pkey. */
        if ((ret = openssl_dtls_gen_private_key(ctx)) < 0) {
            av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to generate DTLS private key\n");
            return ret;
        }

        /* Generate a self-signed certificate. */
        if ((ret = openssl_dtls_gen_certificate(ctx)) < 0) {
            av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to generate DTLS certificate\n");
            return ret;
        }
    }

    if ((ret = openssl_dtls_init_context(ctx)) < 0) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to initialize DTLS context\n");
        return ret;
    }

    ctx->dtls_init_endtime = av_gettime();
    av_log(ctx, AV_LOG_VERBOSE, "DTLS: Setup ok, MTU=%d, cost=%dms, fingerprint %s\n",
        ctx->mtu, ELAPSED(ctx->dtls_init_starttime, av_gettime()), ctx->dtls_fingerprint);

    return ret;
}

/**
 * Once the DTLS role has been negotiated - active for the DTLS client or passive for the
 * DTLS server - we proceed to set up the DTLS state and initiate the handshake.
 */
static int dtls_context_start(DTLSContext *ctx)
{
    int ret = 0, r0, r1;
    SSL *dtls = ctx->dtls;

    ctx->dtls_handshake_starttime = av_gettime();

    /* Setup DTLS as passive, which is server role. */
    SSL_set_accept_state(dtls);

    /**
     * During initialization, we only need to call SSL_do_handshake once because SSL_read consumes
     * the handshake message if the handshake is incomplete.
     * To simplify maintenance, we initiate the handshake for both the DTLS server and client after
     * sending out the ICE response in the start_active_handshake function. It's worth noting that
     * although the DTLS server may receive the ClientHello immediately after sending out the ICE
     * response, this shouldn't be an issue as the handshake function is called before any DTLS
     * packets are received.
     */
    r0 = SSL_do_handshake(dtls);
    r1 = openssl_ssl_get_error(ctx, r0);
    // Fatal SSL error, for example, no available suite when peer is DTLS 1.0 while we are DTLS 1.2.
    if (r0 < 0 && (r1 != SSL_ERROR_NONE && r1 != SSL_ERROR_WANT_READ && r1 != SSL_ERROR_WANT_WRITE)) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to drive SSL context, r0=%d, r1=%d %s\n", r0, r1, ctx->error_message);
        return AVERROR(EIO);
    }

    return ret;
}

/**
 * DTLS handshake with server, as a server in passive mode, using openssl.
 *
 * This function initializes the SSL context as the client role using OpenSSL and
 * then performs the DTLS handshake until success. Upon successful completion, it
 * exports the SRTP material key.
 *
 * @return 0 if OK, AVERROR_xxx on error
 */
static int dtls_context_write(DTLSContext *ctx, char* buf, int size)
{
    int ret = 0, res_ct, res_ht, r0, r1, do_callback;
    SSL *dtls = ctx->dtls;
    const char* dst = "EXTRACTOR-dtls_srtp";
    BIO *bio_in = ctx->bio_in;

    /* Got DTLS response successfully. */
    openssl_dtls_state_trace(ctx, buf, size, 1);
    if ((r0 = BIO_write(bio_in, buf, size)) <= 0) {
        res_ct = size > 0 ? buf[0]: 0;
        res_ht = size > 13 ? buf[13] : 0;
        av_log(ctx, AV_LOG_ERROR, "DTLS: Feed response failed, content=%d, handshake=%d, size=%d, r0=%d\n",
            res_ct, res_ht, size, r0);
        ret = AVERROR(EIO);
        goto end;
    }

    /**
     * If there is data available in bio_in, use SSL_read to allow SSL to process it.
     * We limit the MTU to 1200 for DTLS handshake, which ensures that the buffer is large enough for reading.
     */
    r0 = SSL_read(dtls, buf, sizeof(buf));
    r1 = openssl_ssl_get_error(ctx, r0);
    if (r0 <= 0) {
        if (r1 != SSL_ERROR_WANT_READ && r1 != SSL_ERROR_WANT_WRITE && r1 != SSL_ERROR_ZERO_RETURN) {
            av_log(ctx, AV_LOG_ERROR, "DTLS: Read failed, r0=%d, r1=%d %s\n", r0, r1, ctx->error_message);
            ret = AVERROR(EIO);
            goto end;
        }
    } else {
        av_log(ctx, AV_LOG_TRACE, "DTLS: Read %d bytes, r0=%d, r1=%d\n", r0, r0, r1);
    }

    /* Check whether the DTLS is completed. */
    if (SSL_is_init_finished(dtls) != 1)
        goto end;

    do_callback = ctx->on_state && !ctx->dtls_done_for_us;
    ctx->dtls_done_for_us = 1;
    ctx->dtls_handshake_endtime = av_gettime();

    /* Export SRTP master key after DTLS done */
    if (!ctx->dtls_srtp_key_exported) {
        ret = SSL_export_keying_material(dtls, ctx->dtls_srtp_materials, sizeof(ctx->dtls_srtp_materials),
            dst, strlen(dst), NULL, 0, 0);
        r1 = openssl_ssl_get_error(ctx, r0);
        if (!ret) {
            av_log(ctx, AV_LOG_ERROR, "DTLS: SSL export key ret=%d, r1=%d %s\n", ret, r1, ctx->error_message);
            ret = AVERROR(EIO);
            goto end;
        }

        av_log(NULL, AV_LOG_INFO, "WHEP: debug: SSL_export_keying_material success\n");
        ctx->dtls_srtp_key_exported = 1;
    }

    if (do_callback && (ret = ctx->on_state(ctx, DTLS_STATE_FINISHED, NULL, NULL)) < 0)
        goto end;

end:
    return ret;
}

/**
 * Cleanup the DTLS context.
 */
static av_cold void dtls_context_deinit(DTLSContext *ctx)
{
    SSL_free(ctx->dtls);
    SSL_CTX_free(ctx->dtls_ctx);
    X509_free(ctx->dtls_cert);
    EVP_PKEY_free(ctx->dtls_pkey);
    av_freep(&ctx->dtls_fingerprint);
    av_freep(&ctx->cert_file);
    av_freep(&ctx->key_file);
#if OPENSSL_VERSION_NUMBER < 0x30000000L /* OpenSSL 3.0 */
    EC_KEY_free(ctx->dtls_eckey);
#endif
}

enum WHEPState {
    WHEP_STATE_NONE,

    /* The initial state. */
    WHEP_STATE_INIT,
    /* The muxer has sent the offer to the peer. */
    WHEP_STATE_OFFER,
    /* The muxer has received the answer from the peer. */
    WHEP_STATE_ANSWER,
    /**
     * After parsing the answer received from the peer, the muxer negotiates the abilities
     * in the offer that it generated.
     */
    WHEP_STATE_NEGOTIATED,
    /* The demuxer is ready to send/receive media frames. */
    WHEP_STATE_READY,
    /* The demuxer has connected to the peer via UDP. */
    WHEP_STATE_UDP_CONNECTED,
    /* The demuxer has sent the ICE request to the peer. */
    WHEP_STATE_ICE_CONNECTING,
    /* The demuxer has received the ICE response from the peer. */
    WHEP_STATE_ICE_CONNECTED,
    /* The demuxer has finished the DTLS handshake with the peer. */
    WHEP_STATE_DTLS_FINISHED,

    /* The demuxer has finished the SRTP setup. */
    WHEP_STATE_SRTP_FINISHED,

    /* The demuxer is failed. */
    WHEP_STATE_FAILED,
};

typedef struct RTPStream {
    void *transport_priv; /**< RTP/RDT parse context if input, RTP AVFormatContext if output */

    /** corresponding stream index, if any. -1 if none (MPEG2TS case) */
    int stream_index;

    /** The following are used only in SDP, not RTSP */
    //@{
    int sdp_port;             /**< port (from SDP content) */
    struct sockaddr_storage sdp_ip; /**< IP address (from SDP content) */
    int nb_include_source_addrs; /**< Number of source-specific multicast include source IP addresses (from SDP content) */
    struct RTPSource **include_source_addrs; /**< Source-specific multicast include source IP addresses (from SDP content) */
    int nb_exclude_source_addrs; /**< Number of source-specific multicast exclude source IP addresses (from SDP content) */
    struct RTPSource **exclude_source_addrs; /**< Source-specific multicast exclude source IP addresses (from SDP content) */
    int sdp_ttl;              /**< IP Time-To-Live (from SDP content) */
    int sdp_payload_type;     /**< payload type */
    //@}

    /** The following are used for dynamic protocols (rtpdec_*.c/rdt.c) */
    //@{
    /** handler structure */
    const RTPDynamicProtocolHandler *dynamic_handler;

    /** private data associated with the dynamic protocol */
    PayloadContext *dynamic_protocol_context;
    //@}

    /** Enable sending RTCP feedback messages according to RFC 4585 */
    int feedback;

    /** SSRC for this stream, to allow identifying RTCP packets before the first RTP packet */
    uint32_t ssrc;
} RTPStream;

typedef struct WHEPContext {
    AVClass *av_class;

    /* The state of the RTC connection. */
    enum WHEPState state;
    /* The callback return value for DTLS. */
    int dtls_ret;
    int dtls_closed;

    /** number of items in the 'streams' variable */
    int nb_streams;

    struct RTPStream **streams; /**< streams in this session */

    /* The random number generator. */
    AVLFG rnd;

    /* The ICE username and pwd fragment generated by the muxer. */
    char ice_ufrag_local[9];
    char ice_pwd_local[33];
    /* The SSRC of the audio and video stream, generated by the muxer. */
    uint32_t audio_ssrc;
    uint32_t video_ssrc;
    /* The PT(Payload Type) of stream, generated by the muxer. */
    uint8_t audio_payload_type;
    uint8_t video_payload_type;
    /**
     * This is the SDP offer generated by the muxer based on the codec parameters,
     * DTLS, and ICE information.
     */
    char *sdp_offer;

    /* The ICE username and pwd from remote server. */
    char *ice_ufrag_remote;
    char *ice_pwd_remote;
    /**
     * This represents the ICE candidate protocol, priority, host and port.
     * Currently, we only support one candidate and choose the first UDP candidate.
     * However, we plan to support multiple candidates in the future.
     */
    char *ice_protocol;
    char *ice_host;
    int ice_port;
    int ice_priority;

    /* The SDP answer received from the WebRTC server. */
    char *sdp_answer;
    /* The resource URL returned in the Location header of WHEP HTTP response. */
    char *whep_resource_url;

    /* These variables represent timestamps used for calculating and tracking the cost. */
    int64_t whep_starttime;
    /*  */
    int64_t whep_init_time;
    int64_t whep_offer_time;
    int64_t whep_answer_time;
    int64_t whep_udp_time;
    int64_t whep_ice_time;
    int64_t whep_dtls_time;
    int64_t whep_srtp_time;

    /* The DTLS context. */
    DTLSContext dtls_ctx;

    /* The SRTP send context, to encrypt outgoing packets. */
    SRTPContext srtp_rtcp_send;
    /* The SRTP receive context, to decrypt incoming packets. */
    SRTPContext srtp_recv;

    char crypto_suite[40];
    char crypto_send_params[AV_BASE64_SIZE(DTLS_SRTP_KEY_LEN + DTLS_SRTP_SALT_LEN)];
    char crypto_recv_params[AV_BASE64_SIZE(DTLS_SRTP_KEY_LEN + DTLS_SRTP_SALT_LEN)];

    /* The UDP transport is used for delivering ICE, DTLS and SRTP packets. */
    URLContext *udp_uc;

    /** Reusable buffer for receiving packets */
    int recvbuf_size;

    /** Reusable buffer for receiving packets */
    uint8_t* recvbuf;

    /* The timeout in milliseconds for ICE and DTLS handshake. */
    int handshake_timeout;
    /**
     * The size of RTP packet, should generally be set to MTU.
     * Note that pion requires a smaller value, for example, 1200.
     */
    int pkt_size;
    /**
     * The optional Bearer token for WHEP Authorization.
     * See https://www.ietf.org/archive/id/draft-ietf-wish-whep-03.html#name-authentication-and-authoriz
     */
    char* authorization;
    /* The certificate and private key used for DTLS handshake. */
    char* cert_file;
    char* key_file;
} WHEPContext;

/**
 * When DTLS state change.
 */
static int dtls_context_on_state(DTLSContext *ctx, enum DTLSState state, const char* type, const char* desc)
{
    int ret = 0;
    AVFormatContext *s = ctx->opaque;
    WHEPContext *whep = s->priv_data;
    av_log(whep, AV_LOG_INFO, "WHEP: debug: dtls_context_on_state 11\n");

    if (state == DTLS_STATE_CLOSED) {
        whep->dtls_closed = 1;
        av_log(whep, AV_LOG_INFO, "WHEP: DTLS session closed, type=%s, desc=%s, elapsed=%dms\n",
            type ? type : "", desc ? desc : "", ELAPSED(whep->whep_starttime, av_gettime()));
        return ret;
    }

    if (state == DTLS_STATE_FAILED) {
        whep->state = WHEP_STATE_FAILED;
        av_log(whep, AV_LOG_INFO, "WHEP: DTLS session failed, type=%s, desc=%s\n",
            type ? type : "", desc ? desc : "");
        whep->dtls_ret = AVERROR(EIO);
        return ret;
    }

    if (state == DTLS_STATE_FINISHED && whep->state < WHEP_STATE_DTLS_FINISHED) {
        whep->state = WHEP_STATE_DTLS_FINISHED;
        whep->whep_dtls_time = av_gettime();
        av_log(whep, AV_LOG_INFO, "WHEP: DTLS handshake, done=%d, exported=%d, arq=%d, srtp_material=%luB, cost=%dms, elapsed=%dms\n",
            ctx->dtls_done_for_us, ctx->dtls_srtp_key_exported, ctx->dtls_arq_packets, sizeof(ctx->dtls_srtp_materials),
            ELAPSED(ctx->dtls_handshake_starttime, ctx->dtls_handshake_endtime),
            ELAPSED(whep->whep_starttime, av_gettime()));
        return ret;
    }

    av_log(whep, AV_LOG_INFO, "WHEP: debug: dtls_context_on_state 11\n");
    return ret;
}

/**
 * When DTLS write data.
 */
static int dtls_context_on_write(DTLSContext *ctx, char* data, int size)
{
    AVFormatContext *s = ctx->opaque;
    WHEPContext *whep = s->priv_data;

    av_log(whep, AV_LOG_INFO, "WHEP: debug: dtls_context_on_write 11\n");

    if (!whep->udp_uc) {
        av_log(whep, AV_LOG_ERROR, "WHEP: DTLS write data, but udp_uc is NULL\n");
        return AVERROR(EIO);
    }

    av_log(whep, AV_LOG_INFO, "WHEP: debug: dtls_context_on_write 22\n");
    return ffurl_write(whep->udp_uc, data, size);
}

/**
 * Initialize and check the options for the WebRTC muxer.
 */
static av_cold int initialize(AVFormatContext *s)
{
    int ret, ideal_pkt_size = 532;
    WHEPContext *whep = s->priv_data;
    uint32_t seed;

    av_log(whep, AV_LOG_INFO, "WHEP: debug: initialize 11\n");
    whep->whep_starttime = av_gettime();

    /* Initialize the random number generator. */
    seed = av_get_random_seed();
    av_lfg_init(&whep->rnd, seed);

    whep->recvbuf_size = MAX_UDP_BUFFER_SIZE;
    if (!whep->recvbuf) {
        whep->recvbuf = av_malloc(whep->recvbuf_size);
        if (!whep->recvbuf)
            return AVERROR(ENOMEM);
    }

    /* Use the same logging context as AV format. */
    whep->dtls_ctx.av_class = whep->av_class;
    whep->dtls_ctx.mtu = whep->pkt_size;
    whep->dtls_ctx.opaque = s;
    whep->dtls_ctx.on_state = dtls_context_on_state;
    whep->dtls_ctx.on_write = dtls_context_on_write;
    if (whep->cert_file)
        whep->dtls_ctx.cert_file = av_strdup(whep->cert_file);
    if (whep->key_file)
        whep->dtls_ctx.key_file = av_strdup(whep->key_file);

    if ((ret = dtls_context_init(s, &whep->dtls_ctx)) < 0) {
        av_log(whep, AV_LOG_ERROR, "WHEP: Failed to init DTLS context\n");
        return ret;
    }

    if (whep->pkt_size < ideal_pkt_size)
        av_log(whep, AV_LOG_WARNING, "WHEP: pkt_size=%d(<%d) is too small, may cause packet loss\n",
               whep->pkt_size, ideal_pkt_size);

    if (whep->state < WHEP_STATE_INIT)
        whep->state = WHEP_STATE_INIT;
    whep->whep_init_time = av_gettime();
    av_log(whep, AV_LOG_VERBOSE, "WHEP: Init state=%d, handshake_timeout=%dms, pkt_size=%d, seed=%d, elapsed=%dms\n",
        whep->state, whep->handshake_timeout, whep->pkt_size, seed, ELAPSED(whep->whep_starttime, av_gettime()));

    av_log(whep, AV_LOG_INFO, "WHEP: debug: initialize 22\n");
    return 0;
}

/**
 * When duplicating a stream, the demuxer has already set the extradata, profile, and
 * level of the par. Keep in mind that this function will not be invoked since the
 * profile and level are set.
 *
 * When utilizing an encoder, such as libx264, to encode a stream, the extradata in
 * par->extradata contains the SPS, which includes profile and level information.
 * However, the profile and level of par remain unspecified. Therefore, it is necessary
 * to extract the profile and level data from the extradata and assign it to the par's
 * profile and level. Keep in mind that AVFMT_GLOBALHEADER must be enabled; otherwise,
 * the extradata will remain empty.
 */
static int parse_profile_level(AVFormatContext *s, AVCodecParameters *par)
{
    int ret = 0;
    const uint8_t *r = par->extradata, *r1, *end = par->extradata + par->extradata_size;
    H264SPS seq, *const sps = &seq;
    uint32_t state;
    WHEPContext *whep = s->priv_data;

    if (par->codec_id != AV_CODEC_ID_H264)
        return ret;

    if (par->profile != FF_PROFILE_UNKNOWN && par->level != FF_LEVEL_UNKNOWN)
        return ret;

    if (!par->extradata || par->extradata_size <= 0) {
        av_log(whep, AV_LOG_ERROR, "WHEP: Unable to parse profile from empty extradata=%p, size=%d\n",
            par->extradata, par->extradata_size);
        return AVERROR(EINVAL);
    }

    while (1) {
        r = avpriv_find_start_code(r, end, &state);
        if (r >= end)
            break;

        r1 = ff_avc_find_startcode(r, end);
        if ((state & 0x1f) == H264_NAL_SPS) {
            ret = ff_avc_decode_sps(sps, r, r1 - r);
            if (ret < 0) {
                av_log(whep, AV_LOG_ERROR, "WHEP: Failed to decode SPS, state=%x, size=%d\n",
                    state, (int)(r1 - r));
                return ret;
            }

            av_log(whep, AV_LOG_VERBOSE, "WHEP: Parse profile=%d, level=%d from SPS\n",
                sps->profile_idc, sps->level_idc);
            par->profile = sps->profile_idc;
            par->level = sps->level_idc;
        }

        r = r1;
    }

    return ret;
}

/**
 * Generate SDP offer according to the codec parameters, DTLS and ICE information.
 *
 * Note that we don't use av_sdp_create to generate SDP offer because it doesn't
 * support DTLS and ICE information.
 *
 * @return 0 if OK, AVERROR_xxx on error
 */
static int generate_sdp_offer(AVFormatContext *s)
{
    int ret = 0, profile, level, profile_iop;
    const char *acodec_name = NULL, *vcodec_name = NULL;
    AVBPrint bp;
    WHEPContext *whep = s->priv_data;

    av_log(whep, AV_LOG_INFO, "WHEP: debug: generate_sdp_offer 11\n");

    /* To prevent a crash during cleanup, always initialize it. */
    av_bprint_init(&bp, 1, MAX_SDP_SIZE);

    if (whep->sdp_offer) {
        av_log(whep, AV_LOG_ERROR, "WHEP: SDP offer is already set\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    snprintf(whep->ice_ufrag_local, sizeof(whep->ice_ufrag_local), "%08x",
        av_lfg_get(&whep->rnd));
    snprintf(whep->ice_pwd_local, sizeof(whep->ice_pwd_local), "%08x%08x%08x%08x",
        av_lfg_get(&whep->rnd), av_lfg_get(&whep->rnd), av_lfg_get(&whep->rnd),
        av_lfg_get(&whep->rnd));

    whep->audio_ssrc = av_lfg_get(&whep->rnd);
    whep->video_ssrc = av_lfg_get(&whep->rnd);

    whep->audio_payload_type = WHEP_RTP_PAYLOAD_TYPE_OPUS;
    whep->video_payload_type = WHEP_RTP_PAYLOAD_TYPE_H264;

    av_bprintf(&bp, ""
        "v=0\r\n"
        "o=FFmpeg %s 2 IN IP4 %s\r\n"
        "s=FFmpegPublishSession\r\n"
        "t=0 0\r\n"
        "a=group:BUNDLE 0 1\r\n"
        "a=extmap-allow-mixed\r\n"
        "a=msid-semantic: WMS\r\n",
        WHEP_SDP_SESSION_ID,
        WHEP_SDP_CREATOR_IP);

    //audio
    /* if (0) */
    {
        acodec_name = "opus";

        av_bprintf(&bp, ""
            "m=audio 9 UDP/TLS/RTP/SAVPF %u\r\n"
            "c=IN IP4 0.0.0.0\r\n"
            "a=ice-ufrag:%s\r\n"
            "a=ice-pwd:%s\r\n"
            "a=fingerprint:sha-256 %s\r\n"
            "a=setup:passive\r\n"
            "a=mid:0\r\n"
            "a=sendonly\r\n"
            "a=msid:FFmpeg audio\r\n"
            "a=rtcp-mux\r\n"
            "a=rtpmap:%u %s/%d\r\n"
            "a=ssrc:%u cname:FFmpeg\r\n"
            "a=ssrc:%u msid:FFmpeg audio\r\n",
            whep->audio_payload_type,
            whep->ice_ufrag_local,
            whep->ice_pwd_local,
            whep->dtls_ctx.dtls_fingerprint,
            whep->audio_payload_type,
            acodec_name,
            48000,
            whep->audio_ssrc,
            whep->audio_ssrc);
    }

    //video
    {
        /* profile_iop = profile = whep->video_par->profile; */
        /* level = whep->video_par->level; */
         profile_iop = profile = FF_PROFILE_H264_MAIN;
        level = FF_PROFILE_H264_MAIN;

        vcodec_name = "H264";
        profile_iop &= FF_PROFILE_H264_CONSTRAINED;
        profile &= (~FF_PROFILE_H264_CONSTRAINED);

        av_bprintf(&bp, ""
            "m=video 9 UDP/TLS/RTP/SAVPF %u\r\n"
            "c=IN IP4 0.0.0.0\r\n"
            "a=ice-ufrag:%s\r\n"
            "a=ice-pwd:%s\r\n"
            "a=fingerprint:sha-256 %s\r\n"
            "a=mid:1\r\n"
            "a=recvonly\r\n"
            "a=msid:FFmpeg video\r\n"
            "a=rtcp-mux\r\n"
            "a=rtcp-rsize\r\n"
            "a=rtpmap:%u %s/90000\r\n"
            /* "a=fmtp:%u level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=%02x%02x%02x\r\n" */
            "a=fmtp:%u level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=422001e\r\n"
            "a=ssrc:%u cname:FFmpeg\r\n"
            "a=ssrc:%u msid:FFmpeg video\r\n",
            whep->video_payload_type,
            whep->ice_ufrag_local,
            whep->ice_pwd_local,
            whep->dtls_ctx.dtls_fingerprint,
            whep->video_payload_type,
            vcodec_name,
            whep->video_payload_type,
            /* profile, */
            /* profile_iop, */
            /* level, */
            whep->video_ssrc,
            whep->video_ssrc);
    }

    if (!av_bprint_is_complete(&bp)) {
        av_log(whep, AV_LOG_ERROR, "WHEP: Offer exceed max %d, %s\n", MAX_SDP_SIZE, bp.str);
        ret = AVERROR(EIO);
        goto end;
    }

    whep->sdp_offer = av_strdup(bp.str);
    if (!whep->sdp_offer) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    if (whep->state < WHEP_STATE_OFFER)
        whep->state = WHEP_STATE_OFFER;
    whep->whep_offer_time = av_gettime();
    av_log(whep, AV_LOG_VERBOSE, "WHEP: Generated state=%d, offer: %s\n", whep->state, whep->sdp_offer);

end:
    av_bprint_finalize(&bp, NULL);

    av_log(whep, AV_LOG_INFO, "WHEP: debug: generate_sdp_offer 22\n");
    return ret;
}

/**
 * Exchange SDP offer with WebRTC peer to get the answer.
 *
 * @return 0 if OK, AVERROR_xxx on error
 */
static int exchange_sdp(AVFormatContext *s)
{
    int ret;
    char buf[MAX_URL_SIZE];
    AVBPrint bp;
    WHEPContext *whep = s->priv_data;
    /* The URL context is an HTTP transport layer for the WHEP protocol. */
    URLContext *whep_uc = NULL;
    AVDictionary *opts = NULL;
    char *hex_data = NULL;
    av_log(whep, AV_LOG_INFO, "WHEP: debug: exchange_sdp 11\n");

    /* To prevent a crash during cleanup, always initialize it. */
    av_bprint_init(&bp, 1, MAX_SDP_SIZE);

    if (!whep->sdp_offer || !strlen(whep->sdp_offer)) {
        av_log(whep, AV_LOG_ERROR, "WHEP: No offer to exchange\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    ret = snprintf(buf, sizeof(buf), "Cache-Control: no-cache\r\nContent-Type: application/sdp\r\n");
    if (whep->authorization)
        ret += snprintf(buf + ret, sizeof(buf) - ret, "Authorization: Bearer %s\r\n", whep->authorization);
    if (ret <= 0 || ret >= sizeof(buf)) {
        av_log(whep, AV_LOG_ERROR, "WHEP: Failed to generate headers, size=%d, %s\n", ret, buf);
        ret = AVERROR(EINVAL);
        goto end;
    }

    av_dict_set(&opts, "headers", buf, 0);
    av_dict_set_int(&opts, "chunked_post", 0, 0);

    hex_data = av_mallocz(2 * strlen(whep->sdp_offer) + 1);
    if (!hex_data) {
        ret = AVERROR(ENOMEM);
        goto end;
    }
    ff_data_to_hex(hex_data, whep->sdp_offer, strlen(whep->sdp_offer), 0);
    av_dict_set(&opts, "post_data", hex_data, 0);

    ret = ffurl_open_whitelist(&whep_uc, s->url, AVIO_FLAG_READ_WRITE, &s->interrupt_callback,
        &opts, s->protocol_whitelist, s->protocol_blacklist, NULL);
    if (ret < 0) {
        av_log(whep, AV_LOG_ERROR, "WHEP: Failed to request url=%s, offer: %s\n", s->url, whep->sdp_offer);
        goto end;
    }

    if (ff_http_get_new_location(whep_uc)) {
        whep->whep_resource_url = av_strdup(ff_http_get_new_location(whep_uc));
        if (!whep->whep_resource_url) {
            ret = AVERROR(ENOMEM);
            goto end;
        }
    }

    while (1) {
        ret = ffurl_read(whep_uc, buf, sizeof(buf));
        if (ret == AVERROR_EOF) {
            /* Reset the error because we read all response as answer util EOF. */
            ret = 0;
            break;
        }
        if (ret <= 0) {
            av_log(whep, AV_LOG_ERROR, "WHEP: Failed to read response from url=%s, offer is %s, answer is %s\n",
                s->url, whep->sdp_offer, whep->sdp_answer);
            goto end;
        }

        av_bprintf(&bp, "%.*s", ret, buf);
        if (!av_bprint_is_complete(&bp)) {
            av_log(whep, AV_LOG_ERROR, "WHEP: Answer exceed max size %d, %.*s, %s\n", MAX_SDP_SIZE, ret, buf, bp.str);
            ret = AVERROR(EIO);
            goto end;
        }
    }

    if (!av_strstart(bp.str, "v=", NULL)) {
        av_log(whep, AV_LOG_ERROR, "WHEP: Invalid answer: %s\n", bp.str);
        ret = AVERROR(EINVAL);
        goto end;
    }

    whep->sdp_answer = av_strdup(bp.str);
    if (!whep->sdp_answer) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    if (whep->state < WHEP_STATE_ANSWER)
        whep->state = WHEP_STATE_ANSWER;
    av_log(whep, AV_LOG_VERBOSE, "WHEP: Got state=%d, answer: %s\n", whep->state, whep->sdp_answer);

end:
    ffurl_closep(&whep_uc);
    av_bprint_finalize(&bp, NULL);
    av_dict_free(&opts);
    av_freep(&hex_data);

    av_log(whep, AV_LOG_INFO, "WHEP: debug: exchange_sdp 22\n");
    return ret;
}

/**
 * Parses the ICE ufrag, pwd, and candidates from the SDP answer.
 *
 * This function is used to extract the ICE ufrag, pwd, and candidates from the SDP answer.
 * It returns an error if any of these fields is NULL. The function only uses the first
 * candidate if there are multiple candidates. However, support for multiple candidates
 * will be added in the future.
 *
 * @param s Pointer to the AVFormatContext
 * @returns Returns 0 if successful or AVERROR_xxx if an error occurs.
 */
static int parse_answer_ice(AVFormatContext *s)
{
    int ret = 0;
    AVIOContext *pb;
    char line[MAX_URL_SIZE];
    const char *ptr;
    int i;
    WHEPContext *whep = s->priv_data;

    av_log(whep, AV_LOG_INFO, "WHEP: debug: parse_answer_ice 11\n");

    if (!whep->sdp_answer || !strlen(whep->sdp_answer)) {
        av_log(whep, AV_LOG_ERROR, "WHEP: No answer to parse\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    av_log(whep, AV_LOG_INFO, "WHEP: debug get sdp_answer:\n%s\n", whep->sdp_answer);

    pb = avio_alloc_context(whep->sdp_answer, strlen(whep->sdp_answer), 0, NULL, NULL, NULL, NULL);
    if (!pb)
        return AVERROR(ENOMEM);

    for (i = 0; !avio_feof(pb); i++) {
        ff_get_chomp_line(pb, line, sizeof(line));
        if (av_strstart(line, "a=ice-ufrag:", &ptr) && !whep->ice_ufrag_remote) {
            whep->ice_ufrag_remote = av_strdup(ptr);
            if (!whep->ice_ufrag_remote) {
                ret = AVERROR(ENOMEM);
                goto end;
            }
        } else if (av_strstart(line, "a=ice-pwd:", &ptr) && !whep->ice_pwd_remote) {
            whep->ice_pwd_remote = av_strdup(ptr);
            if (!whep->ice_pwd_remote) {
                ret = AVERROR(ENOMEM);
                goto end;
            }
        } else if (av_strstart(line, "a=candidate:", &ptr) && !whep->ice_protocol) {
            av_log(whep, AV_LOG_ERROR, "debug aaa 1 ptr: %s\n", ptr? ptr: "null");
            ptr = av_stristr(ptr, " udp ");
            av_log(whep, AV_LOG_ERROR, "debug aaa 2 ptr: %s\n", ptr? ptr: "null");
            if (ptr && av_stristr(ptr, "host")) {
                char protocol[17], host[129];
                int priority, port;
                av_log(whep, AV_LOG_ERROR, "debug aaa 3 ptr: %s\n", ptr? ptr: "null");
                ret = sscanf(ptr, "%16s %d %128s %d typ host", protocol, &priority, host, &port);
                if (ret != 4) {
                    av_log(whep, AV_LOG_ERROR, "WHEP: Failed %d to parse line %d %s from %s\n",
                        ret, i, line, whep->sdp_answer);
                    ret = AVERROR(EIO);
                    goto end;
                }

                if (av_strcasecmp(protocol, "udp")) {
                    av_log(whep, AV_LOG_ERROR, "WHEP: Protocol %s is not supported by RTC, choose udp, line %d %s of %s\n",
                        protocol, i, line, whep->sdp_answer);
                    ret = AVERROR(EIO);
                    goto end;
                }

                whep->ice_protocol = av_strdup(protocol);
                whep->ice_host = av_strdup(host);
                whep->ice_port = port;
                whep->ice_priority = priority;
                if (!whep->ice_protocol || !whep->ice_host) {
                    ret = AVERROR(ENOMEM);
                    goto end;
                }
            }
        }
    }

    if (!whep->ice_pwd_remote || !strlen(whep->ice_pwd_remote)) {
        av_log(whep, AV_LOG_ERROR, "WHEP: No remote ice pwd parsed from %s\n", whep->sdp_answer);
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (!whep->ice_ufrag_remote || !strlen(whep->ice_ufrag_remote)) {
        av_log(whep, AV_LOG_ERROR, "WHEP: No remote ice ufrag parsed from %s\n", whep->sdp_answer);
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (!whep->ice_protocol || !whep->ice_host || !whep->ice_port) {
        av_log(whep, AV_LOG_ERROR, "WHEP: No ice candidate parsed from %s\n", whep->sdp_answer);
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (whep->state < WHEP_STATE_NEGOTIATED)
        whep->state = WHEP_STATE_NEGOTIATED;
    whep->whep_answer_time = av_gettime();
    av_log(whep, AV_LOG_VERBOSE, "WHEP: SDP state=%d, offer=%luB, answer=%luB, ufrag=%s, pwd=%luB, transport=%s://%s:%d, elapsed=%dms\n",
        whep->state, strlen(whep->sdp_offer), strlen(whep->sdp_answer), whep->ice_ufrag_remote, strlen(whep->ice_pwd_remote),
        whep->ice_protocol, whep->ice_host, whep->ice_port, ELAPSED(whep->whep_starttime, av_gettime()));

end:
    avio_context_free(&pb);

    av_log(whep, AV_LOG_INFO, "WHEP: debug: parse_answer_ice 22\n");
    return ret;
}

/**
 * Creates and marshals an ICE binding request packet.
 *
 * This function creates and marshals an ICE binding request packet. The function only
 * generates the username attribute and does not include goog-network-info, ice-controlling,
 * use-candidate, and priority. However, some of these attributes may be added in the future.
 *
 * @param s Pointer to the AVFormatContext
 * @param buf Pointer to memory buffer to store the request packet
 * @param buf_size Size of the memory buffer
 * @param request_size Pointer to an integer that receives the size of the request packet
 * @return Returns 0 if successful or AVERROR_xxx if an error occurs.
 */
static int ice_create_request(AVFormatContext *s, uint8_t *buf, int buf_size, int *request_size)
{
    int ret, size, crc32;
    char username[128];
    AVIOContext *pb = NULL;
    AVHMAC *hmac = NULL;
    WHEPContext *whep = s->priv_data;

    pb = avio_alloc_context(buf, buf_size, 1, NULL, NULL, NULL, NULL);
    if (!pb)
        return AVERROR(ENOMEM);

    hmac = av_hmac_alloc(AV_HMAC_SHA1);
    if (!hmac) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    /* Write 20 bytes header */
    avio_wb16(pb, 0x0001); /* STUN binding request */
    avio_wb16(pb, 0);      /* length */
    avio_wb32(pb, STUN_MAGIC_COOKIE); /* magic cookie */
    avio_wb32(pb, av_lfg_get(&whep->rnd)); /* transaction ID */
    avio_wb32(pb, av_lfg_get(&whep->rnd)); /* transaction ID */
    avio_wb32(pb, av_lfg_get(&whep->rnd)); /* transaction ID */

    /* The username is the concatenation of the two ICE ufrag */
    ret = snprintf(username, sizeof(username), "%s:%s", whep->ice_ufrag_remote, whep->ice_ufrag_local);
    if (ret <= 0 || ret >= sizeof(username)) {
        av_log(whep, AV_LOG_ERROR, "WHEP: Failed to build username %s:%s, max=%lu, ret=%d\n",
            whep->ice_ufrag_remote, whep->ice_ufrag_local, sizeof(username), ret);
        ret = AVERROR(EIO);
        goto end;
    }

    /* Write the username attribute */
    avio_wb16(pb, STUN_ATTR_USERNAME); /* attribute type username */
    avio_wb16(pb, ret); /* size of username */
    avio_write(pb, username, ret); /* bytes of username */
    ffio_fill(pb, 0, (4 - (ret % 4)) % 4); /* padding */

    /* Write the priority attribute */
    avio_wb16(pb, STUN_ATTR_PRIORITY); /* attribute type priority */
    avio_wb16(pb, 4); /* size of priority */
    avio_wb32(pb, whep->ice_priority); /* value of priority */

    /* Write the use-candidate attribute */
    avio_wb16(pb, STUN_ATTR_USE_CANDIDATE); /* attribute type use-candidate */
    avio_wb16(pb, 0); /* size of use-candidate */

    /* Build and update message integrity */
    avio_wb16(pb, STUN_ATTR_MESSAGE_INTEGRITY); /* attribute type message integrity */
    avio_wb16(pb, 20); /* size of message integrity */
    ffio_fill(pb, 0, 20); /* fill with zero to directly write and skip it */
    size = avio_tell(pb);
    buf[2] = (size - 20) >> 8;
    buf[3] = (size - 20) & 0xFF;
    av_hmac_init(hmac, whep->ice_pwd_remote, strlen(whep->ice_pwd_remote));
    av_hmac_update(hmac, buf, size - 24);
    av_hmac_final(hmac, buf + size - 20, 20);

    /* Write the fingerprint attribute */
    avio_wb16(pb, STUN_ATTR_FINGERPRINT); /* attribute type fingerprint */
    avio_wb16(pb, 4); /* size of fingerprint */
    ffio_fill(pb, 0, 4); /* fill with zero to directly write and skip it */
    size = avio_tell(pb);
    buf[2] = (size - 20) >> 8;
    buf[3] = (size - 20) & 0xFF;
    /* Refer to the av_hash_alloc("CRC32"), av_hash_init and av_hash_final */
    crc32 = av_crc(av_crc_get_table(AV_CRC_32_IEEE_LE), 0xFFFFFFFF, buf, size - 8) ^ 0xFFFFFFFF;
    avio_skip(pb, -4);
    avio_wb32(pb, crc32 ^ 0x5354554E); /* xor with "STUN" */

    *request_size = size;

end:
    avio_context_free(&pb);
    av_hmac_free(hmac);
    return ret;
}

/**
 * Create an ICE binding response.
 *
 * This function generates an ICE binding response and writes it to the provided
 * buffer. The response is signed using the local password for message integrity.
 *
 * @param s Pointer to the AVFormatContext structure.
 * @param tid Pointer to the transaction ID of the binding request. The tid_size should be 12.
 * @param tid_size The size of the transaction ID, should be 12.
 * @param buf Pointer to the buffer where the response will be written.
 * @param buf_size The size of the buffer provided for the response.
 * @param response_size Pointer to an integer that will store the size of the generated response.
 * @return Returns 0 if successful or AVERROR_xxx if an error occurs.
 */
static int ice_create_response(AVFormatContext *s, char *tid, int tid_size, uint8_t *buf, int buf_size, int *response_size)
{
    int ret = 0, size, crc32;
    AVIOContext *pb = NULL;
    AVHMAC *hmac = NULL;
    WHEPContext *whep = s->priv_data;

    if (tid_size != 12) {
        av_log(whep, AV_LOG_ERROR, "WHEP: Invalid transaction ID size. Expected 12, got %d\n", tid_size);
        return AVERROR(EINVAL);
    }

    pb = avio_alloc_context(buf, buf_size, 1, NULL, NULL, NULL, NULL);
    if (!pb)
        return AVERROR(ENOMEM);

    hmac = av_hmac_alloc(AV_HMAC_SHA1);
    if (!hmac) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    /* Write 20 bytes header */
    avio_wb16(pb, 0x0101); /* STUN binding response */
    avio_wb16(pb, 0);      /* length */
    avio_wb32(pb, STUN_MAGIC_COOKIE); /* magic cookie */
    avio_write(pb, tid, tid_size); /* transaction ID */

    /* Build and update message integrity */
    avio_wb16(pb, STUN_ATTR_MESSAGE_INTEGRITY); /* attribute type message integrity */
    avio_wb16(pb, 20); /* size of message integrity */
    ffio_fill(pb, 0, 20); /* fill with zero to directly write and skip it */
    size = avio_tell(pb);
    buf[2] = (size - 20) >> 8;
    buf[3] = (size - 20) & 0xFF;
    av_hmac_init(hmac, whep->ice_pwd_local, strlen(whep->ice_pwd_local));
    av_hmac_update(hmac, buf, size - 24);
    av_hmac_final(hmac, buf + size - 20, 20);

    /* Write the fingerprint attribute */
    avio_wb16(pb, STUN_ATTR_FINGERPRINT); /* attribute type fingerprint */
    avio_wb16(pb, 4); /* size of fingerprint */
    ffio_fill(pb, 0, 4); /* fill with zero to directly write and skip it */
    size = avio_tell(pb);
    buf[2] = (size - 20) >> 8;
    buf[3] = (size - 20) & 0xFF;
    /* Refer to the av_hash_alloc("CRC32"), av_hash_init and av_hash_final */
    crc32 = av_crc(av_crc_get_table(AV_CRC_32_IEEE_LE), 0xFFFFFFFF, buf, size - 8) ^ 0xFFFFFFFF;
    avio_skip(pb, -4);
    avio_wb32(pb, crc32 ^ 0x5354554E); /* xor with "STUN" */

    *response_size = size;

end:
    avio_context_free(&pb);
    av_hmac_free(hmac);
    return ret;
}

/**
 * A Binding request has class=0b00 (request) and method=0b000000000001 (Binding)
 * and is encoded into the first 16 bits as 0x0001.
 * See https://datatracker.ietf.org/doc/html/rfc5389#section-6
 */
static int ice_is_binding_request(uint8_t *b, int size)
{
    return size >= ICE_STUN_HEADER_SIZE && AV_RB16(&b[0]) == 0x0001;
}

/**
 * A Binding response has class=0b10 (success response) and method=0b000000000001,
 * and is encoded into the first 16 bits as 0x0101.
 */
static int ice_is_binding_response(uint8_t *b, int size)
{
    return size >= ICE_STUN_HEADER_SIZE && AV_RB16(&b[0]) == 0x0101;
}

/**
 * In RTP packets, the first byte is represented as 0b10xxxxxx, where the initial
 * two bits (0b10) indicate the RTP version,
 * see https://www.rfc-editor.org/rfc/rfc3550#section-5.1
 * The RTCP packet header is similar to RTP,
 * see https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1
 */
static int media_is_rtp_rtcp(uint8_t *b, int size) {
    return size >= WHEP_RTP_HEADER_SIZE && (b[0] & 0xC0) == 0x80;
}

/* Whether the packet is RTCP. */
static int media_is_rtcp(uint8_t *b, int size) {
    return size >= WHEP_RTP_HEADER_SIZE && b[1] >= WHEP_RTCP_PT_START && b[1] <= WHEP_RTCP_PT_END;
}

static int get_rtp_payload(uint8_t *b, int size) {
    return b[1] & 0x7f;
}

static RTPStream* get_stream_by_payload(WHEPContext *whep, int payload) {

    for (int i = 0; i < whep->nb_streams; i++) {
        RTPStream *stream = whep->streams[i];
        if (stream->sdp_payload_type == payload) {
            return stream;
        }
    }
    return NULL;
} 

/**
 * This function handles incoming binding request messages by responding to them.
 * If the message is not a binding request, it will be ignored.
 */
static int ice_handle_binding_request(AVFormatContext *s, char *buf, int buf_size)
{
    int ret = 0, size;
    char tid[12];
    WHEPContext *whep = s->priv_data;

    /* Ignore if not a binding request. */
    if (!ice_is_binding_request(buf, buf_size))
        return ret;

    if (buf_size < ICE_STUN_HEADER_SIZE) {
        av_log(whep, AV_LOG_ERROR, "WHEP: Invalid STUN message, expected at least %d, got %d\n",
            ICE_STUN_HEADER_SIZE, buf_size);
        return AVERROR(EINVAL);
    }

    /* Parse transaction id from binding request in buf. */
    memcpy(tid, buf + 8, 12);

    /* Build the STUN binding response. */
    ret = ice_create_response(s, tid, sizeof(tid), whep->recvbuf, whep->recvbuf_size, &size);
    if (ret < 0) {
        av_log(whep, AV_LOG_ERROR, "WHEP: Failed to create STUN binding response, size=%d\n", size);
        return ret;
    }

    ret = ffurl_write(whep->udp_uc, whep->recvbuf, size);
    if (ret < 0) {
        av_log(whep, AV_LOG_ERROR, "WHEP: Failed to send STUN binding response, size=%d\n", size);
        return ret;
    }

    return 0;
}

/**
 * To establish a connection with the UDP server, we utilize ICE-LITE in a Client-Server
 * mode. In this setup, FFmpeg acts as the UDP client, while the peer functions as the
 * UDP server.
 */
static int udp_connect(AVFormatContext *s)
{
    int ret = 0;
    char url[256] = {0};
    AVDictionary *opts = NULL;
    WHEPContext *whep = s->priv_data;

    av_log(whep, AV_LOG_INFO, "WHEP: debug: udp_connect 11\n");

    /* Build UDP URL and create the UDP context as transport. */
    ff_url_join(url, sizeof(url), "udp", NULL, whep->ice_host, whep->ice_port, NULL);
    av_log(whep, AV_LOG_INFO, "WHEP: debug: udp_connect url :%s\n", url);

    av_dict_set_int(&opts, "connect", 1, 0);
    av_dict_set_int(&opts, "fifo_size", 0, 0);
    /* Set the max packet size to the buffer size. */
    av_dict_set_int(&opts, "pkt_size", whep->pkt_size, 0);

    ret = ffurl_open_whitelist(&whep->udp_uc, url, AVIO_FLAG_WRITE, &s->interrupt_callback,
        &opts, s->protocol_whitelist, s->protocol_blacklist, NULL);
    if (ret < 0) {
        av_log(whep, AV_LOG_ERROR, "WHEP: Failed to connect udp://%s:%d\n", whep->ice_host, whep->ice_port);
        goto end;
    }

    /* Make the socket non-blocking, set to READ and WRITE mode after connected */
    ff_socket_nonblock(ffurl_get_file_handle(whep->udp_uc), 1);
    whep->udp_uc->flags |= AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK;

    if (whep->state < WHEP_STATE_UDP_CONNECTED)
        whep->state = WHEP_STATE_UDP_CONNECTED;
    whep->whep_udp_time = av_gettime();
    av_log(whep, AV_LOG_VERBOSE, "WHEP: UDP state=%d, elapsed=%dms, connected to udp://%s:%d\n",
        whep->state, ELAPSED(whep->whep_starttime, av_gettime()), whep->ice_host, whep->ice_port);

end:

    av_log(whep, AV_LOG_INFO, "WHEP: debug: udp_connect 22\n");
    av_dict_free(&opts);
    return ret;
}

static int ice_dtls_handshake(AVFormatContext *s)
{
    int ret = 0, size, i;
    int64_t starttime = av_gettime(), now;
    WHEPContext *whep = s->priv_data;

    av_log(whep, AV_LOG_INFO, "WHEP: debug: ice_dtls_handshake 11\n");

    if (whep->state < WHEP_STATE_UDP_CONNECTED || !whep->udp_uc) {
        av_log(whep, AV_LOG_ERROR, "WHEP: UDP not connected, state=%d, udp_uc=%p\n", whep->state, whep->udp_uc);
        return AVERROR(EINVAL);
    }

    while (1) {
        if (whep->state <= WHEP_STATE_ICE_CONNECTING) {
            /* Build the STUN binding request. */
            ret = ice_create_request(s, whep->recvbuf, whep->recvbuf_size, &size);
            if (ret < 0) {
                av_log(whep, AV_LOG_ERROR, "WHEP: Failed to create STUN binding request, size=%d\n", size);
                goto end;
            }

            ret = ffurl_write(whep->udp_uc, whep->recvbuf, size);
            if (ret < 0) {
                av_log(whep, AV_LOG_ERROR, "WHEP: Failed to send STUN binding request, size=%d\n", size);
                goto end;
            }

            if (whep->state < WHEP_STATE_ICE_CONNECTING)
                whep->state = WHEP_STATE_ICE_CONNECTING;
        }

next_packet:
        av_log(whep, AV_LOG_INFO, "WHEP: debug: ice_dtls_handshake 1100\n");
        if (whep->state >= WHEP_STATE_DTLS_FINISHED) {
            /* DTLS handshake is done, exit the loop. */
            av_log(whep, AV_LOG_INFO, "WHEP: debug: ice_dtls_handshake 11aa\n");
            break;
        }

        now = av_gettime();
        if (now - starttime >= whep->handshake_timeout * 1000) {
            av_log(whep, AV_LOG_ERROR, "WHEP: DTLS handshake timeout=%dms, cost=%dms, elapsed=%dms, state=%d\n",
                whep->handshake_timeout, ELAPSED(starttime, now), ELAPSED(whep->whep_starttime, now), whep->state);
            ret = AVERROR(ETIMEDOUT);
            goto end;
        }

        /* Read the STUN or DTLS messages from peer. */
        for (i = 0; i < ICE_DTLS_READ_INTERVAL / 5; i++) {
            ret = ffurl_read(whep->udp_uc, whep->recvbuf, whep->recvbuf_size);
            if (ret > 0)
                break;
            if (ret == AVERROR(EAGAIN)) {
                av_usleep(5 * 1000);
                continue;
            }
            av_log(whep, AV_LOG_ERROR, "WHEP: Failed to read message\n");
            goto end;
        }

        /* Got nothing, continue to process handshake. */
        if (ret <= 0)
            continue;

        /* Handle the ICE binding response. */
        if (ice_is_binding_response(whep->recvbuf, ret)) {
            if (whep->state < WHEP_STATE_ICE_CONNECTED) {
                whep->state = WHEP_STATE_ICE_CONNECTED;
                whep->whep_ice_time = av_gettime();
                av_log(whep, AV_LOG_INFO, "WHEP: ICE STUN ok, state=%d, url=udp://%s:%d, location=%s, username=%s:%s, res=%dB, elapsed=%dms\n",
                    whep->state, whep->ice_host, whep->ice_port, whep->whep_resource_url ? whep->whep_resource_url : "",
                    whep->ice_ufrag_remote, whep->ice_ufrag_local, ret, ELAPSED(whep->whep_starttime, av_gettime()));

                /* If got the first binding response, start DTLS handshake. */
                if ((ret = dtls_context_start(&whep->dtls_ctx)) < 0) {
                    av_log(whep, AV_LOG_INFO, "WHEP: debug: ice_dtls_handshake 11bb\n");
                    goto end;
                }
            }
            goto next_packet;
        }

        /* When a binding request is received, it is necessary to respond immediately. */
        if (ice_is_binding_request(whep->recvbuf, ret)) {
            if ((ret = ice_handle_binding_request(s, whep->recvbuf, ret)) < 0) {
                av_log(whep, AV_LOG_INFO, "WHEP: debug: ice_dtls_handshake 11cc\n");
                goto end;
            }
            goto next_packet;
        }

        /* If got any DTLS messages, handle it. */
        if (is_dtls_packet(whep->recvbuf, ret) && whep->state >= WHEP_STATE_ICE_CONNECTED) {
            if ((ret = dtls_context_write(&whep->dtls_ctx, whep->recvbuf, ret)) < 0)
                goto end;
            goto next_packet;
        }
    }

end:

    av_log(whep, AV_LOG_INFO, "WHEP: debug: ice_dtls_handshake 22\n");
    return ret;
}

/**
 * Establish the SRTP context using the keying material exported from DTLS.
 *
 * Create separate SRTP contexts for sending video and audio, as their sequences differ
 * and should not share a single context. Generate a single SRTP context for receiving
 * RTCP only.
 *
 * @return 0 if OK, AVERROR_xxx on error
 */
static int setup_srtp_cipher(AVFormatContext *s)
{
    int ret;
    char recv_key[DTLS_SRTP_KEY_LEN + DTLS_SRTP_SALT_LEN];
    char send_key[DTLS_SRTP_KEY_LEN + DTLS_SRTP_SALT_LEN];
    char buf[AV_BASE64_SIZE(DTLS_SRTP_KEY_LEN + DTLS_SRTP_SALT_LEN)];
    /**
     * The profile for OpenSSL's SRTP is SRTP_AES128_CM_SHA1_80, see ssl/d1_srtp.c.
     * The profile for FFmpeg's SRTP is SRTP_AES128_CM_HMAC_SHA1_80, see libavformat/srtp.c.
     */
    const char* suite = "SRTP_AES128_CM_HMAC_SHA1_80";
    WHEPContext *whep = s->priv_data;


    av_log(whep, AV_LOG_INFO, "WHEP: debug: setup_srtp 11\n");

    memset(whep->crypto_suite, 0, sizeof(whep->crypto_suite));
    strcpy(whep->crypto_suite, suite);

    /**
     * This represents the material used to build the SRTP master key. It is
     * generated by DTLS and has the following layout:
     *          16B         16B         14B             14B
     *      client_key | server_key | client_salt | server_salt
     */
    char *client_key = whep->dtls_ctx.dtls_srtp_materials;
    char *server_key = whep->dtls_ctx.dtls_srtp_materials + DTLS_SRTP_KEY_LEN;
    char *client_salt = server_key + DTLS_SRTP_KEY_LEN;
    char *server_salt = client_salt + DTLS_SRTP_SALT_LEN;

    /* As DTLS server, the recv key is client master key plus salt. */
    memcpy(recv_key, client_key, DTLS_SRTP_KEY_LEN);
    memcpy(recv_key + DTLS_SRTP_KEY_LEN, client_salt, DTLS_SRTP_SALT_LEN);

    /* As DTLS server, the send key is server master key plus salt. */
    memcpy(send_key, server_key, DTLS_SRTP_KEY_LEN);
    memcpy(send_key + DTLS_SRTP_KEY_LEN, server_salt, DTLS_SRTP_SALT_LEN);

    /* Setup SRTP context for outgoing packets */
    if (!av_base64_encode(buf, sizeof(buf), send_key, sizeof(send_key))) {
        av_log(whep, AV_LOG_ERROR, "WHEP: Failed to encode send key\n");
        ret = AVERROR(EIO);
        goto end;
    }
    memcpy(whep->crypto_send_params, buf, sizeof(buf));

    /* Setup SRTP context for incoming packets */
    if (!av_base64_encode(buf, sizeof(buf), recv_key, sizeof(recv_key))) {
        av_log(whep, AV_LOG_ERROR, "WHEP: Failed to encode recv key\n");
        ret = AVERROR(EIO);
        goto end;
    }
    memcpy(whep->crypto_recv_params, buf, sizeof(buf));

    av_log(whep, AV_LOG_VERBOSE, "WHEP: SRTP setup ciphers done, suite=%s, recv key=%luB, elapsed=%dms\n",
           suite, sizeof(send_key), ELAPSED(whep->whep_starttime, av_gettime()));

    return 0;

end:

    av_log(whep, AV_LOG_INFO, "WHEP: debug: setup_srtp 22\n");
    return ret;
}

static int whep_open_transport_ctx(AVFormatContext *s, RTPStream *stream) {
    av_log(s, AV_LOG_INFO, "WHEP: debug: whep_open_transport_ctx 11\n");

    WHEPContext *whep = s->priv_data;
    AVStream *st = NULL;

    if (stream->stream_index >= 0)
        st = s->streams[stream->stream_index];

    av_log(s, AV_LOG_INFO, "WHEP: debug: whep_open_transport_ctx 11, st %p\n", st);

    stream->transport_priv = ff_rtp_parse_open(s, st,
                                                stream->sdp_payload_type,
                                                RTP_REORDER_QUEUE_DEFAULT_SIZE);

    if (!stream->transport_priv) {
         return AVERROR(ENOMEM);
    } 

    RTPDemuxContext *rtpctx = stream->transport_priv;
    rtpctx->ssrc = stream->ssrc;
    if (stream->dynamic_handler) {
        ff_rtp_parse_set_dynamic_protocol(stream->transport_priv,
                                          stream->dynamic_protocol_context,
                                          stream->dynamic_handler);
    }

    if (whep->crypto_suite[0])
        ff_rtp_parse_set_crypto(stream->transport_priv,
                                whep->crypto_suite,
                                whep->crypto_recv_params);


    av_log(s, AV_LOG_INFO, "WHEP: debug: whep_open_transport_ctx 22\n");
    return 0;
}

static int setup_srtp(AVFormatContext *s) 
{
    WHEPContext *whep = s->priv_data;
    int i, err;

    av_log(whep, AV_LOG_INFO, "WHEP: debug: setup_srtp 11\n");

    if (err = setup_srtp_cipher(s)) {
        return err;
    }

    /* open each RTP stream */
    for (i = 0; i < whep->nb_streams; i++) {
        RTPStream *stream = whep->streams[i];

        if ((err = whep_open_transport_ctx(s, stream))) {
            return err;
        }
    }

    if (whep->state < WHEP_STATE_SRTP_FINISHED)
        whep->state = WHEP_STATE_SRTP_FINISHED;
    whep->whep_srtp_time = av_gettime();

    av_log(whep, AV_LOG_VERBOSE, "WHEP: SRTP setup done, state=%d\n", whep->state);


    av_log(whep, AV_LOG_INFO, "WHEP: debug: setup_srtp 22\n");
    return 0;
}

/**
 * RTC is connectionless, for it's based on UDP, so it check whether sesison is
 * timeout. In such case, publishers can't republish the stream util the session
 * is timeout.
 * This function is called to notify the server that the stream is ended, server
 * should expire and close the session immediately, so that publishers can republish
 * the stream quickly.
 */
static int dispose_session(AVFormatContext *s)
{
    int ret;
    char buf[MAX_URL_SIZE];
    URLContext *whep_uc = NULL;
    AVDictionary *opts = NULL;
    WHEPContext *whep = s->priv_data;

    if (!whep->whep_resource_url)
        return 0;

    ret = snprintf(buf, sizeof(buf), "Cache-Control: no-cache\r\n");
    if (whep->authorization)
        ret += snprintf(buf + ret, sizeof(buf) - ret, "Authorization: Bearer %s\r\n", whep->authorization);
    if (ret <= 0 || ret >= sizeof(buf)) {
        av_log(whep, AV_LOG_ERROR, "WHEP: Failed to generate headers, size=%d, %s\n", ret, buf);
        ret = AVERROR(EINVAL);
        goto end;
    }

    av_dict_set(&opts, "headers", buf, 0);
    av_dict_set_int(&opts, "chunked_post", 0, 0);
    av_dict_set(&opts, "method", "DELETE", 0);
    ret = ffurl_open_whitelist(&whep_uc, whep->whep_resource_url, AVIO_FLAG_READ_WRITE, &s->interrupt_callback,
        &opts, s->protocol_whitelist, s->protocol_blacklist, NULL);
    if (ret < 0) {
        av_log(whep, AV_LOG_ERROR, "WHEP: Failed to DELETE url=%s\n", whep->whep_resource_url);
        goto end;
    }

    while (1) {
        ret = ffurl_read(whep_uc, buf, sizeof(buf));
        if (ret == AVERROR_EOF) {
            ret = 0;
            break;
        }
        if (ret < 0) {
            av_log(whep, AV_LOG_ERROR, "WHEP: Failed to read response from DELETE url=%s\n", whep->whep_resource_url);
            goto end;
        }
    }

    av_log(whep, AV_LOG_INFO, "WHEP: Dispose resource %s ok\n", whep->whep_resource_url);

end:
    ffurl_closep(&whep_uc);
    av_dict_free(&opts);
    return ret;
}

typedef struct RTPSource {
    char addr[128]; /**< Source-specific multicast include source IP address (from SDP content) */
} RTPSource;

typedef struct SDPParseState {
    /* SDP only */
    struct sockaddr_storage default_ip;
    int            default_ttl;
    int            skip_media;  ///< set if an unknown m= line occurs
    int nb_default_include_source_addrs; /**< Number of source-specific multicast include source IP address (from SDP content) */
    struct RTPSource **default_include_source_addrs; /**< Source-specific multicast include source IP address (from SDP content) */
    int nb_default_exclude_source_addrs; /**< Number of source-specific multicast exclude source IP address (from SDP content) */
    struct RTPSource **default_exclude_source_addrs; /**< Source-specific multicast exclude source IP address (from SDP content) */
    int seen_rtpmap;
    int seen_fmtp;
    char delayed_fmtp[2048];
} SDPParseState;

static int get_sockaddr(AVFormatContext *s,
                        const char *buf, struct sockaddr_storage *sock)
{
    struct addrinfo hints = { 0 }, *ai = NULL;
    int ret;

    hints.ai_flags = AI_NUMERICHOST;
    if ((ret = getaddrinfo(buf, NULL, &hints, &ai))) {
        av_log(s, AV_LOG_ERROR, "getaddrinfo(%s): %s\n",
               buf,
               gai_strerror(ret));
        return -1;
    }
    memcpy(sock, ai->ai_addr, FFMIN(sizeof(*sock), ai->ai_addrlen));
    freeaddrinfo(ai);
    return 0;
}

static void get_word_until_chars(char *buf, int buf_size,
                                 const char *sep, const char **pp)
{
    const char *p;
    char *q;

    p = *pp;
    p += strspn(p, SPACE_CHARS);
    q = buf;
    while (!strchr(sep, *p) && *p != '\0') {
        if ((q - buf) < buf_size - 1)
            *q++ = *p;
        p++;
    }
    if (buf_size > 0)
        *q = '\0';
    *pp = p;
}

static void get_word_sep(char *buf, int buf_size, const char *sep,
                         const char **pp)
{
    if (**pp == '/') (*pp)++;
    get_word_until_chars(buf, buf_size, sep, pp);
}


static void get_word(char *buf, int buf_size, const char **pp)
{
    get_word_until_chars(buf, buf_size, SPACE_CHARS, pp);
}

static void copy_default_source_addrs(struct RTPSource **addrs, int count,
                                      struct RTPSource ***dest, int *dest_count)
{
    RTPSource *rtp_src, *rtp_src2;
    int i;
    for (i = 0; i < count; i++) {
        rtp_src = addrs[i];
        rtp_src2 = av_memdup(rtp_src, sizeof(*rtp_src));
        if (!rtp_src2)
            continue;
        dynarray_add(dest, dest_count, rtp_src2);
    }
}

static void init_rtp_handler(const RTPDynamicProtocolHandler *handler,
                             RTPStream *stream, AVStream *st)
{
    av_log(NULL, AV_LOG_INFO, "WHEP: debug: init_rtp_handler 11\n");

    AVCodecParameters *par = st ? st->codecpar : NULL;
    if (!handler)
        return;
    if (par)
        par->codec_id          = handler->codec_id;
    stream->dynamic_handler = handler;
    if (st)
        ffstream(st)->need_parsing = handler->need_parsing;
    if (handler->priv_data_size) {
        stream->dynamic_protocol_context = av_mallocz(handler->priv_data_size);
        if (!stream->dynamic_protocol_context)
            stream->dynamic_handler = NULL;
    }
}

static void finalize_rtp_handler_init(AVFormatContext *s, RTPStream *stream,
                                      AVStream *st)
{
    if (stream->dynamic_handler && stream->dynamic_handler->init) {
        int ret = stream->dynamic_handler->init(s, st ? st->index : -1,
                                                 stream->dynamic_protocol_context);
        if (ret < 0) {
            if (stream->dynamic_protocol_context) {
                if (stream->dynamic_handler->close)
                    stream->dynamic_handler->close(
                        stream->dynamic_protocol_context);
                av_free(stream->dynamic_protocol_context);
            }
            stream->dynamic_protocol_context = NULL;
            stream->dynamic_handler = NULL;
        }
    }
}

/* parse the rtpmap description: <codec_name>/<clock_rate>[/<other params>] */
static int sdp_parse_rtpmap(AVFormatContext *s,
                            AVStream *st, RTPStream *stream,
                            int payload_type, const char *p)
{
    AVCodecParameters *par = st->codecpar;
    char buf[256];
    int i;
    const AVCodecDescriptor *desc;
    const char *c_name;

    /* See if we can handle this kind of payload.
     * The space should normally not be there but some Real streams or
     * particular servers ("RealServer Version 6.1.3.970", see issue 1658)
     * have a trailing space. */
    get_word_sep(buf, sizeof(buf), "/ ", &p);
    if (payload_type < RTP_PT_PRIVATE) {
        /* We are in a standard case
         * (from http://www.iana.org/assignments/rtp-parameters). */
        par->codec_id = ff_rtp_codec_id(buf, par->codec_type);
    }

    if (par->codec_id == AV_CODEC_ID_NONE) {

        const RTPDynamicProtocolHandler *handler =
            ff_rtp_handler_find_by_name(buf, par->codec_type);
        init_rtp_handler(handler, stream, st);
        /* If no dynamic handler was found, check with the list of standard
         * allocated types, if such a stream for some reason happens to
         * use a private payload type. This isn't handled in rtpdec.c, since
         * the format name from the rtpmap line never is passed into rtpdec. */
        if (!stream->dynamic_handler)
            par->codec_id = ff_rtp_codec_id(buf, par->codec_type);
    }

    desc = avcodec_descriptor_get(par->codec_id);
    if (desc && desc->name)
        c_name = desc->name;
    else
        c_name = "(null)";

    get_word_sep(buf, sizeof(buf), "/", &p);
    i = atoi(buf);
    switch (par->codec_type) {
    case AVMEDIA_TYPE_AUDIO:
        av_log(s, AV_LOG_DEBUG, "audio codec set to: %s\n", c_name);
        par->sample_rate = WHEP_DEFAULT_AUDIO_SAMPLERATE;
        par->ch_layout = (AVChannelLayout)AV_CHANNEL_LAYOUT_MONO;
        if (i > 0) {
            par->sample_rate = i;
            avpriv_set_pts_info(st, 32, 1, par->sample_rate);
            get_word_sep(buf, sizeof(buf), "/", &p);
            i = atoi(buf);
            if (i > 0)
                av_channel_layout_default(&par->ch_layout, i);
        }
        av_log(s, AV_LOG_DEBUG, "audio samplerate set to: %i\n",
               par->sample_rate);
        av_log(s, AV_LOG_DEBUG, "audio channels set to: %i\n",
               par->ch_layout.nb_channels);
        break;
    case AVMEDIA_TYPE_VIDEO:
        av_log(s, AV_LOG_DEBUG, "video codec set to: %s\n", c_name);
        if (i > 0)
            avpriv_set_pts_info(st, 32, 1, i);
        break;
    default:
        break;
    }

    finalize_rtp_handler_init(s, stream, st);
    return 0;
}

static void parse_fmtp(AVFormatContext *s, WHEPContext *whep,
                       int payload_type, const char *line)
{
    int i;

    for (i = 0; i < whep->nb_streams; i++) {
        RTPStream *stream = whep->streams[i];
        if (stream->sdp_payload_type == payload_type &&
            stream->dynamic_handler &&
            stream->dynamic_handler->parse_sdp_a_line) {
            stream->dynamic_handler->parse_sdp_a_line(s, stream->stream_index,
                stream->dynamic_protocol_context, line);
        }
    }
}

/** Parse a string p in the form of Range:npt=xx-xx, and determine the start
 *  and end time.
 *  Used for seeking in the rtp stream.
 */
static void rtp_parse_range_npt(const char *p, int64_t *start, int64_t *end)
{
    char buf[256];

    p += strspn(p, SPACE_CHARS);
    if (!av_stristart(p, "npt=", &p))
        return;

    *start = AV_NOPTS_VALUE;
    *end = AV_NOPTS_VALUE;

    get_word_sep(buf, sizeof(buf), "-", &p);
    if (av_parse_time(start, buf, 1) < 0)
        return;
    if (*p == '-') {
        p++;
        get_word_sep(buf, sizeof(buf), "-", &p);
        if (av_parse_time(end, buf, 1) < 0)
            av_log(NULL, AV_LOG_DEBUG, "Failed to parse interval end specification '%s'\n", buf);
    }
}

static void sdp_parse_line(AVFormatContext *s, SDPParseState *s1,
                           int letter, const char *buf)
{
    WHEPContext *whep = s->priv_data;

    char buf1[64], st_type[64];
    const char *p;
    enum AVMediaType codec_type;
    int payload_type;
    AVStream *st;
    RTPStream *stream;
    RTPSource *rtp_src;
    struct sockaddr_storage sdp_ip;
    int ttl;

    av_log(s, AV_LOG_TRACE, "sdp: %c='%s'\n", letter, buf);

    p = buf;
    if (s1->skip_media && letter != 'm')
        return;
    switch (letter) {
    case 'c':
        get_word(buf1, sizeof(buf1), &p);
        if (strcmp(buf1, "IN") != 0)
            return;
        get_word(buf1, sizeof(buf1), &p);
        if (strcmp(buf1, "IP4") && strcmp(buf1, "IP6"))
            return;
        get_word_sep(buf1, sizeof(buf1), "/", &p);
        if (get_sockaddr(s, buf1, &sdp_ip))
            return;
        ttl = 16;
        if (*p == '/') {
            p++;
            get_word_sep(buf1, sizeof(buf1), "/", &p);
            ttl = atoi(buf1);
        }
        if (s->nb_streams == 0) {
            s1->default_ip = sdp_ip;
            s1->default_ttl = ttl;
        } else {
            stream = whep->streams[whep->nb_streams - 1];
            stream->sdp_ip = sdp_ip;
            stream->sdp_ttl = ttl;
        }
        break;
    case 's':
        av_dict_set(&s->metadata, "title", p, 0);
        break;
    case 'i':
        if (s->nb_streams == 0) {
            av_dict_set(&s->metadata, "comment", p, 0);
            break;
        }
        break;
    case 'm':
        /* new stream */
        s1->skip_media  = 0;
        s1->seen_fmtp   = 0;
        s1->seen_rtpmap = 0;
        codec_type = AVMEDIA_TYPE_UNKNOWN;
        get_word(st_type, sizeof(st_type), &p);
        if (!strcmp(st_type, "audio")) {
            codec_type = AVMEDIA_TYPE_AUDIO;
        } else if (!strcmp(st_type, "video")) {
            codec_type = AVMEDIA_TYPE_VIDEO;
        } else if (!strcmp(st_type, "application")) {
            codec_type = AVMEDIA_TYPE_DATA;
        } else if (!strcmp(st_type, "text")) {
            codec_type = AVMEDIA_TYPE_SUBTITLE;
        }
        if (codec_type == AVMEDIA_TYPE_UNKNOWN ||
            /* !(whep->media_type_mask & (1 << codec_type)) || */
            whep->nb_streams >= s->max_streams
        ) {
            s1->skip_media = 1;
            return;
        }
        stream = av_mallocz(sizeof(RTPStream));
        if (!stream)
            return;
        stream->stream_index = -1;
        dynarray_add(&whep->streams, &whep->nb_streams, stream);

        stream->sdp_ip = s1->default_ip;
        stream->sdp_ttl = s1->default_ttl;

        copy_default_source_addrs(s1->default_include_source_addrs,
                                  s1->nb_default_include_source_addrs,
                                  &stream->include_source_addrs,
                                  &stream->nb_include_source_addrs);
        copy_default_source_addrs(s1->default_exclude_source_addrs,
                                  s1->nb_default_exclude_source_addrs,
                                  &stream->exclude_source_addrs,
                                  &stream->nb_exclude_source_addrs);

        get_word(buf1, sizeof(buf1), &p); /* port */
        stream->sdp_port = atoi(buf1);

        get_word(buf1, sizeof(buf1), &p); /* protocol */

        if (strstr(buf1, "/AVPF") || strstr(buf1, "/SAVPF"))
            stream->feedback = 1;

        /* XXX: handle list of formats */
        get_word(buf1, sizeof(buf1), &p); /* format list */
        stream->sdp_payload_type = atoi(buf1);

        st = avformat_new_stream(s, NULL);
        if (!st)
            return;
        st->id = whep->nb_streams - 1;
        stream->stream_index = st->index;
        st->codecpar->codec_type = codec_type;
        if (stream->sdp_payload_type < RTP_PT_PRIVATE) {
            const RTPDynamicProtocolHandler *handler;
            /* if standard payload type, we can find the codec right now */
            ff_rtp_get_codec_info(st->codecpar, stream->sdp_payload_type);
            if (st->codecpar->codec_type == AVMEDIA_TYPE_AUDIO &&
                st->codecpar->sample_rate > 0)
                avpriv_set_pts_info(st, 32, 1, st->codecpar->sample_rate);
            /* Even static payload types may need a custom depacketizer */
            handler = ff_rtp_handler_find_by_id(
                          stream->sdp_payload_type, st->codecpar->codec_type);
            init_rtp_handler(handler, stream, st);
            finalize_rtp_handler_init(s, stream, st);
        }
        break;
    case 'a':
        if (av_strstart(p, "rtpmap:", &p) && s->nb_streams > 0) {
            /* NOTE: rtpmap is only supported AFTER the 'm=' tag */
            get_word(buf1, sizeof(buf1), &p);
            payload_type = atoi(buf1);
            stream = whep->streams[whep->nb_streams - 1];
            if (stream->stream_index >= 0) {
                st = s->streams[stream->stream_index];
                sdp_parse_rtpmap(s, st, stream, payload_type, p);
            }
            s1->seen_rtpmap = 1;
            if (s1->seen_fmtp) {
                parse_fmtp(s, whep, payload_type, s1->delayed_fmtp);
            }
        } else if (av_strstart(p, "fmtp:", &p) ||
                   av_strstart(p, "framesize:", &p)) {
            // let dynamic protocol handlers have a stab at the line.
            get_word(buf1, sizeof(buf1), &p);
            payload_type = atoi(buf1);
            if (s1->seen_rtpmap) {
                parse_fmtp(s, whep, payload_type, buf);
            } else {
                s1->seen_fmtp = 1;
                av_strlcpy(s1->delayed_fmtp, buf, sizeof(s1->delayed_fmtp));
            }
        } else if (av_strstart(p, "ssrc:", &p) && s->nb_streams > 0) {
            stream = whep->streams[whep->nb_streams - 1];
            get_word(buf1, sizeof(buf1), &p);
            stream->ssrc = strtoll(buf1, NULL, 10);
        } else if (av_strstart(p, "range:", &p)) {
            int64_t start, end;

            // this is so that seeking on a streamed file can work.
            rtp_parse_range_npt(p, &start, &end);
            s->start_time = start;
            /* AV_NOPTS_VALUE means live broadcast (and can't seek) */
            s->duration   = (end == AV_NOPTS_VALUE) ?
                            AV_NOPTS_VALUE : end - start;
        } else if (av_strstart(p, "lang:", &p)) {
            if (s->nb_streams > 0) {
                get_word(buf1, sizeof(buf1), &p);
                stream = whep->streams[whep->nb_streams - 1];
                if (stream->stream_index >= 0) {
                    st = s->streams[stream->stream_index];
                    av_dict_set(&st->metadata, "language", buf1, 0);
                }
            } 
        } else if (av_strstart(p, "SampleRate:integer;", &p) &&
                   s->nb_streams > 0) {
            st = s->streams[s->nb_streams - 1];
            st->codecpar->sample_rate = atoi(p);
        } else if (av_strstart(p, "source-filter:", &p)) {
            int exclude = 0;
            get_word(buf1, sizeof(buf1), &p);
            if (strcmp(buf1, "incl") && strcmp(buf1, "excl"))
                return;
            exclude = !strcmp(buf1, "excl");

            get_word(buf1, sizeof(buf1), &p);
            if (strcmp(buf1, "IN") != 0)
                return;
            get_word(buf1, sizeof(buf1), &p);
            if (strcmp(buf1, "IP4") && strcmp(buf1, "IP6") && strcmp(buf1, "*"))
                return;
            // not checking that the destination address actually matches or is wildcard
            get_word(buf1, sizeof(buf1), &p);

            while (*p != '\0') {
                rtp_src = av_mallocz(sizeof(*rtp_src));
                if (!rtp_src)
                    return;
                get_word(rtp_src->addr, sizeof(rtp_src->addr), &p);
                if (exclude) {
                    if (s->nb_streams == 0) {
                        dynarray_add(&s1->default_exclude_source_addrs, &s1->nb_default_exclude_source_addrs, rtp_src);
                    } else {
                        stream = whep->streams[whep->nb_streams - 1];
                        dynarray_add(&stream->exclude_source_addrs, &stream->nb_exclude_source_addrs, rtp_src);
                    }
                } else {
                    if (s->nb_streams == 0) {
                        dynarray_add(&s1->default_include_source_addrs, &s1->nb_default_include_source_addrs, rtp_src);
                    } else {
                        stream = whep->streams[whep->nb_streams - 1];
                        dynarray_add(&stream->include_source_addrs, &stream->nb_include_source_addrs, rtp_src);
                    }
                }
            }
        } else {

            if (s->nb_streams > 0) {
                stream = whep->streams[whep->nb_streams - 1];

                if (stream->dynamic_handler &&
                    stream->dynamic_handler->parse_sdp_a_line)
                    stream->dynamic_handler->parse_sdp_a_line(s,
                        stream->stream_index,
                        stream->dynamic_protocol_context, buf);
            }
        }
        break;
    }
}

static int parse_answer_media(AVFormatContext *s)
{
    const char *p;
    int letter, i;
    char buf[MAX_SDP_SIZE], *q;
    SDPParseState sdp_parse_state = { { 0 } }, *s1 = &sdp_parse_state;
    WHEPContext *whep = s->priv_data;

    av_log(whep, AV_LOG_INFO, "WHEP: debug: parse_answer_media 11\n");
    p = whep->sdp_answer;
    for (;;) {
        p += strspn(p, SPACE_CHARS);
        letter = *p;
        if (letter == '\0')
            break;
        p++;
        if (*p != '=')
            goto next_line;
        p++;
        /* get the content */
        q = buf;
        while (*p != '\n' && *p != '\r' && *p != '\0') {
            if ((q - buf) < sizeof(buf) - 1)
                *q++ = *p;
            p++;
        }
        *q = '\0';
        sdp_parse_line(s, s1, letter, buf);
    next_line:
        while (*p != '\n' && *p != '\0')
            p++;
        if (*p == '\n')
            p++;
    }

    for (i = 0; i < s1->nb_default_include_source_addrs; i++)
        av_freep(&s1->default_include_source_addrs[i]);
    av_freep(&s1->default_include_source_addrs);
    for (i = 0; i < s1->nb_default_exclude_source_addrs; i++)
        av_freep(&s1->default_exclude_source_addrs[i]);
    av_freep(&s1->default_exclude_source_addrs);



    av_log(whep, AV_LOG_INFO, "WHEP: debug: parse_answer_media 22\n");
    return 0;
}



static av_cold int whep_read_header(AVFormatContext *s)
{
    int ret;
    WHEPContext *whep = s->priv_data;

    av_log(whep, AV_LOG_INFO, "WHEP: debug: whep_read_header 11\n");

    if ((ret = initialize(s)) < 0)
        goto end;

    if ((ret = generate_sdp_offer(s)) < 0)
        goto end;

    if ((ret = exchange_sdp(s)) < 0)
        goto end;

    if ((ret = parse_answer_ice(s)) < 0)
        goto end;

    if ((ret = parse_answer_media(s)) < 0)
        goto end;

    if ((ret = udp_connect(s)) < 0)
        goto end;

    if ((ret = ice_dtls_handshake(s)) < 0)
        goto end;

    if ((ret = setup_srtp(s)) < 0)
        goto end;

end:
    if (ret < 0 && whep->state < WHEP_STATE_FAILED) {
        av_log(whep, AV_LOG_INFO, "WHEP: debug: whep_read_header 2200, ret %d\n", ret);
        whep->state = WHEP_STATE_FAILED;
    }
    if (ret >= 0 && whep->state >= WHEP_STATE_FAILED && whep->dtls_ret < 0) {
        av_log(whep, AV_LOG_INFO, "WHEP: debug: whep_read_header 2211, ret %d\n", ret);
        ret = whep->dtls_ret;
    }

    av_log(whep, AV_LOG_INFO, "WHEP: debug: whep_read_header 22, ret %d\n", ret);
    return ret;
}

static int whep_read_packet(AVFormatContext *s, AVPacket *pkt)
{

    int ret;
    WHEPContext *whep = s->priv_data;
    /* AVStream *st = s->streams[pkt->stream_index]; */
    /* AVFormatContext *rtp_ctx = st->priv_data; */
    /* av_log(whep, AV_LOG_INFO, "WHEP: debug: whep_read_packet 11\n"); */

    /* TODO: Send binding request every 1s as WebRTC heartbeat. */

    /**
     * Receive packets from the server such as ICE binding requests, DTLS messages,
     * and RTCP like PLI requests, then respond to them.
     */
    ret = ffurl_read(whep->udp_uc, whep->recvbuf, whep->recvbuf_size);
    if (ret > 0) {
        if (is_dtls_packet(whep->recvbuf, ret)) {
            av_log(whep, AV_LOG_ERROR, "WHEP: is dtls packet\n");
            if ((ret = dtls_context_write(&whep->dtls_ctx, whep->recvbuf, ret)) < 0) {
                av_log(whep, AV_LOG_ERROR, "WHEP: Failed to handle DTLS message\n");
                goto end;
            }
        } else if (media_is_rtp_rtcp(whep->recvbuf, ret)) {
            if (media_is_rtcp(whep->recvbuf, ret)) {
                /* av_log(whep, AV_LOG_INFO, "WHEP: read rtcp data, len %d\n", ret); */
            } else {
                /* av_log(whep, AV_LOG_INFO, "WHEP: read rtp data, len %d\n", ret); */
                RTPStream *stream = get_stream_by_payload(whep, get_rtp_payload(whep->recvbuf, ret));
                if (stream) {
                    uint8_t* recvbuf = av_memdup(whep->recvbuf, ret);

                    AVIOContext *pb = NULL;
                    ffio_fdopen(&pb, whep->udp_uc);
                    pb->write_flag = 0;
                    /* av_log(whep, AV_LOG_INFO, "WHEP: proc rtp data, len %d, pkt: %p\n", ret, pkt); */
                    ff_rtp_check_and_send_back_rr(stream->transport_priv, NULL, pb, ret);
                    ret = ff_rtp_parse_packet(stream->transport_priv, pkt, &recvbuf, ret);
                    //rtcp
                    /* ff_rtp_send_rtcp_feedback(stream->transport_priv, NULL, pb); */
                    /* avio_close(pb); */
                }
            }
        }  else {
            av_log(whep, AV_LOG_INFO, "WHEP: read other type data, len %d\n", ret);
        }
    } else if (ret != AVERROR(EAGAIN)) {
        av_log(whep, AV_LOG_ERROR, "WHEP: Failed to read from UDP socket, ret: %d\n", ret);
        goto end;
    } else {
        return 0;
    }

    /* av_log(whep, AV_LOG_INFO, "WHEP: debug: whep_read_packet 1100\n"); */

end:
    if (ret < 0 && whep->state < WHEP_STATE_FAILED) {
        av_log(whep, AV_LOG_INFO, "WHEP: debug: whep_read_packet 22 fail ret: %d\n", ret);
        /* av_log(whep, AV_LOG_INFO, "WHEP: debug: whep_read_packet 22 ret: %d\n", ret); */
    }
    if (ret >= 0 && whep->state >= WHEP_STATE_FAILED && whep->dtls_ret < 0)
        ret = whep->dtls_ret;
    if (ret >= 0 && whep->dtls_closed)
        ret = AVERROR(EIO);

    /* av_log(whep, AV_LOG_INFO, "WHEP: debug: whep_read_packet 22 ret: %d\n", ret); */
    return ret;
}

static av_cold int whep_read_close(AVFormatContext *s)
{
    int i, ret;
    WHEPContext *whep = s->priv_data;
    av_log(whep, AV_LOG_INFO, "WHEP: debug: whep_read_close 11\n");

    ret = dispose_session(s);
    if (ret < 0)
        av_log(whep, AV_LOG_WARNING, "WHEP: Failed to dispose resource, ret=%d\n", ret);

    for (i = 0; i < s->nb_streams; i++) {
        AVFormatContext* rtp_ctx = s->streams[i]->priv_data;
        if (!rtp_ctx)
            continue;

        av_write_trailer(rtp_ctx);
        /**
         * Keep in mind that it is necessary to free the buffer of pb since we allocate
         * it and pass it to pb using avio_alloc_context, while avio_context_free does
         * not perform this action.
         */
        av_freep(&rtp_ctx->pb->buffer);
        avio_context_free(&rtp_ctx->pb);
        avformat_free_context(rtp_ctx);
        s->streams[i]->priv_data = NULL;
    }

    av_freep(&whep->sdp_offer);
    av_freep(&whep->sdp_answer);
    av_freep(&whep->whep_resource_url);
    av_freep(&whep->ice_ufrag_remote);
    av_freep(&whep->ice_pwd_remote);
    av_freep(&whep->ice_protocol);
    av_freep(&whep->ice_host);
    av_freep(&whep->authorization);
    av_freep(&whep->cert_file);
    av_freep(&whep->key_file);
    av_freep(&whep->recvbuf);
    ffurl_closep(&whep->udp_uc);
    ff_srtp_free(&whep->srtp_rtcp_send);
    dtls_context_deinit(&whep->dtls_ctx);

    av_log(whep, AV_LOG_INFO, "WHEP: debug: whep_read_close 22\n");
    return 0;
}

#define OFFSET(x) offsetof(WHEPContext, x)
#define DEC AV_OPT_FLAG_DECODING_PARAM
static const AVOption options[] = {
    { "handshake_timeout",  "Timeout in milliseconds for ICE and DTLS handshake.",      OFFSET(handshake_timeout),  AV_OPT_TYPE_INT,    { .i64 = 5000 },    -1, INT_MAX, DEC },
    { "pkt_size",           "The maximum size, in bytes, of RTP packets that send out", OFFSET(pkt_size),           AV_OPT_TYPE_INT,    { .i64 = 1500 },    -1, INT_MAX, DEC },
    { "authorization",      "The optional Bearer token for WHEP Authorization",         OFFSET(authorization),      AV_OPT_TYPE_STRING, { .str = NULL },     0,       0, DEC },
    { "cert_file",          "The optional certificate file path for DTLS",              OFFSET(cert_file),          AV_OPT_TYPE_STRING, { .str = NULL },     0,       0, DEC },
    { "key_file",           "The optional private key file path for DTLS",              OFFSET(key_file),      AV_OPT_TYPE_STRING, { .str = NULL },     0,       0, DEC },
    { NULL },
};

static const AVClass whep_demuxer_class = {
    .class_name = "WHEP demuxer",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const AVInputFormat ff_whep_demuxer = {
    .name             = "whep",
    .long_name        = NULL_IF_CONFIG_SMALL("WHEP(WebRTC-HTTP egress protocol) muxer"),
    .flags            = AVFMT_GLOBALHEADER | AVFMT_NOFILE,
    .priv_class       = &whep_demuxer_class,
    .priv_data_size   = sizeof(WHEPContext),
    .read_header      = whep_read_header,
    .read_packet      = whep_read_packet,
    .read_close       = whep_read_close,
};

