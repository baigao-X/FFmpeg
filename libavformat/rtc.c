/*
 * WebRTC protocol
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

#include "libavutil/time.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/random_seed.h"
#include "libavutil/crc.h"
#include "libavutil/hmac.h"
#include "libavutil/mem.h"
#include "libavutil/base64.h"

#include "avio_internal.h"
#include "internal.h"
#include "network.h"
#include "http.h"
#include "rtc.h"

/**
 * Maximum size limit of a Session Description Protocol (SDP),
 * be it an offer or answer.
 */
#define MAX_SDP_SIZE 8192

/**
 * The size of the Secure Real-time Transport Protocol (SRTP) master key material
 * that is exported by Secure Sockets Layer (SSL) after a successful Datagram
 * Transport Layer Security (DTLS) handshake. This material consists of a key
 * of 16 bytes and a salt of 14 bytes.
 */
#define DTLS_SRTP_KEY_LEN 16
#define DTLS_SRTP_SALT_LEN 14

/**
 * If we try to read from UDP and get EAGAIN, we sleep for 5ms and retry up to 10 times.
 * This will limit the total duration (in milliseconds, 50ms)
 */
#define ICE_DTLS_READ_MAX_RETRY 10
#define ICE_DTLS_READ_SLEEP_DURATION 5

/* The magic cookie for Session Traversal Utilities for NAT (STUN) messages. */
#define STUN_MAGIC_COOKIE 0x2112A442

/**
 * Refer to RFC 8445 5.1.2
 * priority = (2^24)*(type preference) + (2^8)*(local preference) + (2^0)*(256 - component ID)
 * host candidate priority is 126 << 24 | 65535 << 8 | 255
 */
#define STUN_HOST_CANDIDATE_PRIORITY 126 << 24 | 65535 << 8 | 255

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

/**
 * Maximum size of the buffer for sending and receiving UDP packets.
 * Please note that this size does not limit the size of the UDP packet that can be sent.
 * To set the limit for packet size, modify the `pkt_size` parameter.
 * For instance, it is possible to set the UDP buffer to 4096 to send or receive packets,
 * but please keep in mind that the `pkt_size` option limits the packet size to 1400.
 */
#define MAX_UDP_BUFFER_SIZE 4096

/* Referring to Chrome's definition of RTP payload types. */
#define RTC_RTP_PAYLOAD_TYPE_H264 106
#define RTC_RTP_PAYLOAD_TYPE_OPUS 111
#define RTC_RTP_PAYLOAD_TYPE_VIDEO_RTX 105

/**
 * The STUN message header, which is 20 bytes long, comprises the
 * STUNMessageType (1B), MessageLength (2B), MagicCookie (4B),
 * and TransactionID (12B).
 * See https://datatracker.ietf.org/doc/html/rfc5389#section-6
 */
#define ICE_STUN_HEADER_SIZE 20

/**
 * In the case of ICE-LITE, these fields are not used; instead, they are defined
 * as constant values.
 */
#define RTC_SDP_SESSION_ID "4489045141692799359"
#define RTC_SDP_CREATOR_IP "127.0.0.1"

/* Calculate the elapsed time from starttime to endtime in milliseconds. */
#define ELAPSED(starttime, endtime) ((float)(endtime - starttime) / 1000)

/* STUN Attribute, comprehension-required range (0x0000-0x7FFF) */
enum STUNAttr {
    STUN_ATTR_USERNAME                  = 0x0006, /// shared secret response/bind request
    STUN_ATTR_PRIORITY                  = 0x0024, /// must be included in a Binding request
    STUN_ATTR_USE_CANDIDATE             = 0x0025, /// bind request
    STUN_ATTR_MESSAGE_INTEGRITY         = 0x0008, /// bind request/response
    STUN_ATTR_FINGERPRINT               = 0x8028, /// rfc5389
    STUN_ATTR_ICE_CONTROLLING           = 0x802A, /// ICE controlling role
};

/**
 * Whether the packet is a DTLS packet.
 */
int ff_rtc_is_dtls_packet(uint8_t *b, int size) {
    uint16_t version = AV_RB16(&b[1]);
    return size > DTLS_RECORD_LAYER_HEADER_LEN &&
        b[0] >= DTLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC &&
        (version == DTLS_VERSION_10 || version == DTLS_VERSION_12);
}

/**
 * Get or Generate a self-signed certificate and private key for DTLS,
 * fingerprint for SDP
 */
static av_cold int certificate_key_init(AVFormatContext *s)
{
    int ret = 0;
    RTCContext *rtc = s->priv_data;

    if (rtc->cert_file && rtc->key_file) {
        /* Read the private key and certificate from the file. */
        if ((ret = ff_ssl_read_key_cert(rtc->key_file, rtc->cert_file,
                                        rtc->key_buf, sizeof(rtc->key_buf),
                                        rtc->cert_buf, sizeof(rtc->cert_buf),
                                        &rtc->dtls_fingerprint)) < 0) {
            av_log(s, AV_LOG_ERROR, "Failed to read DTLS certificate from cert=%s, key=%s\n",
                rtc->cert_file, rtc->key_file);
            return ret;
        }
    } else {
        /* Generate a private key to ctx->dtls_pkey and self-signed certificate. */
        if ((ret = ff_ssl_gen_key_cert(rtc->key_buf, sizeof(rtc->key_buf),
                                       rtc->cert_buf, sizeof(rtc->cert_buf),
                                       &rtc->dtls_fingerprint)) < 0) {
            av_log(s, AV_LOG_ERROR, "Failed to generate DTLS private key and certificate\n");
            return ret;
        }
    }

    return ret;
}

static av_cold int dtls_initialize(AVFormatContext *s)
{
    RTCContext *rtc = s->priv_data;
    /* reuse the udp created by rtc */
    ff_tls_set_external_socket(rtc->dtls_uc, rtc->udp);

    /* Make the socket non-blocking */
    ff_socket_nonblock(ffurl_get_file_handle(rtc->dtls_uc), 1);
    rtc->dtls_uc->flags |= AVIO_FLAG_NONBLOCK;

    return 0;
}

/**
 * Initialize and check the options for the WebRTC muxer.
 */
av_cold int ff_rtc_initialize(AVFormatContext *s)
{
    int ret, ideal_pkt_size = 532;
    RTCContext *rtc = s->priv_data;
    uint32_t seed;

    rtc->rtc_starttime = av_gettime_relative();

    ret = certificate_key_init(s);
    if (ret < 0) {
        av_log(rtc, AV_LOG_ERROR, "Failed to init certificate and key\n");
        return ret;
    }

    /* Initialize the random number generator. */
    seed = av_get_random_seed();
    av_lfg_init(&rtc->rnd, seed);

    /* 64 bit tie breaker for ICE-CONTROLLING (RFC 8445 16.1) */
    ret = av_random_bytes((uint8_t *)&rtc->ice_tie_breaker, sizeof(rtc->ice_tie_breaker));
    if (ret < 0) {
        av_log(rtc, AV_LOG_ERROR, "Couldn't generate random bytes for ICE tie breaker\n");
        return ret;
    }

    rtc->audio_first_seq = av_lfg_get(&rtc->rnd) & 0x0fff;
    rtc->video_first_seq = rtc->audio_first_seq + 1;

    if (rtc->pkt_size < ideal_pkt_size)
        av_log(rtc, AV_LOG_WARNING, "pkt_size=%d(<%d) is too small, may cause packet loss\n",
               rtc->pkt_size, ideal_pkt_size);

    if (rtc->state < RTC_STATE_INIT)
        rtc->state = RTC_STATE_INIT;
    rtc->rtc_init_time = av_gettime_relative();
    av_log(rtc, AV_LOG_VERBOSE, "Init state=%d, handshake_timeout=%dms, pkt_size=%d, seed=%d, elapsed=%.2fms\n",
        rtc->state, rtc->handshake_timeout, rtc->pkt_size, seed, ELAPSED(rtc->rtc_starttime, av_gettime_relative()));

    return 0;
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
    int ret = 0, profile_idc = 0, level, profile_iop = 0;
    const char *acodec_name = NULL, *vcodec_name = NULL;
    AVBPrint bp;
    RTCContext *rtc = s->priv_data;

    /* To prevent a crash during cleanup, always initialize it. */
    av_bprint_init(&bp, 1, MAX_SDP_SIZE);

    if (rtc->sdp_offer) {
        av_log(rtc, AV_LOG_ERROR, "SDP offer is already set\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    snprintf(rtc->ice_ufrag_local, sizeof(rtc->ice_ufrag_local), "%08x",
        av_lfg_get(&rtc->rnd));
    snprintf(rtc->ice_pwd_local, sizeof(rtc->ice_pwd_local), "%08x%08x%08x%08x",
        av_lfg_get(&rtc->rnd), av_lfg_get(&rtc->rnd), av_lfg_get(&rtc->rnd),
        av_lfg_get(&rtc->rnd));

    rtc->audio_ssrc = av_lfg_get(&rtc->rnd);
    rtc->video_ssrc = rtc->audio_ssrc + 1;
    rtc->video_rtx_ssrc = rtc->video_ssrc + 1;

    rtc->audio_payload_type = RTC_RTP_PAYLOAD_TYPE_OPUS;
    rtc->video_payload_type = RTC_RTP_PAYLOAD_TYPE_H264;
    rtc->video_rtx_payload_type = RTC_RTP_PAYLOAD_TYPE_VIDEO_RTX;

    av_bprintf(&bp, ""
        "v=0\r\n"
        "o=FFmpeg %s 2 IN IP4 %s\r\n"
        "s=FFmpegPublishSession\r\n"
        "t=0 0\r\n"
        "a=group:BUNDLE 0 1\r\n"
        "a=extmap-allow-mixed\r\n"
        "a=msid-semantic: WMS\r\n",
        RTC_SDP_SESSION_ID,
        RTC_SDP_CREATOR_IP);

    if (rtc->audio_par) {
        if (rtc->audio_par->codec_id == AV_CODEC_ID_OPUS)
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
            "a=rtpmap:%u %s/%d/%d\r\n"
            "a=ssrc:%u cname:FFmpeg\r\n"
            "a=ssrc:%u msid:FFmpeg audio\r\n",
            rtc->audio_payload_type,
            rtc->ice_ufrag_local,
            rtc->ice_pwd_local,
            rtc->dtls_fingerprint,
            rtc->audio_payload_type,
            acodec_name,
            rtc->audio_par->sample_rate,
            rtc->audio_par->ch_layout.nb_channels,
            rtc->audio_ssrc,
            rtc->audio_ssrc);
    }

    if (rtc->video_par) {
        level = rtc->video_par->level;
        if (rtc->video_par->codec_id == AV_CODEC_ID_H264) {
            vcodec_name = "H264";
            profile_iop |= rtc->video_par->profile & AV_PROFILE_H264_CONSTRAINED ? 1 << 6 : 0;
            profile_iop |= rtc->video_par->profile & AV_PROFILE_H264_INTRA ? 1 << 4 : 0;
            profile_idc = rtc->video_par->profile & 0x00ff;
        }

        av_bprintf(&bp, ""
            "m=video 9 UDP/TLS/RTP/SAVPF %u %u\r\n"
            "c=IN IP4 0.0.0.0\r\n"
            "a=ice-ufrag:%s\r\n"
            "a=ice-pwd:%s\r\n"
            "a=fingerprint:sha-256 %s\r\n"
            "a=setup:passive\r\n"
            "a=mid:1\r\n"
            "a=sendonly\r\n"
            "a=msid:FFmpeg video\r\n"
            "a=rtcp-mux\r\n"
            "a=rtcp-rsize\r\n"
            "a=rtpmap:%u %s/90000\r\n"
            "a=fmtp:%u level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=%02x%02x%02x\r\n"
            "a=rtcp-fb%u nack\r\n"
            "a=rtpmap:%u rtx/90000\r\n"
            "a=fmtp:%u apt=%u\r\n"
            "a=ssrc-group:FID %u %u\r\n"
            "a=ssrc:%u cname:FFmpeg\r\n"
            "a=ssrc:%u msid:FFmpeg video\r\n",
            rtc->video_payload_type,
            rtc->video_rtx_payload_type,
            rtc->ice_ufrag_local,
            rtc->ice_pwd_local,
            rtc->dtls_fingerprint,
            rtc->video_payload_type,
            vcodec_name,
            rtc->video_payload_type,
            profile_idc,
            profile_iop,
            level,
            rtc->video_payload_type,
            rtc->video_rtx_payload_type,
            rtc->video_rtx_payload_type,
            rtc->video_payload_type,
            rtc->video_ssrc,
            rtc->video_rtx_ssrc,
            rtc->video_ssrc,
            rtc->video_ssrc);
    }

    if (!av_bprint_is_complete(&bp)) {
        av_log(rtc, AV_LOG_ERROR, "Offer exceed max %d, %s\n", MAX_SDP_SIZE, bp.str);
        ret = AVERROR(EIO);
        goto end;
    }

    rtc->sdp_offer = av_strdup(bp.str);
    if (!rtc->sdp_offer) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    if (rtc->state < RTC_STATE_OFFER)
        rtc->state = RTC_STATE_OFFER;
    rtc->rtc_offer_time = av_gettime_relative();
    av_log(rtc, AV_LOG_VERBOSE, "Generated state=%d, offer: %s\n", rtc->state, rtc->sdp_offer);

end:
    av_bprint_finalize(&bp, NULL);
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
    RTCContext *rtc = s->priv_data;
    /* The URL context is an HTTP transport layer for the WHIP/WHEP protocol. */
    URLContext *rtc_uc = NULL;
    AVDictionary *opts = NULL;
    char *hex_data = NULL;
    const char *proto_name = avio_find_protocol_name(s->url);

    /* To prevent a crash during cleanup, always initialize it. */
    av_bprint_init(&bp, 1, MAX_SDP_SIZE);

    if (!av_strstart(proto_name, "http", NULL)) {
        av_log(rtc, AV_LOG_ERROR, "Protocol %s is not supported by RTC, choose http, url is %s\n",
            proto_name, s->url);
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (!rtc->sdp_offer || !strlen(rtc->sdp_offer)) {
        av_log(rtc, AV_LOG_ERROR, "No offer to exchange\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    ret = snprintf(buf, sizeof(buf), "Cache-Control: no-cache\r\nContent-Type: application/sdp\r\n");
    if (rtc->authorization)
        ret += snprintf(buf + ret, sizeof(buf) - ret, "Authorization: Bearer %s\r\n", rtc->authorization);
    if (ret <= 0 || ret >= sizeof(buf)) {
        av_log(rtc, AV_LOG_ERROR, "Failed to generate headers, size=%d, %s\n", ret, buf);
        ret = AVERROR(EINVAL);
        goto end;
    }

    av_dict_set(&opts, "headers", buf, 0);
    av_dict_set_int(&opts, "chunked_post", 0, 0);

    hex_data = av_mallocz(2 * strlen(rtc->sdp_offer) + 1);
    if (!hex_data) {
        ret = AVERROR(ENOMEM);
        goto end;
    }
    ff_data_to_hex(hex_data, rtc->sdp_offer, strlen(rtc->sdp_offer), 0);
    av_dict_set(&opts, "post_data", hex_data, 0);

    ret = ffurl_open_whitelist(&rtc_uc, s->url, AVIO_FLAG_READ_WRITE, &s->interrupt_callback,
        &opts, s->protocol_whitelist, s->protocol_blacklist, NULL);
    if (ret < 0) {
        av_log(rtc, AV_LOG_ERROR, "Failed to request url=%s, offer: %s\n", s->url, rtc->sdp_offer);
        goto end;
    }

    if (ff_http_get_new_location(rtc_uc)) {
        rtc->rtc_resource_url = av_strdup(ff_http_get_new_location(rtc_uc));
        if (!rtc->rtc_resource_url) {
            ret = AVERROR(ENOMEM);
            goto end;
        }
    }

    while (1) {
        ret = ffurl_read(rtc_uc, buf, sizeof(buf));
        if (ret == AVERROR_EOF) {
            /* Reset the error because we read all response as answer util EOF. */
            ret = 0;
            break;
        }
        if (ret <= 0) {
            av_log(rtc, AV_LOG_ERROR, "Failed to read response from url=%s, offer is %s, answer is %s\n",
                s->url, rtc->sdp_offer, rtc->sdp_answer);
            goto end;
        }

        av_bprintf(&bp, "%.*s", ret, buf);
        if (!av_bprint_is_complete(&bp)) {
            av_log(rtc, AV_LOG_ERROR, "Answer exceed max size %d, %.*s, %s\n", MAX_SDP_SIZE, ret, buf, bp.str);
            ret = AVERROR(EIO);
            goto end;
        }
    }

    if (!av_strstart(bp.str, "v=", NULL)) {
        av_log(rtc, AV_LOG_ERROR, "Invalid answer: %s\n", bp.str);
        ret = AVERROR(EINVAL);
        goto end;
    }

    rtc->sdp_answer = av_strdup(bp.str);
    if (!rtc->sdp_answer) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    if (rtc->state < RTC_STATE_ANSWER)
        rtc->state = RTC_STATE_ANSWER;
    av_log(rtc, AV_LOG_VERBOSE, "Got state=%d, answer: %s\n", rtc->state, rtc->sdp_answer);

end:
    ffurl_closep(&rtc_uc);
    av_bprint_finalize(&bp, NULL);
    av_dict_free(&opts);
    av_freep(&hex_data);
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
static int parse_answer(AVFormatContext *s)
{
    int ret = 0;
    AVIOContext *pb;
    char line[MAX_URL_SIZE];
    const char *ptr;
    int i;
    RTCContext *rtc = s->priv_data;

    if (!rtc->sdp_answer || !strlen(rtc->sdp_answer)) {
        av_log(rtc, AV_LOG_ERROR, "No answer to parse\n");
        ret = AVERROR(EINVAL);
        goto end;
    }

    pb = avio_alloc_context(rtc->sdp_answer, strlen(rtc->sdp_answer), 0, NULL, NULL, NULL, NULL);
    if (!pb)
        return AVERROR(ENOMEM);

    for (i = 0; !avio_feof(pb); i++) {
        ff_get_chomp_line(pb, line, sizeof(line));
        if (av_strstart(line, "a=ice-lite", &ptr))
            rtc->is_peer_ice_lite = 1;
        if (av_strstart(line, "a=ice-ufrag:", &ptr) && !rtc->ice_ufrag_remote) {
            rtc->ice_ufrag_remote = av_strdup(ptr);
            if (!rtc->ice_ufrag_remote) {
                ret = AVERROR(ENOMEM);
                goto end;
            }
        } else if (av_strstart(line, "a=ice-pwd:", &ptr) && !rtc->ice_pwd_remote) {
            rtc->ice_pwd_remote = av_strdup(ptr);
            if (!rtc->ice_pwd_remote) {
                ret = AVERROR(ENOMEM);
                goto end;
            }
        } else if (av_strstart(line, "a=candidate:", &ptr) && !rtc->ice_protocol) {
            if (ptr && av_stristr(ptr, "host")) {
                /* Refer to RFC 5245 15.1 */
                char foundation[33], protocol[17], host[129];
                int component_id, priority, port;
                ret = sscanf(ptr, "%32s %d %16s %d %128s %d typ host", foundation, &component_id, protocol, &priority, host, &port);
                if (ret != 6) {
                    av_log(rtc, AV_LOG_ERROR, "Failed %d to parse line %d %s from %s\n",
                        ret, i, line, rtc->sdp_answer);
                    ret = AVERROR(EIO);
                    goto end;
                }

                if (av_strcasecmp(protocol, "udp")) {
                    av_log(rtc, AV_LOG_ERROR, "Protocol %s is not supported by RTC, choose udp, line %d %s of %s\n",
                        protocol, i, line, rtc->sdp_answer);
                    ret = AVERROR(EIO);
                    goto end;
                }

                rtc->ice_protocol = av_strdup(protocol);
                rtc->ice_host = av_strdup(host);
                rtc->ice_port = port;
                if (!rtc->ice_protocol || !rtc->ice_host) {
                    ret = AVERROR(ENOMEM);
                    goto end;
                }
            }
        }
    }

    if (!rtc->ice_pwd_remote || !strlen(rtc->ice_pwd_remote)) {
        av_log(rtc, AV_LOG_ERROR, "No remote ice pwd parsed from %s\n", rtc->sdp_answer);
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (!rtc->ice_ufrag_remote || !strlen(rtc->ice_ufrag_remote)) {
        av_log(rtc, AV_LOG_ERROR, "No remote ice ufrag parsed from %s\n", rtc->sdp_answer);
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (!rtc->ice_protocol || !rtc->ice_host || !rtc->ice_port) {
        av_log(rtc, AV_LOG_ERROR, "No ice candidate parsed from %s\n", rtc->sdp_answer);
        ret = AVERROR(EINVAL);
        goto end;
    }

    if (rtc->state < RTC_STATE_NEGOTIATED)
        rtc->state = RTC_STATE_NEGOTIATED;
    rtc->rtc_answer_time = av_gettime_relative();
    av_log(rtc, AV_LOG_VERBOSE, "SDP state=%d, offer=%zuB, answer=%zuB, ufrag=%s, pwd=%zuB, transport=%s://%s:%d, elapsed=%.2fms\n",
        rtc->state, strlen(rtc->sdp_offer), strlen(rtc->sdp_answer), rtc->ice_ufrag_remote, strlen(rtc->ice_pwd_remote),
        rtc->ice_protocol, rtc->ice_host, rtc->ice_port, ELAPSED(rtc->rtc_starttime, av_gettime_relative()));

end:
    avio_context_free(&pb);
    return ret;
}

/**
 * Creates and marshals an ICE binding request packet.
 *
 * This function creates and marshals an ICE binding request packet. The function only
 * generates the username attribute and does not include goog-network-info,
 * use-candidate. However, some of these attributes may be added in the future.
 *
 * @param s Pointer to the AVFormatContext
 * @param buf Pointer to memory buffer to store the request packet
 * @param buf_size Size of the memory buffer
 * @param request_size Pointer to an integer that receives the size of the request packet
 * @return Returns 0 if successful or AVERROR_xxx if an error occurs.
 */
int ff_rtc_ice_create_request(AVFormatContext *s, uint8_t *buf, int buf_size, int *request_size)
{
    int ret, size, crc32;
    char username[128];
    AVIOContext *pb = NULL;
    AVHMAC *hmac = NULL;
    RTCContext *rtc = s->priv_data;

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
    avio_wb32(pb, av_lfg_get(&rtc->rnd)); /* transaction ID */
    avio_wb32(pb, av_lfg_get(&rtc->rnd)); /* transaction ID */
    avio_wb32(pb, av_lfg_get(&rtc->rnd)); /* transaction ID */

    /* The username is the concatenation of the two ICE ufrag */
    ret = snprintf(username, sizeof(username), "%s:%s", rtc->ice_ufrag_remote, rtc->ice_ufrag_local);
    if (ret <= 0 || ret >= sizeof(username)) {
        av_log(rtc, AV_LOG_ERROR, "Failed to build username %s:%s, max=%zu, ret=%d\n",
            rtc->ice_ufrag_remote, rtc->ice_ufrag_local, sizeof(username), ret);
        ret = AVERROR(EIO);
        goto end;
    }

    /* Write the username attribute */
    avio_wb16(pb, STUN_ATTR_USERNAME); /* attribute type username */
    avio_wb16(pb, ret); /* size of username */
    avio_write(pb, username, ret); /* bytes of username */
    ffio_fill(pb, 0, (4 - (ret % 4)) % 4); /* padding */

    /* Write the use-candidate attribute */
    avio_wb16(pb, STUN_ATTR_USE_CANDIDATE); /* attribute type use-candidate */
    avio_wb16(pb, 0); /* size of use-candidate */

    avio_wb16(pb, STUN_ATTR_PRIORITY);
    avio_wb16(pb, 4);
    avio_wb32(pb, STUN_HOST_CANDIDATE_PRIORITY);

    avio_wb16(pb, STUN_ATTR_ICE_CONTROLLING);
    avio_wb16(pb, 8);
    avio_wb64(pb, rtc->ice_tie_breaker);

    /* Build and update message integrity */
    avio_wb16(pb, STUN_ATTR_MESSAGE_INTEGRITY); /* attribute type message integrity */
    avio_wb16(pb, 20); /* size of message integrity */
    ffio_fill(pb, 0, 20); /* fill with zero to directly write and skip it */
    size = avio_tell(pb);
    buf[2] = (size - 20) >> 8;
    buf[3] = (size - 20) & 0xFF;
    av_hmac_init(hmac, rtc->ice_pwd_remote, strlen(rtc->ice_pwd_remote));
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
    RTCContext *rtc = s->priv_data;

    if (tid_size != 12) {
        av_log(rtc, AV_LOG_ERROR, "Invalid transaction ID size. Expected 12, got %d\n", tid_size);
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
    av_hmac_init(hmac, rtc->ice_pwd_local, strlen(rtc->ice_pwd_local));
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
int ff_rtc_ice_is_binding_request(uint8_t *b, int size)
{
    return size >= ICE_STUN_HEADER_SIZE && AV_RB16(&b[0]) == 0x0001;
}

/**
 * A Binding response has class=0b10 (success response) and method=0b000000000001,
 * and is encoded into the first 16 bits as 0x0101.
 */
int ff_rtc_ice_is_binding_response(uint8_t *b, int size)
{
    return size >= ICE_STUN_HEADER_SIZE && AV_RB16(&b[0]) == 0x0101;
}

/**
 * This function handles incoming binding request messages by responding to them.
 * If the message is not a binding request, it will be ignored.
 */
static int ice_handle_binding_request(AVFormatContext *s, char *buf, int buf_size)
{
    int ret = 0, size;
    char tid[12];
    RTCContext *rtc = s->priv_data;

    /* Ignore if not a binding request. */
    if (!ff_rtc_ice_is_binding_request(buf, buf_size))
        return ret;

    if (buf_size < ICE_STUN_HEADER_SIZE) {
        av_log(rtc, AV_LOG_ERROR, "Invalid STUN message, expected at least %d, got %d\n",
            ICE_STUN_HEADER_SIZE, buf_size);
        return AVERROR(EINVAL);
    }

    /* Parse transaction id from binding request in buf. */
    memcpy(tid, buf + 8, 12);

    /* Build the STUN binding response. */
    ret = ice_create_response(s, tid, sizeof(tid), rtc->buf, sizeof(rtc->buf), &size);
    if (ret < 0) {
        av_log(rtc, AV_LOG_ERROR, "Failed to create STUN binding response, size=%d\n", size);
        return ret;
    }

    ret = ffurl_write(rtc->udp, rtc->buf, size);
    if (ret < 0) {
        av_log(rtc, AV_LOG_ERROR, "Failed to send STUN binding response, size=%d\n", size);
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
    char url[256];
    AVDictionary *opts = NULL;
    RTCContext *rtc = s->priv_data;

    /* Build UDP URL and create the UDP context as transport. */
    ff_url_join(url, sizeof(url), "udp", NULL, rtc->ice_host, rtc->ice_port, NULL);

    av_dict_set_int(&opts, "connect", 1, 0);
    av_dict_set_int(&opts, "fifo_size", 0, 0);
    /* Pass through the pkt_size and buffer_size to underling protocol */
    av_dict_set_int(&opts, "pkt_size", rtc->pkt_size, 0);
    av_dict_set_int(&opts, "buffer_size", rtc->buffer_size, 0);

    ret = ffurl_open_whitelist(&rtc->udp, url, AVIO_FLAG_WRITE, &s->interrupt_callback,
        &opts, s->protocol_whitelist, s->protocol_blacklist, NULL);
    if (ret < 0) {
        av_log(rtc, AV_LOG_ERROR, "Failed to connect udp://%s:%d\n", rtc->ice_host, rtc->ice_port);
        goto end;
    }

    /* Make the socket non-blocking, set to READ and WRITE mode after connected */
    ff_socket_nonblock(ffurl_get_file_handle(rtc->udp), 1);
    rtc->udp->flags |= AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK;

    if (rtc->state < RTC_STATE_UDP_CONNECTED)
        rtc->state = RTC_STATE_UDP_CONNECTED;
    rtc->rtc_udp_time = av_gettime_relative();
    av_log(rtc, AV_LOG_VERBOSE, "UDP state=%d, elapsed=%.2fms, connected to udp://%s:%d\n",
        rtc->state, ELAPSED(rtc->rtc_starttime, av_gettime_relative()), rtc->ice_host, rtc->ice_port);

end:
    av_dict_free(&opts);
    return ret;
}

static int ice_dtls_handshake(AVFormatContext *s)
{
    int ret = 0, size, i;
    int64_t starttime = av_gettime_relative(), now;
    RTCContext *rtc = s->priv_data;
    AVDictionary *opts = NULL;
    char buf[256], *cert_buf = NULL, *key_buf = NULL;

    if (rtc->state < RTC_STATE_UDP_CONNECTED || !rtc->udp) {
        av_log(rtc, AV_LOG_ERROR, "UDP not connected, state=%d, udp=%p\n", rtc->state, rtc->udp);
        return AVERROR(EINVAL);
    }

    while (1) {
        if (rtc->state <= RTC_STATE_ICE_CONNECTING) {
            /* Build the STUN binding request. */
            ret = ff_rtc_ice_create_request(s, rtc->buf, sizeof(rtc->buf), &size);
            if (ret < 0) {
                av_log(rtc, AV_LOG_ERROR, "Failed to create STUN binding request, size=%d\n", size);
                goto end;
            }

            ret = ffurl_write(rtc->udp, rtc->buf, size);
            if (ret < 0) {
                av_log(rtc, AV_LOG_ERROR, "Failed to send STUN binding request, size=%d\n", size);
                goto end;
            }

            if (rtc->state < RTC_STATE_ICE_CONNECTING)
                rtc->state = RTC_STATE_ICE_CONNECTING;
        }

next_packet:
        if (rtc->state >= RTC_STATE_DTLS_FINISHED)
            /* DTLS handshake is done, exit the loop. */
            break;

        now = av_gettime_relative();
        if (now - starttime >= rtc->handshake_timeout * RTC_US_PER_MS) {
            av_log(rtc, AV_LOG_ERROR, "DTLS handshake timeout=%dms, cost=%.2fms, elapsed=%.2fms, state=%d\n",
                rtc->handshake_timeout, ELAPSED(starttime, now), ELAPSED(rtc->rtc_starttime, now), rtc->state);
            ret = AVERROR(ETIMEDOUT);
            goto end;
        }

        /* Read the STUN or DTLS messages from peer. */
        for (i = 0; i < ICE_DTLS_READ_MAX_RETRY; i++) {
            if (rtc->state > RTC_STATE_ICE_CONNECTED)
                break;
            ret = ffurl_read(rtc->udp, rtc->buf, sizeof(rtc->buf));
            if (ret > 0)
                break;
            if (ret == AVERROR(EAGAIN)) {
                av_usleep(ICE_DTLS_READ_SLEEP_DURATION * RTC_US_PER_MS);
                continue;
            }
            av_log(rtc, AV_LOG_ERROR, "Failed to read message\n");
            goto end;
        }

        /* Handle the ICE binding response. */
        if (ff_rtc_ice_is_binding_response(rtc->buf, ret)) {
            if (rtc->state < RTC_STATE_ICE_CONNECTED) {
                if (rtc->is_peer_ice_lite)
                    rtc->state = RTC_STATE_ICE_CONNECTED;
                rtc->rtc_ice_time = av_gettime_relative();
                av_log(rtc, AV_LOG_VERBOSE, "ICE STUN ok, state=%d, url=udp://%s:%d, location=%s, username=%s:%s, res=%dB, elapsed=%.2fms\n",
                    rtc->state, rtc->ice_host, rtc->ice_port, rtc->rtc_resource_url ? rtc->rtc_resource_url : "",
                    rtc->ice_ufrag_remote, rtc->ice_ufrag_local, ret, ELAPSED(rtc->rtc_starttime, av_gettime_relative()));

                ff_url_join(buf, sizeof(buf), "dtls", NULL, rtc->ice_host, rtc->ice_port, NULL);
                av_dict_set_int(&opts, "mtu", rtc->pkt_size, 0);
                if (rtc->cert_file) {
                    av_dict_set(&opts, "cert_file", rtc->cert_file, 0);
                } else
                    av_dict_set(&opts, "cert_pem", rtc->cert_buf, 0);

                if (rtc->key_file) {
                    av_dict_set(&opts, "key_file", rtc->key_file, 0);
                } else
                    av_dict_set(&opts, "key_pem", rtc->key_buf, 0);
                av_dict_set_int(&opts, "external_sock", 1, 0);
                av_dict_set_int(&opts, "use_srtp", 1, 0);
                av_dict_set_int(&opts, "listen", 1, 0);
                /* If got the first binding response, start DTLS handshake. */
                ret = ffurl_open_whitelist(&rtc->dtls_uc, buf, AVIO_FLAG_READ_WRITE, &s->interrupt_callback,
                    &opts, s->protocol_whitelist, s->protocol_blacklist, NULL);
                av_dict_free(&opts);
                if (ret < 0)
                    goto end;
                dtls_initialize(s);
            }
            goto next_packet;
        }

        /* When a binding request is received, it is necessary to respond immediately. */
        if (ff_rtc_ice_is_binding_request(rtc->buf, ret)) {
            if ((ret = ice_handle_binding_request(s, rtc->buf, ret)) < 0)
                goto end;
            goto next_packet;
        }

        /* If got any DTLS messages, handle it. */
        if (ff_rtc_is_dtls_packet(rtc->buf, ret)) {
            /* Start consent timer when ICE selected */
            rtc->rtc_last_consent_tx_time = rtc->rtc_last_consent_rx_time = av_gettime_relative();
            rtc->state = RTC_STATE_ICE_CONNECTED;
            ret = ffurl_handshake(rtc->dtls_uc);
            if (ret < 0) {
                rtc->state = RTC_STATE_FAILED;
                av_log(rtc, AV_LOG_VERBOSE, "DTLS session failed\n");
                goto end;
            }
            if (!ret) {
                rtc->state = RTC_STATE_DTLS_FINISHED;
                rtc->rtc_dtls_time = av_gettime_relative();
                av_log(rtc, AV_LOG_VERBOSE, "DTLS handshake is done, elapsed=%.2fms\n",
                    ELAPSED(rtc->rtc_starttime, rtc->rtc_dtls_time));
            }
            goto next_packet;
        }
    }

end:
    if (cert_buf)
        av_free(cert_buf);
    if (key_buf)
        av_free(key_buf);
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
static int setup_srtp(AVFormatContext *s)
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
    RTCContext *rtc = s->priv_data;
    ret = ff_dtls_export_materials(rtc->dtls_uc, rtc->dtls_srtp_materials, sizeof(rtc->dtls_srtp_materials));
    if (ret < 0)
        goto end;
    /**
     * This represents the material used to build the SRTP master key. It is
     * generated by DTLS and has the following layout:
     *          16B         16B         14B             14B
     *      client_key | server_key | client_salt | server_salt
     */
    char *client_key = rtc->dtls_srtp_materials;
    char *server_key = rtc->dtls_srtp_materials + DTLS_SRTP_KEY_LEN;
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
        av_log(rtc, AV_LOG_ERROR, "Failed to encode send key\n");
        ret = AVERROR(EIO);
        goto end;
    }

    ret = ff_srtp_set_crypto(&rtc->srtp_audio_send, suite, buf);
    if (ret < 0) {
        av_log(rtc, AV_LOG_ERROR, "Failed to set crypto for audio send\n");
        goto end;
    }

    ret = ff_srtp_set_crypto(&rtc->srtp_video_send, suite, buf);
    if (ret < 0) {
        av_log(rtc, AV_LOG_ERROR, "Failed to set crypto for video send\n");
        goto end;
    }

    ret = ff_srtp_set_crypto(&rtc->srtp_video_rtx_send, suite, buf);
    if (ret < 0) {
        av_log(rtc, AV_LOG_ERROR, "Failed to set crypto for video rtx send\n");
        goto end;
    }

    ret = ff_srtp_set_crypto(&rtc->srtp_rtcp_send, suite, buf);
    if (ret < 0) {
        av_log(rtc, AV_LOG_ERROR, "Failed to set crypto for rtcp send\n");
        goto end;
    }

    /* Setup SRTP context for incoming packets */
    if (!av_base64_encode(buf, sizeof(buf), recv_key, sizeof(recv_key))) {
        av_log(rtc, AV_LOG_ERROR, "Failed to encode recv key\n");
        ret = AVERROR(EIO);
        goto end;
    }

    ret = ff_srtp_set_crypto(&rtc->srtp_recv, suite, buf);
    if (ret < 0) {
        av_log(rtc, AV_LOG_ERROR, "Failed to set crypto for recv\n");
        goto end;
    }

    if (rtc->state < RTC_STATE_SRTP_FINISHED)
        rtc->state = RTC_STATE_SRTP_FINISHED;
    rtc->rtc_srtp_time = av_gettime_relative();
    av_log(rtc, AV_LOG_VERBOSE, "SRTP setup done, state=%d, suite=%s, key=%zuB, elapsed=%.2fms\n",
        rtc->state, suite, sizeof(send_key), ELAPSED(rtc->rtc_starttime, av_gettime_relative()));

end:
    return ret;
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
    URLContext *rtc_uc = NULL;
    AVDictionary *opts = NULL;
    RTCContext *rtc = s->priv_data;

    if (!rtc->rtc_resource_url)
        return 0;

    ret = snprintf(buf, sizeof(buf), "Cache-Control: no-cache\r\n");
    if (rtc->authorization)
        ret += snprintf(buf + ret, sizeof(buf) - ret, "Authorization: Bearer %s\r\n", rtc->authorization);
    if (ret <= 0 || ret >= sizeof(buf)) {
        av_log(rtc, AV_LOG_ERROR, "Failed to generate headers, size=%d, %s\n", ret, buf);
        ret = AVERROR(EINVAL);
        goto end;
    }

    av_dict_set(&opts, "headers", buf, 0);
    av_dict_set_int(&opts, "chunked_post", 0, 0);
    av_dict_set(&opts, "method", "DELETE", 0);
    ret = ffurl_open_whitelist(&rtc_uc, rtc->rtc_resource_url, AVIO_FLAG_READ_WRITE, &s->interrupt_callback,
        &opts, s->protocol_whitelist, s->protocol_blacklist, NULL);
    if (ret < 0) {
        av_log(rtc, AV_LOG_ERROR, "Failed to DELETE url=%s\n", rtc->rtc_resource_url);
        goto end;
    }

    while (1) {
        ret = ffurl_read(rtc_uc, buf, sizeof(buf));
        if (ret == AVERROR_EOF) {
            ret = 0;
            break;
        }
        if (ret < 0) {
            av_log(rtc, AV_LOG_ERROR, "Failed to read response from DELETE url=%s\n", rtc->rtc_resource_url);
            goto end;
        }
    }

    av_log(rtc, AV_LOG_INFO, "Dispose resource %s ok\n", rtc->rtc_resource_url);

end:
    ffurl_closep(&rtc_uc);
    av_dict_free(&opts);
    return ret;
}

int ff_rtc_connect(AVFormatContext *s) {
    int ret = 0;
    if ((ret = generate_sdp_offer(s)) < 0)
        goto end;

    if ((ret = exchange_sdp(s)) < 0)
        goto end;

    if ((ret = parse_answer(s)) < 0)
        goto end;

    if ((ret = udp_connect(s)) < 0)
        goto end;

    if ((ret = ice_dtls_handshake(s)) < 0)
        goto end;

    if ((ret = setup_srtp(s)) < 0)
        goto end;

end:
    return ret;
}

void ff_rtc_close(AVFormatContext *s)
{
    int i, ret;
    RTCContext *rtc = s->priv_data;

    ret = dispose_session(s);
    if (ret < 0)
        av_log(rtc, AV_LOG_WARNING, "Failed to dispose resource, ret=%d\n", ret);

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

    av_freep(&rtc->sdp_offer);
    av_freep(&rtc->sdp_answer);
    av_freep(&rtc->rtc_resource_url);
    av_freep(&rtc->ice_ufrag_remote);
    av_freep(&rtc->ice_pwd_remote);
    av_freep(&rtc->ice_protocol);
    av_freep(&rtc->ice_host);
    av_freep(&rtc->authorization);
    av_freep(&rtc->cert_file);
    av_freep(&rtc->key_file);
    ff_srtp_free(&rtc->srtp_audio_send);
    ff_srtp_free(&rtc->srtp_video_send);
    ff_srtp_free(&rtc->srtp_video_rtx_send);
    ff_srtp_free(&rtc->srtp_rtcp_send);
    ff_srtp_free(&rtc->srtp_recv);
    ffurl_close(rtc->dtls_uc);
    ffurl_closep(&rtc->udp);
}

#define OFFSET(x) offsetof(RTCContext, x)
#define ENC AV_OPT_FLAG_ENCODING_PARAM
const AVOption ff_rtc_options[] = {
    { "handshake_timeout",  "Timeout in milliseconds for ICE and DTLS handshake.",      OFFSET(handshake_timeout),  AV_OPT_TYPE_INT,    { .i64 = 5000 },    -1, INT_MAX, ENC },
    { "pkt_size",           "The maximum size, in bytes, of RTP packets that send out", OFFSET(pkt_size),           AV_OPT_TYPE_INT,    { .i64 = 1200 },    -1, INT_MAX, ENC },
    { "buffer_size",        "The buffer size, in bytes, of underlying protocol",        OFFSET(buffer_size),        AV_OPT_TYPE_INT,    { .i64 = -1 },      -1, INT_MAX, ENC },
    { "authorization",      "The optional Bearer token for WHIP Authorization",         OFFSET(authorization),      AV_OPT_TYPE_STRING, { .str = NULL },     0,       0, ENC },
    { "cert_file",          "The optional certificate file path for DTLS",              OFFSET(cert_file),          AV_OPT_TYPE_STRING, { .str = NULL },     0,       0, ENC },
    { "key_file",           "The optional private key file path for DTLS",              OFFSET(key_file),      AV_OPT_TYPE_STRING, { .str = NULL },     0,       0, ENC },
    { NULL },
};
