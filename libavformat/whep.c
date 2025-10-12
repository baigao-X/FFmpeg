/*
 * WebRTC-HTTP egress protocol (WHEP) demuxer
 * Copyright (c) 2025 baigao
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

#include "libavutil/opt.h"
#include "libavutil/mem.h"
#include "libavutil/base64.h"
#include "libavutil/dict.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/time.h"
#include "libavutil/mathematics.h"
#include "libavcodec/codec_desc.h"
#include "avio_internal.h"
#include "demux.h"
#include "internal.h"
#include "rtpdec.h"
#include "rtp.h"
#include "rtc.h"

/**
 * Initialize RTP dynamic protocol handler.
 *
 * Similar to init_rtp_handler and finalize_rtp_handler_init in rtsp.c
 */
static int init_rtp_handler(AVFormatContext *s, AVStream *st,
                            RTPDemuxContext *rtp_ctx,
                            const RTPDynamicProtocolHandler *handler,
                            PayloadContext **payload_ctx_out)
{
    PayloadContext *payload_ctx = NULL;
    int ret;

    if (!handler)
        return 0;

    if (handler->codec_id != AV_CODEC_ID_NONE)
        st->codecpar->codec_id = handler->codec_id;

    if (handler->priv_data_size > 0) {
        payload_ctx = av_mallocz(handler->priv_data_size);
        if (!payload_ctx)
            return AVERROR(ENOMEM);
    }

    ff_rtp_parse_set_dynamic_protocol(rtp_ctx, payload_ctx, handler);
    ffstream(st)->need_parsing = handler->need_parsing;

    if (handler->init) {
        ret = handler->init(s, st->index, payload_ctx);
        if (ret < 0) {
            av_log(s, AV_LOG_ERROR, "Failed to initialize RTP handler '%s': %d\n",
                   handler->enc_name, ret);
            if (payload_ctx) {
                if (handler->close)
                    handler->close(payload_ctx);
                av_free(payload_ctx);
            }
            return ret;
        }
    }

    *payload_ctx_out = payload_ctx;
    return 0;
}

/**
 * Parse fmtp attributes for the stream.
 */
static int parse_fmtp(AVFormatContext *s, AVStream *st,
                     const RTPDynamicProtocolHandler *handler,
                     PayloadContext *payload_ctx,
                     int payload_type, const char *fmtp)
{
    char fmtp_line[1024];
    int ret;

    if (!fmtp || !handler || !handler->parse_sdp_a_line)
        return 0;

    snprintf(fmtp_line, sizeof(fmtp_line), "fmtp:%d %s", payload_type, fmtp);
    av_log(s, AV_LOG_INFO, "Processing fmtp for stream %d: %s\n", st->index, fmtp_line);

    ret = handler->parse_sdp_a_line(s, st->index, payload_ctx, fmtp_line);
    if (ret < 0) {
        av_log(s, AV_LOG_WARNING, "Failed to parse fmtp line for stream %d: %d\n",
               st->index, ret);
    } else {
        av_log(s, AV_LOG_INFO, "Successfully processed fmtp for stream %d\n", st->index);
    }

    return ret;
}

/**
 * Create RTP demuxer contexts for each stream.
 */
static int create_rtp_demuxer(AVFormatContext *s)
{
    int ret = 0, i;
    RTCContext *rtc = s->priv_data;

    if (!rtc->stream_infos || rtc->nb_stream_infos == 0) {
        av_log(rtc, AV_LOG_ERROR, "No stream info available for RTP demuxer\n");
        return AVERROR(EINVAL);
    }

    for (i = 0; i < rtc->nb_stream_infos; i++) {
        RTCStreamInfo *stream_info = rtc->stream_infos[i];
        AVStream *st;
        RTPDemuxContext *rtp_ctx;
        const RTPDynamicProtocolHandler *handler;
        int payload_type;

        if (!stream_info) {
            av_log(rtc, AV_LOG_ERROR, "Stream info %d is NULL\n", i);
            ret = AVERROR(EINVAL);
            goto fail;
        }

        /* Skip inactive streams */
        if (stream_info->direction && strcmp(stream_info->direction, "inactive") == 0) {
            av_log(rtc, AV_LOG_INFO, "Skipping inactive stream %d\n", i);
            continue;
        }

        st = avformat_new_stream(s, NULL);
        if (!st) {
            av_log(rtc, AV_LOG_ERROR, "Failed to create stream %d\n", i);
            ret = AVERROR(ENOMEM);
            goto fail;
        }

        st->id = i;
        st->codecpar->codec_type = stream_info->codec_type;

        payload_type = stream_info->payload_type;
        if (payload_type < RTP_PT_PRIVATE) {
            ff_rtp_get_codec_info(st->codecpar, payload_type);
        } else if (stream_info->codec_name) {
            st->codecpar->codec_id = ff_rtp_codec_id(stream_info->codec_name, stream_info->codec_type);
        } else {
            st->codecpar->codec_id = AV_CODEC_ID_NONE;
        }

        if (stream_info->codec_type == AVMEDIA_TYPE_AUDIO) {
            st->codecpar->sample_rate = stream_info->clock_rate;
            if (stream_info->channels > 0)
                av_channel_layout_default(&st->codecpar->ch_layout, stream_info->channels);
            avpriv_set_pts_info(st, 32, 1, stream_info->clock_rate);
        } else if (stream_info->codec_type == AVMEDIA_TYPE_VIDEO) {
            avpriv_set_pts_info(st, 32, 1, stream_info->clock_rate);
        }

        av_log(rtc, AV_LOG_VERBOSE, "Creating RTP demuxer for stream %d: type=%s, codec=%s, pt=%d, rate=%d\n",
               i, av_get_media_type_string(stream_info->codec_type),
               stream_info->codec_name ? stream_info->codec_name : avcodec_get_name(st->codecpar->codec_id),
               payload_type, stream_info->clock_rate);

        rtp_ctx = ff_rtp_parse_open(s, st, payload_type, RTP_REORDER_QUEUE_DEFAULT_SIZE);
        if (!rtp_ctx) {
            av_log(rtc, AV_LOG_ERROR, "Failed to create RTP demuxer for stream %d\n", i);
            ret = AVERROR(ENOMEM);
            goto fail;
        }

        handler = NULL;
        if (payload_type < RTP_PT_PRIVATE) {
            handler = ff_rtp_handler_find_by_id(payload_type, stream_info->codec_type);
        }
        if (!handler && stream_info->codec_name) {
            handler = ff_rtp_handler_find_by_name(stream_info->codec_name, stream_info->codec_type);
        }

        if (handler) {
            PayloadContext *payload_ctx = NULL;

            av_log(rtc, AV_LOG_VERBOSE, "Found RTP handler '%s' for stream %d, codec=%s, pt=%d\n",
                   handler->enc_name, i,
                   stream_info->codec_name ? stream_info->codec_name : avcodec_get_name(st->codecpar->codec_id),
                   payload_type);

            ret = init_rtp_handler(s, st, rtp_ctx, handler, &payload_ctx);
            if (ret < 0) {
                av_log(rtc, AV_LOG_ERROR, "Failed to initialize RTP handler for stream %d\n", i);
                ff_rtp_parse_close(rtp_ctx);
                goto fail;
            }

            parse_fmtp(s, st, handler, payload_ctx, payload_type, stream_info->fmtp);
        } else {
            av_log(rtc, AV_LOG_WARNING, "No RTP handler found for stream %d, codec=%s, pt=%d\n",
                   i,
                   stream_info->codec_name ? stream_info->codec_name : avcodec_get_name(st->codecpar->codec_id),
                   payload_type);
        }

        rtp_ctx->ssrc = stream_info->ssrc;
        av_log(rtc, AV_LOG_VERBOSE, "Set SSRC %u for stream %d\n", stream_info->ssrc, i);

        if (stream_info->rtx_pt >= 0) {
            av_log(rtc, AV_LOG_INFO, "Stream %d has RTX support: rtx_pt=%d, rtx_ssrc=%u\n",
                   i, stream_info->rtx_pt, stream_info->rtx_ssrc);
            /* TODO: Configure RTX support in RTPDemuxContext when RTX implementation is ready */
        }

        ff_rtp_parse_set_crypto(rtp_ctx, rtc->suite, rtc->recv_suite_param);

        st->priv_data = rtp_ctx;
        av_log(rtc, AV_LOG_VERBOSE, "Created RTP demuxer for stream %d: type=%s, pt=%d\n",
               i, av_get_media_type_string(st->codecpar->codec_type), payload_type);
    }

    av_log(rtc, AV_LOG_VERBOSE, "Created %d RTP demuxer contexts\n", s->nb_streams);
    return 0;

fail:
    for (i = 0; i < s->nb_streams; i++) {
        if (s->streams[i]->priv_data) {
            ff_rtp_parse_close(s->streams[i]->priv_data);
            s->streams[i]->priv_data = NULL;
        }
    }
    return ret;
}

static av_cold int whep_read_header(AVFormatContext *s)
{
    int ret;
    RTCContext *rtc = s->priv_data;

    if ((ret = ff_rtc_initialize(s)) < 0)
        goto end;

    if ((ret = ff_rtc_connect(s)) < 0)
        goto end;

    if ((ret = create_rtp_demuxer(s)) < 0)
        goto end;

end:
    if (ret < 0)
        rtc->state = RTC_STATE_FAILED;
    return ret;
}

/**
 * Send encrypted RTCP packet using SRTP.
 */
static int send_encrypted_rtcp(AVFormatContext *s, const uint8_t *buf, int len)
{
    RTCContext *rtc = s->priv_data;
    uint8_t encrypted_buf[MAX_UDP_BUFFER_SIZE];
    int cipher_size;
    int ret;

    cipher_size = ff_srtp_encrypt(&rtc->srtp_rtcp_send, buf, len,
                                  encrypted_buf, sizeof(encrypted_buf));
    if (cipher_size <= 0 || cipher_size < len) {
        av_log(rtc, AV_LOG_WARNING, "Failed to encrypt RTCP packet=%dB, cipher=%dB\n",
               len, cipher_size);
        return AVERROR(EIO);
    }

    ret = ffurl_write(rtc->udp, encrypted_buf, cipher_size);
    if (ret < 0) {
        av_log(rtc, AV_LOG_ERROR, "Failed to write encrypted RTCP packet=%dB, ret=%d\n",
               cipher_size, ret);
        return ret;
    }

    av_log(rtc, AV_LOG_TRACE, "Sent encrypted RTCP packet: plain=%dB, cipher=%dB\n",
           len, cipher_size);
    return ret;
}

static int send_rtcp_rr(AVFormatContext *s, RTPDemuxContext *rtp_ctx, int len)
{
    AVIOContext *rtcp_pb = NULL;
    uint8_t *rtcp_buf = NULL;
    int ret = 0;

    if (avio_open_dyn_buf(&rtcp_pb) >= 0) {
        ff_rtp_check_and_send_back_rr(rtp_ctx, NULL, rtcp_pb, len);
        int rtcp_len = avio_close_dyn_buf(rtcp_pb, &rtcp_buf);
        if (rtcp_len > 0 && rtcp_buf) {
            ret = send_encrypted_rtcp(s, rtcp_buf, rtcp_len);
            av_free(rtcp_buf);
        }
    }

    return ret;
}

static int send_rtcp_feedback(AVFormatContext *s, RTPDemuxContext *rtp_ctx)
{
    AVIOContext *rtcp_pb = NULL;
    uint8_t *rtcp_buf = NULL;
    int ret = 0;

    if (avio_open_dyn_buf(&rtcp_pb) >= 0) {
        ff_rtp_send_rtcp_feedback(rtp_ctx, NULL, rtcp_pb);
        int rtcp_len = avio_close_dyn_buf(rtcp_pb, &rtcp_buf);
        if (rtcp_len > 0 && rtcp_buf) {
            ret = send_encrypted_rtcp(s, rtcp_buf, rtcp_len);
            av_free(rtcp_buf);
        }
    }

    return ret;
}

static int whep_read_packet(AVFormatContext *s, AVPacket *pkt)
{
    int ret;
    RTCContext *rtc = s->priv_data;

    while (1) {
        /**
         * Receive packets from the server suh as ICE binding requests, DTLS messages,
         * and RTCP like PLI requests, then respond to them.
        */
        ret = ffurl_read(rtc->udp, rtc->buf, rtc->bufsize);
        if (ret < 0) {
            if (ret == AVERROR(EAGAIN))
                return ret;
            goto end;
        }

        if (!ret) {
            av_log(rtc, AV_LOG_ERROR, "Receive EOF from UDP socket\n");
            ret = AVERROR_EOF;
            goto end;
        }

        if (ff_rtc_is_dtls_packet(rtc->buf, ret)) {
            if ((ret = ffurl_write(rtc->dtls_uc, rtc->buf, ret)) < 0) {
                av_log(rtc, AV_LOG_ERROR, "Failed to handle DTLS message\n");
                goto end;
            }
            continue;
        } else if (ff_rtc_media_is_rtp_rtcp(rtc->buf, ret)) {
            int len = ret;
            int is_rtcp = ff_rtc_media_is_rtcp(rtc->buf, ret);

            av_log(rtc, AV_LOG_TRACE, "Received %s packet, len %d\n",
                   is_rtcp ? "RTCP" : "RTP", ret);

            for (int i = 0; i < s->nb_streams; i++) {
                AVStream *st = s->streams[i];
                RTPDemuxContext *rtp_ctx = st->priv_data;
                if (!rtp_ctx)
                    continue;

                if (!is_rtcp) {
                    int pkt_payload_type = rtc->buf[1] & 0x7f;
                    int stream_id = st->id;
                    if (stream_id >= 0 && stream_id < rtc->nb_stream_infos && rtc->stream_infos[stream_id]) {
                        RTCStreamInfo *stream_info = rtc->stream_infos[stream_id];
                        if (stream_info->rtx_pt >= 0 && pkt_payload_type == stream_info->rtx_pt) {
                            /* TODO: Implement RTX packet processing */
                            av_log(rtc, AV_LOG_INFO, "Received RTX retransmission packet for stream %d (id=%d): "
                                   "PT=%d, SSRC=%u, main_PT=%d\n",
                                   i, stream_id, pkt_payload_type, stream_info->rtx_ssrc, rtp_ctx->payload_type);
                            continue;
                        }
                    }

                    if (pkt_payload_type != rtp_ctx->payload_type) {
                        av_log(rtc, AV_LOG_INFO, "RTP packet PT=%d doesn't match stream %d PT=%d\n",
                               pkt_payload_type, i, rtp_ctx->payload_type);
                        continue;
                    }
                }

                ret = ff_rtp_parse_packet(rtp_ctx, pkt, &rtc->buf, len);
                if (!is_rtcp) {
                    if (ret == AVERROR(EAGAIN)) {
                        av_log(rtc, AV_LOG_DEBUG, "RTP packet buffered for stream %d\n", i);
                        continue;
                    } else if (ret >= 0 && pkt->size > 0) {
                        pkt->stream_index = i;
                        send_rtcp_rr(s, rtp_ctx, len);
                        send_rtcp_feedback(s, rtp_ctx);
                        goto end;
                    } else if (ret >= 0) {
                        av_log(rtc, AV_LOG_DEBUG, "RTP parsed but no output for stream %d\n", i);
                    }
                } else {
                    /* TODO: Implement RTCP processing*/
                    av_log(rtc, AV_LOG_DEBUG, "RECV RTCP, len=%d\n", len);
                }
            }
        } else {
            //TODO: Implement ICE processing
            av_log(rtc, AV_LOG_TRACE, "Received other type data, len %d\n", ret);
        }
    }

end:
    if (ret < 0)
        rtc->state = RTC_STATE_FAILED;
    return ret;
}

static av_cold int whep_read_close(AVFormatContext *s)
{
    int i;

    for (i = 0; i < s->nb_streams; i++) {
        if (s->streams[i]->priv_data) {
            ff_rtp_parse_close(s->streams[i]->priv_data);
            s->streams[i]->priv_data = NULL;
        }
    }

    ff_rtc_close(s);
    return 0;
}

static const AVClass whep_demuxer_class = {
    .class_name = "WHEP demuxer",
    .item_name  = av_default_item_name,
    .option     = ff_rtc_options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const FFInputFormat ff_whep_demuxer = {
    .p.name             = "whep",
    .p.long_name        = NULL_IF_CONFIG_SMALL("WHEP(WebRTC-HTTP egress protocol) demuxer"),
    .p.flags            = AVFMT_GLOBALHEADER | AVFMT_NOFILE | AVFMT_EXPERIMENTAL,
    .p.priv_class       = &whep_demuxer_class,
    .priv_data_size     = sizeof(RTCContext),
    .read_probe         = NULL,
    .read_header        = whep_read_header,
    .read_packet        = whep_read_packet,
    .read_close         = whep_read_close,
    .read_seek          = NULL,
    .read_play          = NULL,
    .read_pause         = NULL,
};
