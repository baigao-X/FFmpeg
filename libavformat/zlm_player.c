/*
 * ZLM Player protocol demuxer
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

#include "mk/mk_mediakit.h"

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
#include "libavutil/thread.h"
#include "avc.h"
#include "avio_internal.h"
#include "http.h"
#include "internal.h"
#include "demux.h"
#include "rtpdec.h"
#include "network.h"
#include "srtp.h"
#include "avformat.h"

enum PlayerState  {
    ZLM_PLAYER_STATE_NONE,

    /* The initial state. */
    ZLM_PLAYER_STATE_INIT,

    /* The demuxer is failed. */
    ZLM_PLAYER_STATE_FAILED,

    /* The player is playing media. */
    ZLM_PLAYER_STATE_PLAYING,

    /* The player is closing. */
    ZLM_PLAYER_STATE_CLOSING
};

typedef struct ZlmPlayerContext {
    AVClass *av_class;
    mk_player player;

    /* The state of the RTC connection. */
    enum PlayerState state;
  
    AVFormatContext *parent;
    int video_stream_index;
    int audio_stream_index;
    
    /** number of items in the 'streams' variable */
    int nb_streams;

    struct RTPStream **streams; /**< streams in this session */

    PacketList packet_buffer;

    /* The timeout in milliseconds for open stream. */
    int timeout;

    // 添加信号量
    pthread_mutex_t play_mutex;
    pthread_cond_t play_cond;
    int play_event_received;

} ZlmPlayerContext;


static void on_track_frame_out(void *user_data, mk_frame frame);
static void  on_mk_play_event_func(void *user_data, int err_code, const char *err_msg, mk_track tracks[], int track_count);
static void on_mk_shutdown_func(void *user_data, int err_code, const char *err_msg, mk_track tracks[], int track_count);


static void on_track_frame_out(void *user_data, mk_frame frame) {

    ZlmPlayerContext *ctx = (ZlmPlayerContext *) user_data;
    
    AVPacket *pkt = av_packet_alloc();
    if (!pkt) {
        av_log(NULL, AV_LOG_ERROR, "Failed to allocate packet\n");
        return;
    }
    
    // 获取帧数据
    const uint8_t *data = mk_frame_get_data(frame);
    int size = mk_frame_get_data_size(frame);
    
    // 设置 AVPacket 数据
    if (av_packet_from_data(pkt, av_malloc(size), size) < 0) {
        av_log(NULL, AV_LOG_ERROR, "Failed to allocate packet data\n");
        av_packet_free(&pkt);
        return;
    }
    
    // 复制数据
    memcpy(pkt->data, data, size);
 
    // 设置时间戳
    // 根据zlm返回的pts和dts,会造成画面卡顿，不设置，让ffmpeg自己处理
    // pkt->pts = mk_frame_get_pts(frame);
    // pkt->dts = mk_frame_get_dts(frame);

    // 设置流索引
    pkt->stream_index = mk_frame_is_video(frame)? ctx->video_stream_index : ctx->audio_stream_index;

    // 添加到包队列

    avpriv_packet_list_put(&ctx->packet_buffer, pkt, NULL, 0);
    av_packet_free(&pkt);
}

static void on_mk_play_event_func(void *user_data, int err_code, const char *err_msg, mk_track tracks[],
                                  int track_count) {
    ZlmPlayerContext *ctx = (ZlmPlayerContext *) user_data;
    AVFormatContext *s = ctx->parent;
    if (err_code == 0) {
        //success
        for (int i = 0; i < track_count; ++i) {
            AVStream *st;

            if (mk_track_is_video(tracks[i])) {
                av_log(ctx, AV_LOG_INFO, "add video stream\n");
                st = avformat_new_stream(s, NULL);
                if (!st) {
                    av_log(s, AV_LOG_ERROR, "Failed to create new video stream\n");
                    continue;
                }

                st->codecpar->codec_type = AVMEDIA_TYPE_VIDEO;

                // 设置编解码器ID
                enum AVCodecID codec_id = AV_CODEC_ID_NONE;
                const char *codec_name = mk_track_codec_name(tracks[i]);
                if (!strcmp(codec_name, "H264")) {
                    codec_id = AV_CODEC_ID_H264;
                } else if (!strcmp(codec_name, "H265")) {
                    codec_id = AV_CODEC_ID_HEVC;
                } else {
                    av_log(ctx, AV_LOG_ERROR, "unknow video codec_name: %s\n", codec_name);
                }

                st->codecpar->codec_id = codec_id;
                // 设置视频宽高和帧率
                st->codecpar->width = mk_track_video_width(tracks[i]);
                st->codecpar->height = mk_track_video_height(tracks[i]);

                // fps 让ffmpeg 自己探测
                // int fps = mk_track_video_fps(tracks[i]);
                // st->time_base = (AVRational){1, fps};

                // 播放时建议加上-probesize参数调一个较小的值(如10000)，不然默认探测会导致开流很慢

                // 监听track数据回调
                ctx->video_stream_index = st->index;
                mk_track_add_delegate(tracks[i], on_track_frame_out, ctx);
            } else {
                av_log(ctx, AV_LOG_INFO, "add audio stream\n");
                // 设置编解码器ID
                enum AVCodecID codec_id = AV_CODEC_ID_NONE;
                const char *codec_name = mk_track_codec_name(tracks[i]);
                if (!strcmp(codec_name, "AAC")) {
                    codec_id = AV_CODEC_ID_AAC;
                } else if (!strcmp(codec_name, "OPUS")) {
                    codec_id = AV_CODEC_ID_OPUS;
                } else {
                    av_log(ctx, AV_LOG_ERROR, "unknow audio codec_name: %s\n", codec_name);
                }

                st = avformat_new_stream(s, NULL);
                if (!st) {
                    av_log(s, AV_LOG_ERROR, "Failed to create new audio stream\n");
                    continue;
                }

                st->codecpar->codec_id = codec_id;
                st->codecpar->codec_type = AVMEDIA_TYPE_AUDIO;

                // 设置音频参数
                st->codecpar->sample_rate = mk_track_audio_sample_rate(tracks[i]);
                st->codecpar->ch_layout.nb_channels = mk_track_audio_channel(tracks[i]);

                // 设置时间基准
                st->time_base = (AVRational){1, st->codecpar->sample_rate};

                // 监听track数据回调
                ctx->audio_stream_index = st->index;
                mk_track_add_delegate(tracks[i], on_track_frame_out, ctx);
            }
        }
        ctx->state = ZLM_PLAYER_STATE_PLAYING;
    } else {
        av_log(ctx, AV_LOG_ERROR, "play failed: %d %s", err_code, err_msg);
        ctx->state = ZLM_PLAYER_STATE_FAILED;
    }

    // 设置回调已接收标志并发送信号
    pthread_mutex_lock(&ctx->play_mutex);
    ctx->play_event_received = 1;
    pthread_cond_signal(&ctx->play_cond);
    pthread_mutex_unlock(&ctx->play_mutex);
    return;
}

static void on_mk_shutdown_func(void *user_data, int err_code, const char *err_msg, mk_track tracks[], int track_count) {
    ZlmPlayerContext *ctx = (ZlmPlayerContext *) user_data;
    ctx->state = ZLM_PLAYER_STATE_CLOSING; 
    av_log(ctx, AV_LOG_ERROR, "zlm player shutdown err_code: %d, err_msg: %s", err_code, err_msg);
    return;
}

static av_cold int zlm_read_header(AVFormatContext *s)
{
    mk_config config = {
            .ini = NULL,
            .ini_is_path = 0,
            .log_level = 0,
            // .log_mask = LOG_CONSOLE,
            .log_mask = 0,
            .ssl = NULL,
            .ssl_is_path = 1,
            .ssl_pwd = NULL,
            .thread_num = 0
    };

    int ret;
    ZlmPlayerContext *ctx = s->priv_data;
    ctx->video_stream_index = -1;
    ctx->audio_stream_index = -1;

    ctx->parent = s;
    // 初始化信号量和互斥锁
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&ctx->play_mutex, &mutexattr);
    pthread_mutexattr_destroy(&mutexattr);

    pthread_condattr_t condattr;
    pthread_condattr_init(&condattr);
    pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC);
    pthread_cond_init(&ctx->play_cond, &condattr);
    pthread_condattr_destroy(&condattr);

    mk_env_init(&config);
    ctx->state = ZLM_PLAYER_STATE_INIT;
    ctx->player = mk_player_create();
    mk_player_set_on_result(ctx->player, on_mk_play_event_func, ctx);
    mk_player_set_on_shutdown(ctx->player, on_mk_shutdown_func, ctx);
    mk_player_play(ctx->player, s->url);

    // 等待回调函数执行完成或超时
    pthread_mutex_lock(&ctx->play_mutex);
    if (!ctx->play_event_received) {
        struct timespec ts;
        int64_t wait_time = ctx->timeout * 1000; // 转换为微秒
        av_gettime_relative_is_monotonic();
        int64_t now = av_gettime_relative();
        ts.tv_sec = now / 1000000 + wait_time / 1000000;
        ts.tv_nsec = (now % 1000000) * 1000 + (wait_time % 1000000) * 1000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }
        
        while (!ctx->play_event_received) {
            ret = pthread_cond_timedwait(&ctx->play_cond, &ctx->play_mutex, &ts);
            if (0 != ret) {
                if (ret == ETIMEDOUT) {
                    av_log(ctx, AV_LOG_ERROR, "Timeout waiting for play event callback\n");
                } else {
                    av_log(ctx, AV_LOG_ERROR, " waiting for play event callback fail :%d\n", ret);
                }
                ctx->state = ZLM_PLAYER_STATE_FAILED;
                break;
            }
        }
    }
    pthread_mutex_unlock(&ctx->play_mutex);

    // 检查状态
    if (ctx->state == ZLM_PLAYER_STATE_FAILED) {
        return AVERROR(ret);
    }

    return ret;
}

static int zlm_read_packet(AVFormatContext *s, AVPacket *pkt)
{
    ZlmPlayerContext *ctx = s->priv_data;
    int ret;

    // 检查播放状态
    if (ctx->state == ZLM_PLAYER_STATE_FAILED || ctx->state == ZLM_PLAYER_STATE_CLOSING) {
        av_log(ctx, AV_LOG_ERROR, "ctx->state is ZLM_PLAYER_STATE_FAILED or ZLM_PLAYER_STATE_CLOSING\n");
        return AVERROR(EIO);
    }

    if (ctx->state == ZLM_PLAYER_STATE_INIT) {
        av_log(ctx, AV_LOG_ERROR, "ctx->state is ZLM_PLAYER_STATE_INIT\n");
        return AVERROR(EAGAIN);
    }

    // 从包缓冲区获取一个包
    ret = avpriv_packet_list_get(&ctx->packet_buffer, pkt);
    if (ret < 0) {
        // 如果没有可用的包，则等待一小段时间后再尝试
        if (ff_check_interrupt(&s->interrupt_callback)) {
            return AVERROR_EXIT;
        }
 
        return AVERROR(EAGAIN);
    }
    return 0;
}

static av_cold int zlm_read_close(AVFormatContext *s)
{
    ZlmPlayerContext *ctx = s->priv_data;
    mk_player_release(ctx->player);
    avpriv_packet_list_free(&ctx->packet_buffer);
    // 释放信号量和互斥锁
    pthread_mutex_destroy(&ctx->play_mutex);
    pthread_cond_destroy(&ctx->play_cond);
    return 0;
}

#define OFFSET(x) offsetof(ZlmPlayerContext, x)
#define DEC AV_OPT_FLAG_DECODING_PARAM
static const AVOption options[] = {
    { "timeout", "设置连接超时时间(毫秒)", OFFSET(timeout), AV_OPT_TYPE_INT, {.i64 = 10000}, 1000, 60000, DEC },
    { NULL },
};

static const AVClass zlm_player_demuxer_class = {
    .class_name = "ZLM Player demuxer",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const AVInputFormat ff_zlm_player_demuxer = {
    .name             = "zlm_player",
    .long_name        = NULL_IF_CONFIG_SMALL("ZLM PLAYER demuxer"),
    .flags            = AVFMT_GLOBALHEADER | AVFMT_NOFILE,
    .priv_class       = &zlm_player_demuxer_class,
    .priv_data_size   = sizeof(ZlmPlayerContext),
    .read_header      = zlm_read_header,
    .read_packet      = zlm_read_packet,
    .read_close       = zlm_read_close,
};

