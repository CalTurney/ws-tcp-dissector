/* packet-tcp.c
   Routines for TCP packet disassembly
   
   $Id: packet-tcp.c 35705 2011-01-30 21:01:07Z stig $
   
   Wireshark - Network traffic analyzer
   By Gerald Combs <gerald@wireshark.org>
   Copyright 1998 Gerald Combs
   
   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; either version 2
   of the License, or (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <epan/in_cksum.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/ip_opts.h>
#include <epan/follow.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include "packet-tcp.h"
#include "packet-frame.h"
#include <epan/conversation.h>
#include <epan/reassemble.h>
#include <epan/tap.h>
#include <epan/slab.h>
#include <epan/expert.h>
#include <math.h>
#include <packet-ip.h>
#include <timestamp.h>

extern FILE* data_out_file;

/*
    Set the default TCP preferences settings
*/
static gboolean try_heuristic_first = FALSE;
/*
   Enable desegmenting of TCP streams
*/
static gboolean tcp_desegment = TRUE;
/*
   Flag to control whether to check the TCP checksum.
   
   In at least some Solaris network traces, there are packets wmanually_set_wsfith bad
   TCP checksums, but the traffic appears to indicate that the packets
   *were* received; the packets were probably sent by the host on which
   the capture was being done, on a network interface to which
   checksumming was offloaded, so that DLPI supplied an un-checksummed
   packet to the capture program but a checksummed packet got put onto
   the wire.
*/
static gboolean tcp_check_checksum = FALSE;
static gboolean tcp_calculate_ts = FALSE;
static gboolean tcp_analyze_seq = TRUE;
static gboolean tcp_relative_seq = TRUE;
static gboolean tcp_track_unacked_and_bif = TRUE;
/*
   The default RTO period of 201ms while arbitrary is based on the fact that
   TCP implementations commonly set the Delayed ACK period to 200ms so the  
   RTO period is set one ms higher. If the user sets a different value in
   Preferences, that value will be persistent.
*/
static guint tcp_rto_period = 201;
static gboolean only_display_ack_flag_in_packet_list_when_needed = TRUE;
static gboolean display_ports_in_packet_list = TRUE;
/*
   Display the TCP length in the Packet List by default.
*/
static gboolean display_len_in_packet_list = TRUE;
/*
   By default don't display TSV and TSER Timestamps in the Info column 
   because there is very little that mere humans can deduce from them.
*/
static gboolean tcp_display_timestamps_in_summary = FALSE;
/*
  Place TCP summary in proto tree
*/
static gboolean summary_in_tcp_tree_header = TRUE;

#define SIDE_CAP_TAKEN_IS_UNKNOWN    0
#define CAP_TAKEN_ON_THE_RECEIVER    1
#define CAP_TAKEN_ON_THE_SENDER      2
#define AUTO_DETECT_SIDE_CAP_TAKEN   3
static const enum_val_t tcp_side_cap_taken[] = {
  { "Unknown",     "Unknown",      SIDE_CAP_TAKEN_IS_UNKNOWN  },
  { "Sender",      "Sender",       CAP_TAKEN_ON_THE_SENDER    },
  { "Auto-detect", "Auto-detect",  AUTO_DETECT_SIDE_CAP_TAKEN },
  { NULL, NULL, 0 }
};
static int sender_side_cap = AUTO_DETECT_SIDE_CAP_TAKEN;

/* End of static variables used for TCP preferences */


static int tcp_tap = -1;

static int proto_tcp = -1;
static int hf_tcp_srcport = -1;
static int hf_tcp_dstport = -1;
static int hf_tcp_port = -1;
static int hf_tcp_stream = -1;
static int hf_tcp_seq = -1;
static int hf_tcp_nxtseq = -1;
static int hf_tcp_ack = -1;
static int hf_tcp_hdr_len = -1;
static int hf_tcp_flags = -1;
static int hf_tcp_flags_res = -1;
static int hf_tcp_flags_ns = -1;
static int hf_tcp_flags_cwr = -1;
static int hf_tcp_flags_ecn = -1;
static int hf_tcp_flags_urg = -1;
static int hf_tcp_flags_ack = -1;
static int hf_tcp_flags_push = -1;
static int hf_tcp_flags_reset = -1;
static int hf_tcp_flags_syn = -1;
static int hf_tcp_flags_fin = -1;
static int hf_tcp_window_size_value = -1;
static int hf_tcp_window_size_scaled = -1;
static int hf_tcp_window_size_scale_unknown = -1;
static int hf_tcp_window_scale_ignored_due_to_missing_syn_or_synack_packet;
static int hf_tcp_window_size_scaling_unsupported = -1;
static int hf_tcp_window_scalefactor = -1;
static int hf_tcp_checksum = -1;
static int hf_tcp_checksum_bad = -1;
static int hf_tcp_checksum_good = -1;
static int hf_tcp_len = -1;
static int hf_tcp_urgent_pointer = -1;
static int hf_tcp_analysis_flags = -1;
static int hf_tcp_analysis_bytes_in_flight = -1;
static int hf_tcp_analysis_unacked_bytes = -1;
static int hf_tcp_analysis_mss = -1;
static int hf_tcp_analysis_acks_frame = -1;
static int hf_tcp_analysis_unacked_in_rev_flow = -1;
static int hf_tcp_analysis_ack_rtt = -1;
static int hf_tcp_analysis_can_exit_recovery = -1;
static int hf_tcp_analysis_frame_rec_entered = -1;
static int hf_tcp_analysis_time_in_rec = -1;
static int hf_tcp_analysis_rto = -1;
static int hf_tcp_analysis_rto_frame = -1;
static int hf_tcp_analysis_unwarranted_retransmission = -1;
static int hf_tcp_analysis_unwarranted_rxmt_and_new_data = -1;
static int hf_tcp_analysis_retransmission = -1;
static int hf_tcp_analysis_fast_retransmission = -1;
static int hf_tcp_analysis_fack_retransmission = -1;
static int hf_tcp_analysis_sack_retransmission = -1;
static int hf_tcp_analysis_newreno_retransmission = -1;
static int hf_tcp_analysis_rto_retransmission = -1;
static int hf_tcp_analysis_recovery_target = -1;
static int hf_tcp_analysis_first_rxmt = -1;
static int hf_tcp_analysis_orig_frame = -1;
static int hf_tcp_analysis_orig_frame_prior_to = -1;
static int hf_tcp_analysis_time_from_orig = -1;
static int hf_tcp_analysis_unacked_of_orig = -1;
static int hf_tcp_analysis_unacked_of_orig_in_first_rxmt = -1;
static int hf_tcp_analysis_prev_packet_unseen = -1;
static int hf_tcp_analysis_new_data_sent_in_rec = -1;
static int hf_tcp_analysis_prev_packet_lost = -1;
static int hf_tcp_analysis_packet_lost = -1;
static int hf_tcp_analysis_gap_size = -1;
static int hf_tcp_analysis_seq_number_space_alert = -1;
static int hf_tcp_analysis_rxmt_in_frame = -1;
static int hf_tcp_analysis_rxmt_ending_in_frame = -1;
static int hf_tcp_analysis_prev_seg_rxmt_at_frame = -1;
static int hf_tcp_analysis_ack_unseen_segment = -1;
static int hf_tcp_analysis_sack_unseen_segment = -1;
static int hf_tcp_analysis_out_of_order = -1;
static int hf_tcp_analysis_belongs_before_frame = -1;
static int hf_tcp_analysis_ooo_belongs_after_frame = -1;
static int hf_tcp_analysis_duplicate_frame = -1;
static int hf_tcp_analysis_duplicate_of = -1;
static int hf_tcp_analysis_prev_packet_out_of_order = -1;
static int hf_tcp_analysis_prev_packet_ooo_at_frame = -1;
static int hf_tcp_analysis_ack_of_out_of_order_segment = -1;
static int hf_tcp_analysis_reused_ports = -1;
static int hf_tcp_analysis_window_update = -1;
static int hf_tcp_analysis_window_exceeded = -1;
static int hf_tcp_analysis_window_full = -1;
static int hf_tcp_analysis_keep_alive = -1;
static int hf_tcp_analysis_keep_alive_ack = -1;
static int hf_tcp_analysis_duplicate_ack = -1;
static int hf_tcp_analysis_duplicate_ack_num = -1;
static int hf_tcp_analysis_duplicate_ack_frame = -1;
static int hf_tcp_analysis_gratuitous_ack = -1;
static int hf_tcp_analysis_zero_window = -1;
static int hf_tcp_analysis_zero_window_probe = -1;
static int hf_tcp_analysis_zero_window_probe_ack = -1;
static int hf_tcp_continuation_of = -1;
static int hf_tcp_pdu_time = -1;
static int hf_tcp_pdu_size = -1;
static int hf_tcp_pdu_last_frame = -1;
static int hf_tcp_reassembled_in = -1;
static int hf_tcp_reassembled_length = -1;
static int hf_tcp_segments = -1;
static int hf_tcp_segment = -1;
static int hf_tcp_segment_overlap = -1;
static int hf_tcp_segment_overlap_conflict = -1;
static int hf_tcp_segment_multiple_tails = -1;
static int hf_tcp_segment_too_long_fragment = -1;
static int hf_tcp_segment_error = -1;
static int hf_tcp_segment_count = -1;
static int hf_tcp_options = -1;
static int hf_tcp_options_len = -1;
static int hf_tcp_option_kind = -1;
static int hf_tcp_option_len = -1;
static int hf_tcp_option_mss = -1;
static int hf_tcp_option_mss_val = -1;
static int hf_tcp_option_wscale_shift = -1;
static int hf_tcp_option_wscale_multiplier = -1;
static int hf_tcp_option_sack_perm = -1;
static int hf_tcp_option_sack = -1;
static int hf_tcp_option_sack_sle = -1;
static int hf_tcp_option_sack_sre = -1;
static int hf_tcp_option_sack_triggered_by_ack = -1;
static int hf_tcp_option_sack_triggered_by_dsack = -1;
static int hf_tcp_option_sack_triggered_by_new_block = -1;
static int hf_tcp_option_sack_triggered_by_block_update = -1;
static int hf_tcp_option_sack_triggered_by_data = -1;
static int hf_tcp_option_sack_triggered_by_unknown = -1;
static int hf_tcp_option_included_sackblks = -1;
static int hf_tcp_option_active_sackblks = -1;
static int hf_tcp_option_sack_invalid_block = -1;
static int hf_tcp_option_sack_block = -1;
static int hf_tcp_option_sack_total_blocks = -1;
static int hf_tcp_option_sack_total_gaps = -1;
static int hf_tcp_option_sack_ack_to_fack = -1;
static int hf_tcp_option_echo = -1;
static int hf_tcp_option_echo_reply = -1;
static int hf_tcp_option_timestamps = -1;
static int hf_tcp_option_timestamp_tsval = -1;
static int hf_tcp_option_timestamp_tsecr = -1;
static int hf_tcp_option_cc = -1;
static int hf_tcp_option_ccnew = -1;
static int hf_tcp_option_ccecho = -1;
static int hf_tcp_option_md5 = -1;
static int hf_tcp_option_qs = -1;

static int hf_tcp_option_rvbd_probe = -1;
static int hf_tcp_option_rvbd_probe_version1 = -1;
static int hf_tcp_option_rvbd_probe_version2 = -1;
static int hf_tcp_option_rvbd_probe_type1 = -1;
static int hf_tcp_option_rvbd_probe_type2 = -1;
static int hf_tcp_option_rvbd_probe_optlen = -1;
static int hf_tcp_option_rvbd_probe_prober = -1;
static int hf_tcp_option_rvbd_probe_proxy = -1;
static int hf_tcp_option_rvbd_probe_client = -1;
static int hf_tcp_option_rvbd_probe_proxy_port = -1;
static int hf_tcp_option_rvbd_probe_appli_ver = -1;
static int hf_tcp_option_rvbd_probe_storeid = -1;
static int hf_tcp_option_rvbd_probe_flags = -1;
static int hf_tcp_option_rvbd_probe_flag_last_notify = -1;
static int hf_tcp_option_rvbd_probe_flag_server_connected = -1;
static int hf_tcp_option_rvbd_probe_flag_not_cfe = -1;
static int hf_tcp_option_rvbd_probe_flag_sslcert = -1;
static int hf_tcp_option_rvbd_probe_flag_probe_cache = -1;

static int hf_tcp_option_rvbd_trpy = -1;
static int hf_tcp_option_rvbd_trpy_flags = -1;
static int hf_tcp_option_rvbd_trpy_flag_mode = -1;
static int hf_tcp_option_rvbd_trpy_flag_oob = -1;
static int hf_tcp_option_rvbd_trpy_flag_chksum = -1;
static int hf_tcp_option_rvbd_trpy_flag_fw_rst = -1;
static int hf_tcp_option_rvbd_trpy_flag_fw_rst_inner = -1;
static int hf_tcp_option_rvbd_trpy_flag_fw_rst_probe = -1;
static int hf_tcp_option_rvbd_trpy_src = -1;
static int hf_tcp_option_rvbd_trpy_dst = -1;
static int hf_tcp_option_rvbd_trpy_src_port = -1;
static int hf_tcp_option_rvbd_trpy_dst_port = -1;
static int hf_tcp_option_rvbd_trpy_client_port = -1;

static int hf_tcp_ts_relative = -1;
static int hf_tcp_ts_delta = -1;
//static int hf_tcp_est_rtt= -1;
static int hf_tcp_option_scps = -1;
static int hf_tcp_option_scps_vector = -1;
static int hf_tcp_option_scps_binding = -1;
static int hf_tcp_scpsoption_flags_bets = -1;
static int hf_tcp_scpsoption_flags_snack1 = -1;
static int hf_tcp_scpsoption_flags_snack2 = -1;
static int hf_tcp_scpsoption_flags_compress = -1;
static int hf_tcp_scpsoption_flags_nlts = -1;
static int hf_tcp_scpsoption_flags_resv1 = -1;
static int hf_tcp_scpsoption_flags_resv2 = -1;
static int hf_tcp_scpsoption_flags_resv3 = -1;
static int hf_tcp_option_snack = -1;
static int hf_tcp_option_snack_offset = -1;
static int hf_tcp_option_snack_size = -1;
static int hf_tcp_option_snack_le = -1;
static int hf_tcp_option_snack_re = -1;
static int hf_tcp_option_mood = -1;
static int hf_tcp_option_mood_val = -1;
static int hf_tcp_option_user_to = -1;
static int hf_tcp_option_user_to_granularity = -1;
static int hf_tcp_option_user_to_val = -1;
static int hf_tcp_proc_src_uid = -1;
static int hf_tcp_proc_src_pid = -1;
static int hf_tcp_proc_src_uname = -1;
static int hf_tcp_proc_src_cmd = -1;
static int hf_tcp_proc_dst_uid = -1;
static int hf_tcp_proc_dst_pid = -1;
static int hf_tcp_proc_dst_uname = -1;
static int hf_tcp_proc_dst_cmd = -1;

static gint ett_tcp = -1;
static gint ett_tcp_sequence_analysis = -1;
static gint ett_tcp_ack_analysis = -1;
static gint ett_tcp_flags = -1;
static gint ett_tcp_window_size_scale = -1;
static gint ett_tcp_checksum = -1;
static gint ett_tcp_options = -1;
static gint ett_tcp_option_window_scale = -1;
static gint ett_tcp_option_sack = -1;
static int ett_tcp_option_included_sackblks = -1;
static gint ett_tcp_option_active_sackblks = -1;
static gint ett_tcp_option_timestamps = -1;
static gint ett_tcp_option_scps = -1;
static gint ett_tcp_option_scps_extended = -1;
static gint ett_tcp_option_user_to = -1;
static gint ett_tcp_delta_times = -1;
static gint ett_tcp_segments = -1;
static gint ett_tcp_segment  = -1;
static gint ett_tcp_process_info = -1;
static gint ett_tcp_opt_rvbd_probe = -1;
static gint ett_tcp_opt_rvbd_probe_flags = -1;
static gint ett_tcp_opt_rvbd_trpy = -1;
static gint ett_tcp_opt_rvbd_trpy_flags = -1;

/*
   TCP options
*/
#define TCPOPT_NOP              1       /* Padding */
#define TCPOPT_EOL              0       /* End of options */
#define TCPOPT_MSS              2       /* Segment size negotiating */
#define TCPOPT_WINDOW           3       /* Window scaling */
#define TCPOPT_SACK_PERM        4       /* SACK Permitted */
#define TCPOPT_SACK             5       /* SACK Block */
#define TCPOPT_ECHO             6
#define TCPOPT_ECHOREPLY        7
#define TCPOPT_TIMESTAMP        8       /* PAWS */
#define TCPOPT_CC               11
#define TCPOPT_CCNEW            12
#define TCPOPT_CCECHO           13
#define TCPOPT_MD5              19      /* RFC2385 */
#define TCPOPT_SCPS             20      /* SCPS Capabilities */
#define TCPOPT_SNACK            21      /* SCPS SNACK */
#define TCPOPT_RECBOUND         22      /* SCPS Record Boundary */
#define TCPOPT_CORREXP          23      /* SCPS Corruption Experienced */
#define TCPOPT_MOOD             25      /* RFC5841 TCP Packet Mood */
#define TCPOPT_QS               27      /* RFC4782 */
#define TCPOPT_USER_TO          28      /* RFC5482 */
/* Non IANA registered option numbers */
#define TCPOPT_RVBD_PROBE       76      /* Riverbed probe option */
#define TCPOPT_RVBD_TRPY        78      /* Riverbed transparency option */

/*
       TCP option lengths
*/
#define TCPOLEN_MSS            4
#define TCPOLEN_WINDOW         3
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_SACK_MIN       2
#define TCPOLEN_ECHO           6
#define TCPOLEN_ECHOREPLY      6
#define TCPOLEN_TIMESTAMP     10
#define TCPOLEN_CC             6
#define TCPOLEN_CCNEW          6
#define TCPOLEN_CCECHO         6
#define TCPOLEN_MD5           18
#define TCPOLEN_SCPS           4
#define TCPOLEN_SNACK          6
#define TCPOLEN_RECBOUND       2
#define TCPOLEN_CORREXP        2
#define TCPOLEN_MOOD_MIN       2
#define TCPOLEN_QS             8
#define TCPOLEN_USER_TO        4
#define TCPOLEN_RVBD_PROBE_MIN 3
#define TCPOLEN_RVBD_TRPY_MIN 16

static const true_false_string tcp_option_user_to_granularity = {
  "Minutes", "Seconds"
};

static const value_string tcp_option_kind_vs[] = {
    { TCPOPT_WINDOW,     "Window Scale" },
    { TCPOPT_TIMESTAMP,  "Timestamp" },
    { TCPOPT_SACK,       "SACK" },
    { 0, NULL }
};

/*
   Not all of the hf_fields below make sense for TCP but we have to provide
   them anyways to comply with the api (which was aimed for ip fragment
   reassembly)
*/
static const fragment_items tcp_segment_items = {
    &ett_tcp_segment,
    &ett_tcp_segments,
    &hf_tcp_segments,
    &hf_tcp_segment,
    &hf_tcp_segment_overlap,
    &hf_tcp_segment_overlap_conflict,
    &hf_tcp_segment_multiple_tails,
    &hf_tcp_segment_too_long_fragment,
    &hf_tcp_segment_error,
    &hf_tcp_segment_count,
    &hf_tcp_reassembled_in,
    &hf_tcp_reassembled_length,
    "Segments"
};

 /* Window scaling values to be used when not known (set as a preference) */
 enum scaling_window_value {
  WindowScaling_NotKnown=-1,
  WindowScaling_0=0,
  WindowScaling_1,
  WindowScaling_2,
  WindowScaling_3,
  WindowScaling_4,
  WindowScaling_5,
  WindowScaling_6,
  WindowScaling_7,
  WindowScaling_8,
  WindowScaling_9,
  WindowScaling_10,
  WindowScaling_11,
  WindowScaling_12,
  WindowScaling_13,
  WindowScaling_14
};
static gint manually_set_wsf = (gint)WindowScaling_NotKnown;
static const enum_val_t window_scaling_vals[] = {
    {"not-known",  "Not known",                  WindowScaling_NotKnown},
    {"0",          "0 (no scaling)",             WindowScaling_0},
    {"1",          "1 (multiply by 2)",          WindowScaling_1},
    {"2",          "2 (multiply by 4)",          WindowScaling_2},
    {"3",          "3 (multiply by 8)",          WindowScaling_3},
    {"4",          "4 (multiply by 16)",         WindowScaling_4},
    {"5",          "5 (multiply by 32)",         WindowScaling_5},
    {"6",          "6 (multiply by 64)",         WindowScaling_6},
    {"7",          "7 (multiply by 128)",        WindowScaling_7},
    {"8",          "8 (multiply by 256)",        WindowScaling_8},
    {"9",          "9 (multiply by 512)",        WindowScaling_9},
    {"10",         "10 (multiply by 1024)",      WindowScaling_10},
    {"11",         "11 (multiply by 2048)",      WindowScaling_11},
    {"12",         "12 (multiply by 4096)",      WindowScaling_12},
    {"13",         "13 (multiply by 8192)",      WindowScaling_13},
    {"14",         "14 (multiply by 16384)",     WindowScaling_14},
    {NULL, NULL, -1}
};

static dissector_table_t subdissector_table;
static heur_dissector_list_t heur_subdissector_list;
static dissector_handle_t data_handle;

/* SLAB allocators for the tcp_unacked_t, prev_seg_unseen_t, ua_rxmts_in_rec_t, and sackb_t which are
used in the ua_segs_l, prev_seg_miss_l, ua_rxmts_in_rec_l ,and sackb_l lists, respectively. */
SLAB_ITEM_TYPE_DEFINE(ua_segment_t)
static SLAB_FREE_LIST_DEFINE(ua_segment_t)
#define TCP_UNACKED_SEG_NEW(fi) SLAB_ALLOC(fi, ua_segment_t)
#define TCP_UNACKED_SEG_FREE(fi) SLAB_FREE(fi, ua_segment_t)

SLAB_ITEM_TYPE_DEFINE(prev_seg_unseen_t)
static SLAB_FREE_LIST_DEFINE(prev_seg_unseen_t)
#define TCP_PREV_SEGMENT_UNSEEN_NEW(fi) SLAB_ALLOC(fi, prev_seg_unseen_t)
#define TCP_PREV_SEGMENT_UNSEEN_FREE(fi) SLAB_FREE(fi, prev_seg_unseen_t)

SLAB_ITEM_TYPE_DEFINE(ua_rxmts_in_rec_t)
static SLAB_FREE_LIST_DEFINE(ua_rxmts_in_rec_t)
#define TCP_UNACKED_SEG_IN_REC_NEW(fi) SLAB_ALLOC(fi, ua_rxmts_in_rec_t)
#define TCP_UNACKED_SEG_IN_REC_FREE(fi) SLAB_FREE(fi, ua_rxmts_in_rec_t)

SLAB_ITEM_TYPE_DEFINE(sackb_t)
static SLAB_FREE_LIST_DEFINE(sackb_t)
#define TCP_SACKED_NEW(fi) SLAB_ALLOC(fi, sackb_t)
#define TCP_SACKED_FREE(fi) SLAB_FREE(fi, sackb_t)

/*
Although the following flags are used in only one of three structs, they must be unique because they
are OR'd and stored in lastsegmentflags.

Retransmission-related flags stored in tcpd->rxmtinfo->flags */
#define TCP_RETRANSMISSION                0x00000001
#define TCP_FAST_RETRANSMISSION           0x00000002
#define TCP_FACK_RETRANSMISSION           0x00000004
#define TCP_SACK_RETRANSMISSION           0x00000008
#define TCP_NEWRENO_RETRANSMISSION        0x00000010
#define TCP_RTO_RETRANSMISSION            0x00000020
#define TCP_UNWARRANTED_RETRANSMISSION    0x00000040
/*
Sender-related flags stored in tcpd->ta_send->flags */
#define TCP_KEEP_ALIVE                    0x00000080
#define TCP_ZERO_WINDOW_PROBE             0x00000100
#define TCP_DUPLICATE_FRAME               0x00000200
#define TCP_WINDOW_EXCEEDED               0x00000400
#define TCP_REUSED_PORTS                  0x00000800
#define TCP_OLD_SEQ                       0x00001000
#define TCP_SEQ_NUMBER_SPACE_ALERT        0x00002000
/*
TCP_PACKET_LOST must be the first of the next 5 */
#define TCP_PACKET_LOST                   0x00004000
#define TCP_OUT_OF_ORDER                  0x00008000
#define TCP_PREV_PACKET_UNSEEN            0x00010000
#define TCP_PREV_PACKET_LOST              0x00020000
#define TCP_PREV_PACKET_OUT_OF_ORDER      0x00040000
/*
Receiver-related flags stored in tcpd->ta_recv->flags */
#define TCP_DUPLICATE_ACK                 0x00080000 
#define TCP_ACK_OF_UNSEEN_SEGMENT         0x00100000
#define TCP_SACK_OF_UNSEEN_SEGMENT        0x00200000
#define TCP_ACK_OF_OUT_OF_ORDER_SEGMENT   0x00400000
#define TCP_ACK_ONLY_OUT_OF_ORDER         0x00800000
#define TCP_PARTNER_CAN_EXIT_RECOVERY     0x01000000
#define TCP_ACK_OF_KEEP_ALIVE             0x02000000
#define TCP_GRATUITOUS_ACK                0x04000000
/*
TCP_ZERO_WINDOW must be first among the window related flags */
#define TCP_ZERO_WINDOW                   0x08000000
#define TCP_ACK_OF_ZERO_WINDOW_PROBE      0x10000000
#define TCP_WINDOW_UPDATE                 0x20000000
#define TCP_WINDOW_FULL                   0x40000000
/* End of TCP flags */

/* psu triggering flags */
#define PSU_FIRSTXMITSEQ  1
#define PSU_BASED_ON_SEQ  2
#define PSU_BASED_ON_ACK  3
#define PSU_BASED_ON_SACK 4

#define TRIGGER_NEW_SACK_BLOCK     0x0001
#define TRIGGER_SACK_BLOCK_UPDATE  0x0002
#define TRIGGER_DSACK              0x0004
#define TRIGGER_ACK                0x0008
#define TRIGGER_NEW_DATA           0x0010
#define TRIGGER_UNKNOWN            0x0020

#define NANOSECS_PER_SEC 1000000000
#define _U_
#define UNKNOWN      -2
#define UNSUPPORTED  -1

static void
process_tcp_payload(tvbuff_t *tvb, volatile int offset, packet_info *pinfo,
    proto_tree *tree, proto_tree *tcp_tree, int src_port, int dst_port,
    guint32 seq, guint32 nxtseq, guint32 ack, guint32 win, 
    gboolean is_tcp_segment, struct tcp_analysis *tcpd);

/*
   If the 'sender_side_cap' preference is set to "Auto-detect" the following variables are used for that detection
   in the order of importance.
*/
int num_packet_lost        = 0;                                                
int num_ooo_segs           = 0;  
int num_ack_only_ooo       = 0;
int num_lso_pdus           = 0;
int num_lro_pdus           = 0;
/* End of "Auto Detect" variables */

/* The following are maintained but probably not useful for auto-detection or anything else. */
int num_prev_packet_lost   = 0; 
int num_prev_packet_ooo    = 0; 
int num_prev_packet_unseen = 0; 
int num_ack_of_ooo_seg     = 0;
int num_ack_of_unseen      = 0; 
int num_sack_of_unseen     = 0; 

struct tcp_analysis *
init_tcp_conversation_data(packet_info *pinfo)
{
    struct tcp_analysis *tcpd;

    /* Initialize the tcp protocol data structure to add to the tcp conversation */
    tcpd = se_alloc0(sizeof(struct tcp_analysis));

    tcpd->flow1.reused_port_conv = FALSE;
    tcpd->flow1.s_mss = 1460;
    tcpd->flow1.last_tcpflags = 0;
    tcpd->flow1.lastsegmentflags = 0;
    tcpd->flow1.flags = 0;
    tcpd->flow1.prev_frame = 0;

    tcpd->flow1.base_seq = 0;
    tcpd->flow1.firstxmitseq = 0;
    tcpd->flow1.ua_segs_l = NULL;
    tcpd->flow1.base_seq_old = 0;
    tcpd->flow1.last_seq = 0;
    tcpd->flow1.nextseq = 0;
    tcpd->flow1.seglen = 0;
    tcpd->flow1.last_seglen = 0;
    tcpd->flow1.multisegment_pdus=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "tcp_multisegment_pdus");

    tcpd->flow1.frame_rec_entered = 0;
    tcpd->flow1.rec_target = 0;
    tcpd->flow1.first_rxmtl = NULL;
    tcpd->flow1.num_first_rxmts = 0;
    tcpd->flow1.first_rxmt_avg = 0;
    tcpd->flow1.first_rxmt_stdev = 0.0;
    tcpd->flow1.ua_rxmt_bytes_in_rec = 0;
    tcpd->flow1.ua_rxmts_in_rec_l = NULL;
    tcpd->flow1.all_rxmt_bytes_in_rec = 0;
    tcpd->flow1.tot_rxmts_this_event = 0;
    tcpd->flow1.total_rexmits = 0;
    tcpd->flow1.prev_seg_miss_l = NULL;
    tcpd->flow1.max_seglen_rxmt = 0;
    tcpd->flow1.nextseq_upon_exit = 0;
    tcpd->flow1.last_ack_only_ooo = NULL;
    tcpd->flow1.unwarranted_rxmt = FALSE;
    
    tcpd->flow1.highest_ack = 0;
    tcpd->flow1.prior_highest_ack = 0;   
    tcpd->flow1.valid_unacked = TRUE;
    tcpd->flow1.dupacknum = 0;
    tcpd->flow1.dupacks_in_rec = 0;
    tcpd->flow1.lastnondupack_frame = 0;
    tcpd->flow1.num_ssackb = 0;
    tcpd->flow1.totalsacked = 0;
    tcpd->flow1.sackb_l = NULL;
    tcpd->flow1.sackl_rev_nextseq = 0;
    tcpd->flow1.snd_fack = 0;
    tcpd->flow1.partial_ack = FALSE;

    tcpd->flow1.win_scale = UNKNOWN;
    tcpd->flow1.max_size_window = 0;
    tcpd->flow1.max_size_unacked = 0;
    tcpd->flow1.lastwindow = 0;
    tcpd->flow1.max_size_acked = 0;

    tcpd->flow1.ip_id_valid = TRUE;
    tcpd->flow1.ip_id_prev = 0;
    tcpd->flow1.ip_id_highest = 0;

    tcpd->flow1.scps_capable = 0;
    tcpd->flow1.process_uid = 0;
    tcpd->flow1.process_pid = 0;
    tcpd->flow1.username = NULL;
    tcpd->flow1.command = NULL;
    tcpd->flow1.fcpa_stats_calculated = FALSE;

    /* flow2 */
    tcpd->flow2.reused_port_conv = FALSE;
    tcpd->flow2.s_mss = 1460;
    tcpd->flow2.last_tcpflags = 0;
    tcpd->flow2.lastsegmentflags = 0;
    tcpd->flow2.flags = 0;
    tcpd->flow2.prev_frame = 0;

    tcpd->flow2.base_seq = 0;
    tcpd->flow2.firstxmitseq = 0;
    tcpd->flow2.ua_segs_l = NULL;
    tcpd->flow2.base_seq_old = 0;
    tcpd->flow2.last_seq = 0;
    tcpd->flow2.nextseq = 0;
    tcpd->flow2.seglen = 0;
    tcpd->flow2.last_seglen = 0;
    tcpd->flow2.multisegment_pdus=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "tcp_multisegment_pdus");

    tcpd->flow2.frame_rec_entered = 0;
    tcpd->flow2.rec_target = 0;
    tcpd->flow2.first_rxmtl = NULL;
    tcpd->flow2.num_first_rxmts = 0;
    tcpd->flow2.first_rxmt_avg = 0;
    tcpd->flow2.first_rxmt_stdev = 0.0;
    tcpd->flow2.ua_rxmt_bytes_in_rec = 0;
    tcpd->flow2.ua_rxmts_in_rec_l = NULL;
    tcpd->flow2.all_rxmt_bytes_in_rec = 0;
    tcpd->flow2.tot_rxmts_this_event = 0;
    tcpd->flow2.total_rexmits = 0;
    tcpd->flow2.prev_seg_miss_l = NULL;
    tcpd->flow2.max_seglen_rxmt = 0;
    tcpd->flow2.nextseq_upon_exit = 0;
    tcpd->flow2.last_ack_only_ooo = NULL;
    tcpd->flow2.unwarranted_rxmt = FALSE;
    
    tcpd->flow2.highest_ack = 0;
    tcpd->flow2.prior_highest_ack = 0;   
    tcpd->flow2.valid_unacked = TRUE;
    tcpd->flow2.dupacknum = 0;
    tcpd->flow2.dupacks_in_rec = 0;
    tcpd->flow2.lastnondupack_frame = 0;
    tcpd->flow2.num_ssackb = 0;
    tcpd->flow2.totalsacked = 0;
    tcpd->flow2.sackb_l = NULL;
    tcpd->flow2.sackl_rev_nextseq = 0;
    tcpd->flow2.snd_fack = 0;
    tcpd->flow2.partial_ack = FALSE;

    tcpd->flow2.win_scale = UNKNOWN;
    tcpd->flow2.max_size_window = 0;
    tcpd->flow2.max_size_unacked = 0;
    tcpd->flow2.lastwindow = 0;
    tcpd->flow2.max_size_acked = 0;

    tcpd->flow2.ip_id_valid = TRUE;
    tcpd->flow2.ip_id_prev = 0;
    tcpd->flow2.ip_id_highest = 0;

    tcpd->flow2.scps_capable = 0;
    tcpd->flow2.process_uid = 0;
    tcpd->flow2.process_pid = 0;
    tcpd->flow2.username = NULL;
    tcpd->flow2.command = NULL;
    tcpd->flow2.fcpa_stats_calculated = FALSE;

    tcpd->ta_send_table     = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "tcp_analyze_ta_send_table");
    tcpd->ta_recv_table     = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "tcp_analyze_ta_recv_table");
    tcpd->saved_sackl_table = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "tcp_analyze_saved_sackl_table");
    tcpd->rxmtinfo_table    = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "tcp_analyze_rxmtinfo_table");
    
    tcpd->ts_first.secs     = pinfo->fd->abs_ts.secs;
    tcpd->ts_first.nsecs    = pinfo->fd->abs_ts.nsecs;
    tcpd->ts_prev.secs      = pinfo->fd->abs_ts.secs;
    tcpd->ts_prev.nsecs     = pinfo->fd->abs_ts.nsecs;
    
    tcpd->fin_sent          = FALSE;
    tcpd->mss_opt_seen      = FALSE;
    tcpd->ts_optlen         = 0;
    tcpd->sack_supported    = FALSE;
    tcpd->nplists_released  = FALSE;
    tcpd->syn_seen          = FALSE;
    tcpd->syn_ack_seen      = FALSE;
    tcpd->wsf_announced     = FALSE;

    return tcpd;
}

struct tcp_analysis *
get_tcp_conversation_data(conversation_t *conv, packet_info *pinfo)
{
    int direction;
    struct tcp_analysis *tcpd;
    /*
      Did the caller supply the conversation pointer?
    */
    if ( conv == NULL )
            conv = find_or_create_conversation(pinfo);

    /*
      Get the data for this conversation
    */
    tcpd = conversation_get_proto_data(conv, proto_tcp);

    /* If the conversation was just created or it matched a
       conversation with template options, tcpd will not
       have been initialized. So, initialize
       a new tcpd structure for the conversation.
    */
    if (!tcpd) {
        tcpd = init_tcp_conversation_data(pinfo);
        conversation_add_proto_data(conv, proto_tcp, tcpd);
    }

    if (!tcpd) {
      return NULL;
    }

    /*
      Check direction and get ua lists
    */
    direction = CMP_ADDRESS(&pinfo->src, &pinfo->dst);
    /* if the addresses are equal, match the ports instead */
    if (direction == 0) {
        direction= (pinfo->srcport > pinfo->destport) ? 1 : -1;
    }
    if (direction >= 0) {
        tcpd->fwd = (&tcpd->flow1);
        tcpd->rev = (&tcpd->flow2);
    } else {
        tcpd->fwd = (&tcpd->flow2);
        tcpd->rev = (&tcpd->flow1);
    }

    tcpd->ta_send  = NULL;
    tcpd->ta_recv  = NULL;
    tcpd->rxmtinfo = NULL;
    return tcpd;
}

/* Attach process info to a flow
   XXX - We depend on the TCP dissector finding the conversation first
*/
void
add_tcp_process_info(guint32 frame_num, address *local_addr, address *remote_addr, guint16 local_port, guint16 remote_port, guint32 uid, guint32 pid, gchar *username, gchar *command) {
    conversation_t *conv;
    struct tcp_analysis *tcpd;
    tcp_flow_t *flow = NULL;

    conv = find_conversation(frame_num, local_addr, remote_addr, PT_TCP, local_port, remote_port, 0);
    if (!conv) {
        return;
    }

    tcpd = conversation_get_proto_data(conv, proto_tcp);
    if (!tcpd) {
        return;
    }

    if (CMP_ADDRESS(local_addr, &conv->key_ptr->addr1) == 0 && local_port == conv->key_ptr->port1) {
        flow = &tcpd->flow1;
    } else if (CMP_ADDRESS(remote_addr, &conv->key_ptr->addr1) == 0 && remote_port == conv->key_ptr->port1) {
        flow = &tcpd->flow2;
    }
    if (!flow || flow->command) {
        return;
    }

    flow->process_uid = uid;
    flow->process_pid = pid;
    flow->username    = se_strdup(username);
    flow->command     = se_strdup(command);
}


/* Calculate the timestamps relative to this conversation
*/
static void
tcp_calc_delta_time_info(packet_info *pinfo, struct tcp_analysis *tcpd, struct tcp_per_packet_data_t *tcppd)
{
    if (!tcpd || !tcppd)
        return;

    nstime_delta(&tcppd->ts_del, &pinfo->fd->abs_ts, &tcpd->ts_prev);

    tcpd->ts_prev.secs=pinfo->fd->abs_ts.secs;
    tcpd->ts_prev.nsecs=pinfo->fd->abs_ts.nsecs;
}


/*
  Round the timestamp per the currently selected precision and return a printf format string.
*/
static char* 
ts_prec_fmt(int *raw_secs, int *raw_nsecs, int *secs, int *nsecs)
{
    int prec=0;
    guint64 time;
    
    prec = timestamp_get_precision(); 
    time = ((guint64)*raw_secs*NANOSECS_PER_SEC) + *raw_nsecs;

    if (prec == TS_PREC_FIXED_SEC || prec == TS_PREC_AUTO_SEC) {
        time   =       time  + 500000000;
        *secs  = (int)(time  / NANOSECS_PER_SEC);
        *nsecs = 0;
        return ep_strdup("%0d");

    } else if (prec == TS_PREC_FIXED_DSEC || prec == TS_PREC_AUTO_DSEC) {
        time   =       time  + 50000000;
        *secs  = (int)(time  / NANOSECS_PER_SEC);
        *nsecs = (int)(time  % NANOSECS_PER_SEC);
        *nsecs =      *nsecs / 100000000;
        return ep_strdup("%d.%01d");

    } else if (prec == TS_PREC_FIXED_CSEC || prec == TS_PREC_AUTO_CSEC) {
        time   =       time  + 5000000;
        *secs  = (int)(time  / NANOSECS_PER_SEC);
        *nsecs = (int)(time  % NANOSECS_PER_SEC);
        *nsecs =      *nsecs / 10000000;
        return ep_strdup("%d.%02d");
    
    } else if (prec == TS_PREC_FIXED_MSEC || prec == TS_PREC_AUTO_MSEC) {
        time   =       time  + 500000;
        *secs  = (int)(time  / NANOSECS_PER_SEC);
        *nsecs = (int)(time  % NANOSECS_PER_SEC);
        *nsecs =      *nsecs / 1000000;
        return ep_strdup("%d.%03d");
    
    } else if (prec == TS_PREC_FIXED_USEC || prec == TS_PREC_AUTO_USEC) {
        time   =       time  + 500;
        *secs  = (int)(time  / NANOSECS_PER_SEC);
        *nsecs = (int)(time  % NANOSECS_PER_SEC);
        *nsecs =      *nsecs / 1000;
        return ep_strdup("%d.%06d");
    
    } else if (prec == TS_PREC_FIXED_NSEC || prec == TS_PREC_AUTO_NSEC) {
        *secs  =      *raw_secs;
        *nsecs =      *raw_nsecs;
        return ep_strdup("%d.%09d");
    
    } else {
        *secs  =      *raw_secs;
        *nsecs =      *raw_nsecs;
        g_assert_not_reached();
        return ep_strdup("%d.%09d");
    } 
}


/*
  Add a subtree with the timestamps relative to this conversation
*/
static void
tcp_print_delta_time_info(packet_info *pinfo, tvbuff_t *tvb, proto_tree *parent_tree, struct tcp_analysis *tcpd,
                     struct tcp_per_packet_data_t *tcppd)
{
    proto_item *item;
    proto_tree *tree;
    nstime_t ts_rel, ts_del;
    int secs=0, nsecs=0;
    char* ts_fmt;

    if (!tcpd)
        return;

    item = proto_tree_add_text( parent_tree, tvb, 0, 0, "Time Info:");
    tree = proto_item_add_subtree( item, ett_tcp_delta_times);
    /*
      Display the relative time (delta from frame #1). 
    */
    nstime_delta( &ts_rel, &pinfo->fd->abs_ts, &tcpd->ts_first);
    ts_fmt = ts_prec_fmt( (int*)&ts_rel.secs, &ts_rel.nsecs, &secs, &nsecs);
    ts_fmt = g_strconcat("  From start of stream (relative time): ", ts_fmt, NULL);
    proto_item_append_text( tree, ts_fmt, secs, nsecs);
    item = proto_tree_add_time_format(tree, hf_tcp_ts_relative, tvb, 0, 0, 
                                      &ts_rel, ts_fmt+2, secs, nsecs);
    PROTO_ITEM_SET_GENERATED(item);
    /*
      Display the delta time from the previous displayed frame *in this stream*. 
    */
    if ( !tcppd )
        tcppd = p_get_proto_data( pinfo->fd, proto_tcp);

    if ( tcppd ) {
        ts_del = tcppd->ts_del;
        ts_fmt = ts_prec_fmt( (int*)&ts_del.secs, &ts_del.nsecs, &secs, &nsecs);
        ts_fmt = g_strconcat(",  From previous frame in this stream (delta time displayed): ", ts_fmt, NULL);
        proto_item_append_text( tree, ts_fmt, secs, nsecs);
        item = proto_tree_add_time_format(tree, hf_tcp_ts_delta, tvb, 0, 0, 
                                          &ts_del, ts_fmt+3, secs, nsecs);
        PROTO_ITEM_SET_GENERATED(item);
    }
}

static void
print_pdu_tracking_data(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tcp_tree, struct tcp_multisegment_pdu *msp)
{
    proto_item *item;

    col_append_fstr(pinfo->cinfo, COL_INFO, "[Continuation of #%u] ", msp->first_frame);
    item=proto_tree_add_uint(tcp_tree, hf_tcp_continuation_of,
        tvb, 0, 0, msp->first_frame);
    PROTO_ITEM_SET_GENERATED(item);
}

/* if we know that a PDU starts inside this segment, return the adjusted
   offset to where that PDU starts or just return offset back
   and let TCP try to find out what it can about this segment
*/
static int
scan_for_next_pdu(tvbuff_t *tvb, proto_tree *tcp_tree, packet_info *pinfo, int offset, guint32 seq, guint32 nxtseq, emem_tree_t *multisegment_pdus)
{
    struct tcp_multisegment_pdu *msp=NULL;

    if (!pinfo->fd->flags.visited) {
        msp = se_tree_lookup32_le(multisegment_pdus, seq-1);
        if (msp) {
            /* If this is a continuation of a PDU started in a
               previous segment we need to update the last_frame
               variables.
            */
            if(GT_SEQ(seq, msp->seq)
            && LT_SEQ(seq, msp->nxtpdu)) {
                msp->last_frame=pinfo->fd->num;
                msp->last_frame_time=pinfo->fd->abs_ts;
                print_pdu_tracking_data(pinfo, tvb, tcp_tree, msp);
            }

            /* If this segment is completely within a previous PDU
               then we just skip this packet */
                
            if(GT_SEQ(seq, msp->seq)
            && LE_SEQ(nxtseq, msp->nxtpdu)) {
                return -1;
            }
            if (LT_SEQ(seq, msp->nxtpdu) && GT_SEQ(nxtseq, msp->nxtpdu)) {
                offset+=msp->nxtpdu-seq;
                return offset;
            }

        }
    } else {
        /*
           First we try to find the start and transfer time for a PDU.
           We only print this for the very first segment of a PDU
           and only for PDUs spanning multiple segments.
           Se we look for if there was any multisegment PDU started
           just BEFORE the end of this segment. I.e. either inside this
           segment or in a previous segment.
           Since this might also match PDUs that are completely within
           this segment we also verify that the found PDU does span
           beyond the end of this segment.
            
        msp=se_tree_lookup32_le(multisegment_pdus, nxtseq-1);
        if (msp) {
            if (pinfo->fd->num == msp->first_frame) {
                proto_item *item;
                nstime_t ns;

                item=proto_tree_add_uint(tcp_tree, hf_tcp_pdu_last_frame, tvb, 0, 0, msp->last_frame);
                PROTO_ITEM_SET_GENERATED(item);

                nstime_delta(&ns, &msp->last_frame_time, &pinfo->fd->abs_ts);
                item = proto_tree_add_time(tcp_tree, hf_tcp_pdu_time,
                        tvb, 0, 0, &ns);
                PROTO_ITEM_SET_GENERATED(item);
            }
        }

        /*
          Second we check if this segment is part of a PDU started
           prior to the segment (seq-1)
        */
        msp=se_tree_lookup32_le(multisegment_pdus, seq-1);
        if (msp) {
            /*
               If this segment is completely within a previous PDU
               then we just skip this packet
            */
               if (GT_SEQ(seq, msp->seq) && LE_SEQ(nxtseq, msp->nxtpdu)) {
               print_pdu_tracking_data(pinfo, tvb, tcp_tree, msp);
               return -1;
            }

            if (LT_SEQ(seq, msp->nxtpdu) && GT_SEQ(nxtseq, msp->nxtpdu)) {
                offset+=msp->nxtpdu-seq;
                return offset;
            }
        }

    }
    return offset;
}

/* if we saw a PDU that extended beyond the end of the segment,
   use this function to remember where the next pdu starts
*/
struct tcp_multisegment_pdu *
pdu_store_sequencenumber_of_next_pdu(packet_info *pinfo, guint32 seq, guint32 nxtpdu, emem_tree_t *multisegment_pdus)
{
    struct tcp_multisegment_pdu *msp;

    msp=se_alloc(sizeof(struct tcp_multisegment_pdu));
    msp->nxtpdu=nxtpdu;
    msp->seq=seq;
    msp->first_frame=pinfo->fd->num;
    msp->last_frame=pinfo->fd->num;
    msp->last_frame_time=pinfo->fd->abs_ts;
    msp->flags=0;
    se_tree_insert32(multisegment_pdus, seq, (void *)msp);
    return msp;
}

/*
   Set the tcpd->ta_send to the ta_send_t struct for this frame if one exists. If not and createflag is
   TRUE, set tcpd->ta_send to the address of a new ta_send_t struct.
*/
static void
tcp_analyze_get_ta_send_struct(guint32 frame, gboolean createflag, struct tcp_analysis *tcpd)
{
    if (!tcpd)
        return;

    tcpd->ta_send = se_tree_lookup32(tcpd->ta_send_table, frame);

    if (!tcpd->ta_send && createflag) {
        tcpd->ta_send = se_alloc0(sizeof(ta_send_t));
        se_tree_insert32(tcpd->ta_send_table, frame, (void *)tcpd->ta_send);
        tcpd->ta_send->flags = 0;
        tcpd->ta_send->this_frame = 0;
        tcpd->ta_send->rxmt_at_frame = 0;
        tcpd->ta_send->orig_frame = 0;
        tcpd->ta_send->seg_falls_in_gap = FALSE;
        tcpd->ta_send->gap_size = 0;
        tcpd->ta_send->new_data_sent_in_rec = 0;
    }
}

/*
  Set the tcpd->ta_recv to the ta_recv_t struct for this frame if one exists. If not and createflag is
  TRUE, set tcpd->ta_recv to the address of a new ta_recv_t struct and insert it into
  tcpd->ta_recv_table.
*/
static void
tcp_analyze_get_ta_recv_struct(guint32 frame, gboolean createflag, struct tcp_analysis *tcpd)
{
    if (!tcpd)
        return;

    tcpd->ta_recv = se_tree_lookup32(tcpd->ta_recv_table, frame);

    if (!tcpd->ta_recv && createflag) {
        tcpd->ta_recv = se_alloc0(sizeof(ta_recv_t));
        se_tree_insert32(tcpd->ta_recv_table, frame, (void *)tcpd->ta_recv);
        tcpd->ta_recv->flags = 0;
        tcpd->ta_recv->triggered_by = 0;
        tcpd->ta_recv->frame_acked = 0;
        tcpd->ta_recv->dupack_num = 0;
        tcpd->ta_recv->dup_of_ack_in_frame = 0;
        tcpd->ta_recv->ooo_belongs_after = 0;
        tcpd->ta_recv->frame_rec_entered = 0;
        tcpd->ta_recv->unacked_in_rev = 0;
    }
}

/*
   See if there is a (saved_sackb_l_t) tcpd->saved_sackb_l struct for this frame in 
   tcpd->saved_sackl_table. If found, tcpd->saved_sackb_l->arr points to an array of (saved_sackb_t) ssackb structs that were
   active when this frame was sent. If a saved_sackb_l struct does not exist for this frame and
   createflag is TRUE: 
     o allocate memory for a new (saved_sackb_l_t) saved_sackb_l
     o allocate memory for num_active_blks saved_sackb_t (ssackb) structs
     o point tcpd->saved_sackb_l->arr to that list, and
     o insert the new tcpd->saved_sackb_l in tcpd->saved_sackl_table
 */
static void
tcp_analyze_get_saved_sackl_struct(guint32 frame, gboolean createflag, guint16 num_active_blks, 
                                   struct tcp_analysis *tcpd)
{
    if (!tcpd)
        return;

    tcpd->saved_sackb_l = se_tree_lookup32(tcpd->saved_sackl_table, frame);

    if ( !tcpd->saved_sackb_l && createflag) {       
        tcpd->saved_sackb_l      = se_alloc0(sizeof(struct saved_sackb_l_t));
        tcpd->saved_sackb_l->arr = se_alloc_array(saved_sackb_t, num_active_blks);
        se_tree_insert32(tcpd->saved_sackl_table, frame, (void *)tcpd->saved_sackb_l);
        tcpd->saved_sackb_l->num_active_blks = 0;
        tcpd->saved_sackb_l->invalid_blks = FALSE;
        tcpd->saved_sackb_l->rev_in_recovery = FALSE;
    }
}

/* Set tcpd->rxmtinfo to the rxmtinfo struct for this frame if it exists. If not and createflag is
*  TRUE, set tcpd->rxmtinfo to the address of a new rxmtinfo_t struct.
*/
static void
tcp_analyze_get_rxmtinfo_struct(guint32 frame, gboolean createflag, struct tcp_analysis *tcpd)
{
    if (!tcpd)
        return;

    tcpd->rxmtinfo = se_tree_lookup32(tcpd->rxmtinfo_table, frame);

    if (!tcpd->rxmtinfo && createflag) {
        tcpd->rxmtinfo = se_alloc0(sizeof(struct tcp_rxmtinfo_t));
        se_tree_insert32(tcpd->rxmtinfo_table, frame, (void *)tcpd->rxmtinfo);
        tcpd->rxmtinfo->flags = 0;
        tcpd->rxmtinfo->orig_frame = 0;
        tcpd->rxmtinfo->unacked_of_orig = 0;        
        tcpd->rxmtinfo->is_first_rxmt = FALSE;
        tcpd->rxmtinfo->rec_target = 0;
        tcpd->rxmtinfo->frame_rec_entered = 0;
        tcpd->rxmtinfo->remaining = 0;
        tcpd->rxmtinfo->new_data_appended = 0;
        tcpd->rxmtinfo->ack_lost = FALSE;
        tcpd->rxmtinfo->re_retransmission = FALSE;
    }
}

/* Free all the nonpersistent struct lists used in tcp_analyze_sequence_number()
*/
static void
release_all_non_persistent_lists(struct tcp_analysis *tcpd)
{
    ua_segment_t      *ua_seg,  *tmp_ua_seg;
    prev_seg_unseen_t *psu,     *tmp_psu;
    ua_rxmts_in_rec_t *ua_rxmt, *tmp_ua_rxmt;
    sackb_t           *sackb,   *tmp_sackb;
    
    /* Free ua_segs_l */
    ua_seg = tcpd->fwd->ua_segs_l;
    while (ua_seg) {
        tmp_ua_seg = ua_seg->next;
        TCP_UNACKED_SEG_FREE(ua_seg);
        tcpd->fwd->ua_segs_l = tmp_ua_seg; 
        ua_seg = tmp_ua_seg;
    }
    ua_seg = tcpd->rev->ua_segs_l;
    while (ua_seg) {
        tmp_ua_seg = ua_seg->next;
        TCP_UNACKED_SEG_FREE(ua_seg);
        tcpd->rev->ua_segs_l = tmp_ua_seg; 
        ua_seg = tmp_ua_seg;
    }

    /* Free prev_seg_miss_l */
    psu = tcpd->fwd->prev_seg_miss_l;
    while (psu) {
        tmp_psu = psu->next;
        TCP_PREV_SEGMENT_UNSEEN_FREE(psu);
        tcpd->fwd->prev_seg_miss_l = tmp_psu;
        psu = tmp_psu;
    }
    tcpd->fwd->last_ack_only_ooo = NULL;

    psu = tcpd->rev->prev_seg_miss_l;
    while (psu) {
        tmp_psu = psu->next;
        TCP_PREV_SEGMENT_UNSEEN_FREE(psu);
        tcpd->rev->prev_seg_miss_l = tmp_psu;
        psu = tmp_psu;
    }
    tcpd->rev->last_ack_only_ooo = NULL;

    /* Free ua_rxmts_in_rec_l */
    ua_rxmt = tcpd->fwd->ua_rxmts_in_rec_l;
    while (ua_rxmt) {
        tmp_ua_rxmt = ua_rxmt->next;
        TCP_UNACKED_SEG_IN_REC_FREE(ua_rxmt);
        tcpd->fwd->ua_rxmts_in_rec_l = tmp_ua_rxmt;
        ua_rxmt = tmp_ua_rxmt;             
    }

    ua_rxmt = tcpd->rev->ua_rxmts_in_rec_l;
    while (ua_rxmt) {
        tmp_ua_rxmt = ua_rxmt->next;
        TCP_UNACKED_SEG_IN_REC_FREE(ua_rxmt);
        tcpd->rev->ua_rxmts_in_rec_l = tmp_ua_rxmt;
        ua_rxmt = tmp_ua_rxmt;             
    }

    /* Free sackb_l */
    sackb = tcpd->fwd->sackb_l;
    while (sackb) {
        tmp_sackb = sackb->next;
        TCP_SACKED_FREE(sackb);
        tcpd->fwd->sackb_l = tmp_sackb;
        sackb = tmp_sackb;
    }
    tcpd->fwd->num_ssackb = 0;
    tcpd->fwd->totalsacked = 0;
    tcpd->fwd->sackl_rev_nextseq = 0;
    tcpd->fwd->snd_fack = 0;
    tcpd->fwd->dsack = FALSE;
    
    sackb = tcpd->rev->sackb_l;
    while (sackb) {
        tmp_sackb = sackb->next;
        TCP_SACKED_FREE(sackb);
        tcpd->rev->sackb_l = tmp_sackb;
        sackb = tmp_sackb;
    }
    tcpd->rev->num_ssackb = 0;
    tcpd->rev->totalsacked = 0;
    tcpd->rev->sackl_rev_nextseq = 0;
    tcpd->rev->snd_fack = 0;
    tcpd->rev->dsack = FALSE;

    tcpd->nplists_released = TRUE;
}

/*
* Called when there is a drastic change in the sequence number space in either flow. This routine
* reinitializes variables that if left unchanged might cause spurious error messages. 
*/
static void
number_space_alert(guint32 seq, guint32 ack, packet_info *pinfo, struct tcp_analysis *tcpd)
{
    release_all_non_persistent_lists(tcpd);
    
    tcpd->fwd->nextseq = seq;
    tcpd->fwd->last_seq = seq;
    tcpd->fwd->highest_ack = ack;
    tcpd->fwd->prior_highest_ack = ack;
    tcpd->fwd->dupacknum = 0;
    tcpd->fwd->dupacks_in_rec = 0;
    tcpd->fwd->lastnondupack_frame = pinfo->fd->num;
    tcpd->fwd->valid_unacked = FALSE;
    tcpd->fwd->rec_target = 0;
    tcpd->fwd->frame_rec_entered = 0;
    tcpd->fwd->ua_rxmt_bytes_in_rec= 0;
    tcpd->fwd->all_rxmt_bytes_in_rec= 0;
    tcpd->fwd->nextseq_upon_exit = 0;
    tcpd->fwd->tot_rxmts_this_event = 0;
    tcpd->fwd->unwarranted_rxmt = FALSE;
    tcpd->fwd->ip_id_valid = FALSE;
    tcpd->fwd->ip_id_prev = 0;
    tcpd->fwd->ip_id_highest = pinfo->ip_id;

    tcpd->rev->nextseq = ack;
    tcpd->rev->last_seq = ack;
    tcpd->rev->highest_ack = seq;
    tcpd->rev->prior_highest_ack = seq;
    tcpd->rev->dupacknum = 0;
    tcpd->rev->dupacks_in_rec = 0;
    tcpd->rev->lastnondupack_frame = pinfo->fd->num;
    tcpd->rev->valid_unacked = FALSE;
    tcpd->rev->rec_target = 0;
    tcpd->rev->frame_rec_entered = 0;
    tcpd->rev->ua_rxmt_bytes_in_rec= 0;
    tcpd->rev->all_rxmt_bytes_in_rec= 0;
    tcpd->rev->nextseq_upon_exit = 0;
    tcpd->rev->tot_rxmts_this_event = 0;
    tcpd->rev->unwarranted_rxmt = FALSE;
    tcpd->rev->ip_id_valid = FALSE;
    tcpd->rev->ip_id_prev = 0;
    tcpd->rev->ip_id_highest = pinfo->ip_id;     
}


/*
   The TCP options must be processed prior to this routine because BIF of packets sent while in TCP
   recovery, the detection of FACK retransmissions, and (when eventually implemented) the determination
   of the number of segments actually sent with LSO packets. The latter will be used in the calculation
   of the retransmission ratio.     
   
   NOTE: New segments are always added to the head of the fwd/rev lists.
 */
static void
tcp_analyze_sequence_number(packet_info *pinfo, guint32 seq, guint32 ack, guint32 seglen, 
                            guint16 tcpflags, guint32 window, guint optlen, 
                            struct tcp_analysis *tcpd, tcp_per_packet_data_t *tcppd)
{
    conversation_t *conv=NULL;
    guint32 frame=pinfo->fd->num, in_flight=0, unacked;
    guint32 nextseq, snd_fack=0, orig_frame=0, new_data_seq=0;
    guint64 time_from_orig=0, rto_period;
    gboolean is_dupack=FALSE, is_rxmt=FALSE, is_ooo=FALSE, seg_falls_in_gap=FALSE;
    nstime_t orig_frame_ts, tmp_dt;
    ua_segment_t *ua_seg=NULL, *prevual=NULL, *nextual;
    ua_rxmts_in_rec_t  *ua_rxmt=NULL, *tmp_ua_rxmt=NULL, *prev_ua_rxmt=NULL; 
    sackb_t *sackb=NULL, *prev_sackb=NULL, *tmp_sackb=NULL;
    prev_seg_unseen_t *psu=NULL, *next_psu=NULL, *prev_psu=NULL, *tmp_psu=NULL;

#ifdef REMOVED
printf("analyze_sequence numbers   frame:%u  direction:%s\n",frame,direction>=0?"FWD":"REW");
printf("FWD list lastflags:0x%04x base_seq:0x%08x:\n",tcpd->fwd->lastsegmentflags, tcpd->fwd->base_seq);
for(ua_seg=tcpd->fwd->ua_segs_l;ua_seg;ua_seg=ua_seg->next)
    printf("Frame:%d Seq:%d Nextseq:%d\n", ua_seg->frame,ua_seg->seq,ua_seg->nextseq);
printf("REV list lastflags:0x%04x base_seq:0x%08x:\n",tcpd->rev->lastsegmentflags,tcpd->rev->base_seq);
for(ua_seg=tcpd->rev->ua_segs_l;ua_seg;ua_seg=ua_seg->next)
    printf("Frame:%d Seq:%d Nextseq:%d\n",ua_seg->frame,ua_seg->seq,ua_seg->nextseq);
#endif

    if (!tcpd) {
        return;
    }

    tcpd->fwd->unwarranted_rxmt = 0;
    /*
      TCP_REUSED_PORTS

      If this is a SYN packet and seq is different from the base_seq of this conv, create a new
      conversation with the same addresses and ports, and set the TCP_REUSED_PORTS flag. 
    */
    if(tcpd 
    && (tcpflags&(TH_SYN|TH_ACK)) == TH_SYN
    && tcpd->fwd->base_seq != 0
    && seq != tcpd->fwd->base_seq) {          
        guint32 tmp_fwd_base_seq_old = tcpd->fwd->base_seq;
        guint32 tmp_rev_base_seq_old = tcpd->rev->base_seq;
        
        if (!(pinfo->fd->flags.visited)) {
            conv=conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
                pinfo->srcport, pinfo->destport, 0);
            tcpd =get_tcp_conversation_data(conv,pinfo);
            tcpd->fwd->firstxmitseq = 0;
        }
        if (!tcpd->ta_send)
            tcp_analyze_get_ta_send_struct(pinfo->fd->num, TRUE, tcpd);
        tcpd->ta_send->flags|=TCP_REUSED_PORTS;
        tcpd->fwd->reused_port_conv = TRUE;
        tcpd->rev->reused_port_conv = TRUE;
        tcpd->fwd->base_seq_old = tmp_fwd_base_seq_old;
        tcpd->rev->base_seq_old = tmp_rev_base_seq_old;
    }

    /*
       If the port has been reused and seq is more than one max size window greater or less than the
       highext nextseq seen in this flow, consider this packet to be associated with the previous
       connection.  
     */
    if(tcpd->fwd->reused_port_conv
    && (tcpflags&TH_SYN) == 0)
    {
        guint32 tmp_nxtseq = seq + seglen;

        if((tmp_nxtseq > tcpd->fwd->nextseq && tmp_nxtseq > tcpd->fwd->nextseq + tcpd->rev->max_size_window)
        || (tmp_nxtseq < tcpd->fwd->nextseq && tmp_nxtseq < tcpd->fwd->nextseq - tcpd->rev->max_size_window)) {
            /*
              TCP_OLD_SEQ
            */
            tcp_analyze_get_ta_send_struct(pinfo->fd->num, TRUE, tcpd);
            tcpd->ta_send->flags |= TCP_OLD_SEQ;
        } else {
            /*
               The sender is transmitting sequence numbers that belong to the new connection. If this
               seq is more than one max window size greater than the base_seq, we no longer have to 
               check for old seq numbers and can reset the reused_ports flag.
            */
            if (GT_SEQ(seq, tcpd->fwd->base_seq + tcpd->rev->max_size_window))
                tcpd->fwd->reused_port_conv = FALSE;
        }
    }

    /*
        TCP_DUPLICATE_FRAME
    */
    if(pinfo->ip_id == tcpd->fwd->ip_id_prev
    && ((tcpflags & TH_RST) ? pinfo->ip_id > 0 : TRUE)
    && tcpflags == tcpd->fwd->last_tcpflags
    && seq == tcpd->fwd->last_seq
    && seglen == tcpd->fwd->last_seglen
    && window == tcpd->fwd->lastwindow
    && ((tcpflags & TH_RST) ? TRUE : ack == tcpd->fwd->highest_ack)
    && ((tcpflags & TH_RST) ? TRUE : ack == tcpd->fwd->prior_highest_ack)) {
        if (!tcpd->ta_send)
            tcp_analyze_get_ta_send_struct(frame, TRUE, tcpd);
        tcpd->ta_send->flags |= TCP_DUPLICATE_FRAME;
        tcpd->ta_send->orig_frame = tcpd->fwd->prev_frame;
        tcpd->ta_send->this_frame = frame;
        return;
    }
    
    if (pinfo->ip_id == 0 || tcpd->fwd->ip_id_highest == 0 || tcpd->fwd->base_seq == 0) {
        tcpd->fwd->ip_id_valid = FALSE;
        tcpd->fwd->ip_id_highest = pinfo->ip_id;    
    }  

    /* Set nextseq. 
       SYN/FIN counts as one byte; howerver, according to RFC 1122 FIN's can include new data which
       is quite common in half-open connections where the opposite flow has more data to transmit
       before it terminates its half of the connection.
    */
    nextseq = seq + seglen;
    if (tcpd->fwd->nextseq == 0)
        tcpd->fwd->nextseq = seq;     

    if (tcpd->fwd->firstxmitseq == 0)
        tcpd->fwd->firstxmitseq = seq;

    if (tcpd->fwd->highest_ack == 0)
        tcpd->fwd->highest_ack = ack;  

    if (tcpd->fwd->base_seq == 0) {
        if (tcpflags & TH_SYN) {
            tcpd->fwd->base_seq = seq;
        } else {
            /*
               The base_seq is zero. Since SYN flag is not set so the 3-way handshake was not captured,
               set base_seq to seq-1 so that relative seq/ack numbers are displayed correctly. 
               (Solves Bug 1542)
            */
            tcpd->fwd->base_seq = seq-1;
            /*
               In order to detect out-of-order frames sent prior to the first frame in this flow, create
               a dummy "previous segment unseen" (psu) entry in the tcpd->prev_seg_miss_l list.  
            */
            TCP_PREV_SEGMENT_UNSEEN_NEW(psu);
            psu->frame = frame;
            psu->trigger = PSU_FIRSTXMITSEQ;
            psu->ack_only_no_sack = (seglen == 0 ? TRUE : FALSE);
            psu->lbound = 0;
            psu->ubound = 0;
            psu->seq = seq;  
            psu->nextseq = nextseq;
            psu->ack = tcpd->rev->highest_ack;
            psu->ip_id = (tcpd->fwd->ip_id_valid ? pinfo->ip_id : 0);
            psu->ip_id_high_rev = (tcpd->rev->ip_id_valid ? tcpd->rev->ip_id_highest : 0);
            psu->ts = pinfo->fd->abs_ts;
            psu->unacked = 0;
            psu->next = NULL;
            tcpd->fwd->prev_seg_miss_l = psu;
        }
    } else {
        /*
           If seq is lower than base_seq, update base_seq.
        */
        if (!tcpd->fwd->reused_port_conv && (LT_SEQ(seq, tcpd->fwd->base_seq)))
            tcpd->fwd->base_seq = seq;
    }

    /*
       If the base_seq is zero in the *rev* flow, set it to ack-1 and nextseq to ack 
    */
    if (tcpflags & TH_ACK) {
        if (tcpd->rev->base_seq == 0) {
            tcpd->rev->base_seq = ack-1;
            tcpd->rev->nextseq = ack;
        } else {
            /*
               The 3-way handshake is not included in the capture. Update rev->base_seq if ack-1 is
               less which prevents packets which ACK segments not present in the capture from being
               labeled "ACK of unseen segment".
            */
            if (LT_SEQ(ack-1, tcpd->rev->base_seq))
                tcpd->rev->base_seq = ack-1;
        }
    }
    if (tcpflags & TH_ACK) 
        tcpd->rev->valid_unacked = TRUE;

    if (tcpflags & TH_RST) {
        tcpd->fwd->ip_id_prev = pinfo->ip_id;
        tcpd->fwd->last_seq = seq;
        tcpd->fwd->lastwindow = window;
        tcpd->fwd->prev_frame = frame;
        return;
    } 
    /*
      S_MSS 
      The largest segment size that the sender is allowed to transmit given the value of the MSS
      option received from its partner minus 12 bytes if timestamps are present. According to RFC
      5681, MSS “does not include the TCP/IP headers and options.” which explains why a maximum of
      1448 bytes are sent although an MSS option of 1460 was received on connections with timestamp
      options. S_MSS is equivalent to the "effective MSS" defined in RFC 1122 4.2.2.6 and "SMSS"
      defined in RFC 5681 Section 2 minus 12 bytes for the timestamp option if present.   
 
      S_MSS is used in this routine to 1) detect FACK retransmissions, 2) calculate bytes in_flight
      during TCP recovery, and to verify the validity of the IP ID which is used among other things 
      to detect out-of-order delivery. 

      S_MSS Estimation
      If neither the SYN nor SYN-ACK packet is included in the capture for a given connection, MSS is
      estimated as follows:

        1. LSO is not used with retransmissions so the max length of retransmissions is a good indicator
           of S_MSS. Set tcpd->fwd->s_mss to the longest retransmission seen in either flow that is
           >= 512 (500 if timestamps).  
        2. If there are NO retransmissions or none greater than or equal to 512 (or 500) and one of
           the common non-jumbo or jumbo MSS sizes is seen in that flow, set tcp->fwd->s_mss to that
           value.
        3. If NO retransmissions or common MSS sizes are seen, set s_mss to the largest transmitted
           segment size that is less than the max jumbo MSS size of 8960 (or 8948). 
        4. If no retransmissions or common sizes are seen, and all the data transmissions are
            greater than 8960 (or 8948) which means that all the outbound transmissions are LSO
            packets, set s_mss to 1460 or 1448 if the timestamp options are seen.

      With no timestamp options, the common MSS sizes are: 1460, 8960, 1360, 1380 
      With timestamp options the common sizes are:         1448, 8948, 1348, 1368

      (XXX: MSS estimation could be enhanced by detecting *if* the receiver ACKs every 2nd full size
            segment and if so, set s_mss to one half the size of the ACK. 
    */
    if((tcpflags & TH_SYN) 
    && tcpd->mss_opt_seen == FALSE) {
        /*
           Per RFC 1122 4.2.2.6, if a SYN packet arrives without an MSS option, MSS MUST be set
           to 536 in that flow.
        */
        tcpd->fwd->s_mss = 536;
        /*
           If s_mss is 0 in the rev flow, set it to 536 for the moment in case the SYN-ACK is
           missing from the capture
        */
        if (tcpd->rev->s_mss == 0) 
            tcpd->rev->s_mss = 536;
        /*
           Prevent MSS from being *estimated* in either flow
        */
        tcpd->mss_opt_seen = TRUE;
    }
    if(tcpd->mss_opt_seen == FALSE
    && tcpd->fwd->max_seglen_rxmt == 0
    && seglen >= (guint32)(500 + tcpd->ts_optlen)) {
        if((tcpd->ts_optlen == 12 && (seglen == 8948 || seglen == 1448 || seglen == 1348 || seglen == 1368)) 
        || (tcpd->ts_optlen == 0  && (seglen == 8960 || seglen == 1460 || seglen == 1360 || seglen == 1380))) {
            tcpd->fwd->s_mss = seglen;
        } else if (seglen < (guint32)(8960 - tcpd->ts_optlen)) {
            if (seglen > tcpd->fwd->s_mss) 
                tcpd->fwd->s_mss = seglen;
        } else {
            tcpd->fwd->s_mss = 1460 - tcpd->ts_optlen;
        }
    }

    if (tcpflags & (TH_SYN|TH_FIN))
        goto finished_checking_retransmission_type;

    /*
      The IP ID can be very useful for the detection of out-of order frames. It is also useful for
      determining whether a segment is a retransmission or instead the ACK-only packet that makes this
      segment appear to be a retransmission was delivered out-of-order. In some networks such as those
      with Juniper routers, ACKs are not given the same priority as data-carrying segments and in such
      cases Wireshark usually reports an enormous number of retransmissions when in reality there were
      few or none.  
    *
      The IP ID number space can change for a number of reasons including the presence of proxy or
      intrusion detection device in the network path. The number space typically changes with TOE
      devices when control of the connection reverts to the OS long enough for the OS to retransmit a
      segment. The IP ID is validated by checking if it differs from from the highest ID seen on that
      flow by more than 5000. If so, it is invalidated as an indicator of network reordering for that
      flow until the gap between subsequent IP_ID values falls within this limit. The choice of 5000
      is arbitrary and a TCP preference could be added to make it configurable. 
    */
    if(GT_ID(pinfo->ip_id, tcpd->fwd->ip_id_highest, 5000)
    || LT_ID(pinfo->ip_id, tcpd->fwd->ip_id_highest, 5000)) {
        tcpd->fwd->ip_id_valid = TRUE;
        /* ip_id_highest will be set to this ip_id later on */
    } else {
        tcpd->fwd->ip_id_valid = FALSE;
        tcpd->fwd->ip_id_highest = pinfo->ip_id;        
    } 

    /**************************************** PROCESS THE ACK *****************************************    
      
      TCP_ACK_OF_UNSEEN_SEGMENT
    *
      If this ACK exceeds the highest nextseq seen in the rev flow, one or more packets are missing.
      Add an entry to the *rev* flow's prev seg unseen list (prev_seg_miss_l).
    */
    if (GT_SEQ(ack, tcpd->rev->nextseq)) {       
        /*
           Check for a drastic change in the ACK number space 
        */
        if((GT_SEQ(ack, tcpd->rev->nextseq) && ack - tcpd->rev->nextseq > 1000000)
        || (GT_SEQ(tcpd->rev->nextseq, ack) && tcpd->rev->nextseq - ack > 1000000)) {
            number_space_alert(seq, ack, pinfo, tcpd);
            if (!tcpd->ta_send)
                tcp_analyze_get_ta_send_struct(frame, TRUE, tcpd);
            tcpd->ta_send->flags |= TCP_SEQ_NUMBER_SPACE_ALERT;
            goto finished_checking_retransmission_type;
        }       
        if (!tcpd->ta_recv)
            tcp_analyze_get_ta_recv_struct(frame, TRUE, tcpd);
        tcpd->ta_recv->flags |= TCP_ACK_OF_UNSEEN_SEGMENT;
        num_ack_of_unseen++;
        tcpd->ta_recv->unacked_in_rev = 0;
        /*
          Add a psu for this segment to the prev_seg_miss_l list in the *rev* flow.
        */
        TCP_PREV_SEGMENT_UNSEEN_NEW(psu);
        psu->frame = frame;
        psu->trigger = PSU_BASED_ON_ACK;
        if (seglen == 0) {
            /* If this packet has SACK blocks, ack_only_no_sack will get changed to FALSE */
            psu->ack_only_no_sack = TRUE;
        } else {
            psu->ack_only_no_sack = FALSE;
        }
        psu->lbound = tcpd->rev->nextseq;
        psu->ubound = ack;
        psu->seq = seq;
        psu->ack = ack; 
        psu->nextseq = 0;
        psu->ip_id = (tcpd->fwd->ip_id_valid ? pinfo->ip_id : 0);
        psu->ip_id_high_rev = (tcpd->rev->ip_id_valid ? tcpd->rev->ip_id_highest : 0);
        psu->ts = pinfo->fd->abs_ts;
        psu->unacked = 0;  
        
        if (tcpd->rev->prev_seg_miss_l) {
            psu->next = tcpd->rev->prev_seg_miss_l;
        } else {
            psu->next = NULL;
        }
        tcpd->rev->prev_seg_miss_l = psu;
        /*
          Set rev flow's nextseq to this ACK so that we won't get this indication again in this flow
          for the same ACK and segments in the rev flow less than this ACK will be labeled as 
          retransmissions or out-of-order.
        */
        tcpd->rev->nextseq = ack;
    }

    if (GT_SEQ(ack, tcpd->fwd->prior_highest_ack)) { 
        /*
          Remove or truncate all the SACK block entries in sackb_l (the active SACK block list) that fall
          below this ACK.
        */
        if (tcpd->fwd->sackb_l) { 
            sackb = tcpd->fwd->sackb_l;
            while (sackb) {
                if (LE_SEQ(ack, sackb->seq)) {
                    prev_sackb = sackb;
                    sackb = sackb->next;
                } else {
                    if (GE_SEQ(ack, sackb->nextseq)) {            
                        /*
                          Remove the entire block
                        */
                        tcpd->fwd->totalsacked -= (sackb->nextseq - sackb->seq);
                        tmp_sackb = sackb->next;
                        if (!prev_sackb) {
                            tcpd->fwd->sackb_l = tmp_sackb;
                        } else {
                            prev_sackb->next = tmp_sackb;
                        }
                        TCP_SACKED_FREE(sackb);
                        tcpd->fwd->num_ssackb--;
                        sackb = tmp_sackb;
                    } else {
                        /*
                           The ACK falls somewhere within the range of this SACK block which may   
                           indicate that the receiver has reneged (thrown away previously SACKed
                           data) which should rarely happen. Truncate this block.
                        */
                        sackb->nextseq = ack;
                        prev_sackb = sackb;
                        sackb = sackb->next;
                    }
                }
            }   
        }
    }

    if (seglen == 0) {
        /*
          Since this is an ACK-only packet, calculate the unACKed bytes remaining in the *reverse* flow
          for display in this packet's ACK subtree. This info can be useful for determining the 
          sender's high and low watermarks. In addition, when the capture is taken on the sender and 
          it has TSO/LSO enabled, this can provide a clue as to the size of the segments sent by the NIC. 
        */
        unacked = tcpd->rev->nextseq - tcpd->fwd->highest_ack - tcpd->fwd->totalsacked;
        if (unacked > 0) {
            if (!tcpd->ta_recv)
                tcp_analyze_get_ta_recv_struct(frame, TRUE, tcpd);
            tcpd->ta_recv->unacked_in_rev = unacked;
        }      
 
        if(window == 0
        && window == tcpd->fwd->lastwindow
        && (tcpd->rev->lastsegmentflags & TCP_ZERO_WINDOW_PROBE
        && seq == tcpd->fwd->nextseq
        && ack == tcpd->fwd->highest_ack)) {
           /*
              TCP_ACK_OF_ZERO_WINDOW_PROBE

              This is an ACK of a zero_window_probe if it's an ACK-only packet, the window size and the
              last window size in this flow are zero, the last packet in the rev flow was a zero_window
              probe, seq equals the highest nextseq in this flow, and ack repeats the highest ack in
              the fwd flow.   
            */
            if (!tcpd->ta_recv) 
                tcp_analyze_get_ta_recv_struct(frame, TRUE, tcpd);
            tcpd->ta_recv->flags |= TCP_ACK_OF_ZERO_WINDOW_PROBE;
            tcpd->ta_recv->unacked_in_rev = unacked;
            goto finished_checking_retransmission_type;
        }        

        if(window == tcpd->fwd->lastwindow
        && seq == tcpd->fwd->nextseq
        && ack == tcpd->fwd->highest_ack
        && (tcpd->rev->lastsegmentflags & TCP_KEEP_ALIVE)) {
            /*
              TCP_ACK_OF_KEEP_ALIVE

              This is an ACK of a keep-alive in that it repeats the previous ACK and the last segment
              in the reverse direction was a keep-alive.
            */
            if (!tcpd->ta_recv) 
                tcp_analyze_get_ta_recv_struct(frame, TRUE, tcpd);
            tcpd->ta_recv->flags |= TCP_ACK_OF_KEEP_ALIVE;
            tcpd->ta_recv->unacked_in_rev = 0;
            goto finished_checking_retransmission_type;
        }

        if(ack == tcpd->fwd->highest_ack
        && ack == tcpd->fwd->prior_highest_ack
        && window == tcpd->fwd->lastwindow) {
            
            if (LT_SEQ(ack, tcpd->rev->nextseq)) {
                /*
                  TCP_DUPLICATE_ACK

                  RFC 5681: 
                  "DUPLICATE ACKNOWLEDGMENT: An acknowledgment is considered a duplicate when
                  (a) the receiver of the ACK has unacked data 
                  (b) the incoming acknowledgment carries no data
                  (c) the SYN and FIN bits are both off 
                  (d) the acknowledgment number is equal to the greatest acknowledgment received on the
                      connection (TCP.UNA in [RFC793])
                  (e) the advertised window in the incoming acknowledgment equals the advertised window
                      in the last incoming acknowledgment" 
                */
                is_dupack = TRUE;
                tcpd->fwd->dupacknum++;
                if (tcpd->rev->rec_target)
                    tcpd->fwd->dupacks_in_rec++;
                if (!tcpd->ta_recv)
                    tcp_analyze_get_ta_recv_struct(frame, TRUE, tcpd);
                tcpd->ta_recv->flags |= TCP_DUPLICATE_ACK;
                tcpd->ta_recv->dupack_num = tcpd->fwd->dupacknum;
                tcpd->ta_recv->dup_of_ack_in_frame = tcpd->fwd->lastnondupack_frame;
                tcpd->ta_recv->unacked_in_rev = unacked;
                ///*
                //  If this is the 3rd dup-ack, assume that the rev flow has entered TCP Fast Retransmit.
                //  This prevents the first retransmission in a given recovery event from being labeled
                //  as a generic (non-typed) retransmission in cases were the sender doesn't immediately
                //  retransmit a segment possibly because it has already queued new data to be sent. If 
                //  the rev flow retransmits a segment, rec_target will be set to the highest nextseq up
                //  to that point and frame_rec_entered will be set to the frame number of that rexmit.  
                //*/
                //if(tcpd->fwd->dupacknum >= 3 
                //&& tcpd->rev->rec_target == 0) {
                //    /*
                //       The following will trigger the dupacks_in_rec counter to be set to 1 when this 
                //       ACK is processed so there is no need to do so here. tot_rxmts_this_event is 
                //       set to zero so that the first rexmit will be recognized as such.
                //    */
                //    //tcpd->rev->rec_target = tcpd->rev->nextseq;
                //    tcpd->rev->tot_rxmts_this_event = 0;

                //    /* Don't count those 3 dup_acks so that BIF will be accurate. */
                //    tcpd->fwd->dupacks_in_rec = 0;
                //}

               /*
                  Don't jump to finished_checking_retransmission_type because seq must be checked 
                  for the TCP_ACK_ONLY_OUT_OF_ORDER (type 2 of 2) and TCP_PREV_PACKET_UNSEEN conditions.
               */
            } else {
                /*
                  This is NOT a dup-ack
                */
                tcpd->fwd->dupacks_in_rec = 0;

                if(tcpd->rev->rec_target == 0
                && tcpd->rev->unwarranted_rxmt == FALSE
                && tcpd->fwd->dsack == FALSE) {
                    /*
                       TCP_GRATUITOUS_ACK
                    */
                    if (!tcpd->ta_recv)
                        tcp_analyze_get_ta_recv_struct(frame, TRUE, tcpd);
                    tcpd->ta_recv->flags |= TCP_GRATUITOUS_ACK;
                }
            }
        }       

        if(seq != tcpd->rev->highest_ack - 1
        && ((LT_SEQ(ack, tcpd->fwd->highest_ack) && LE_SEQ(seq, tcpd->fwd->nextseq)) ||
            (LE_SEQ(ack, tcpd->fwd->highest_ack) && LT_SEQ(seq, tcpd->fwd->nextseq)))
        && (tcpd->fwd->ip_id_valid ? LT_ID(pinfo->ip_id, tcpd->fwd->ip_id_highest, 5000) : TRUE)) {
            /*
              TCP_ACK_ONLY_OUT_OF_ORDER (type 1 of 2)
            *
              This ACK-only packet is out-of-order in that it does not ACK a Keep-Alive, the ACK
              is <= the highest ACK seen in this flow, the seq# is <= the highest seq# (nextseq) seen, and
              if the the IP_ID is valid it is less than the highest IP_ID seen in this flow. Don't use the
              IP_ID's validity itself as an out-of-order indicator because the IP_ID's number space may
              have changed due to due to other devices such as proxies in the network path. 
              Remove the TCP_GRATUITOUS_ACK bit in case it is set. 
            */
            if (!tcpd->ta_recv) 
                tcp_analyze_get_ta_recv_struct(frame, TRUE, tcpd);        
            tcpd->ta_recv->flags &= ~(TCP_GRATUITOUS_ACK);
            tcpd->ta_recv->flags |= TCP_ACK_ONLY_OUT_OF_ORDER;
            num_ack_only_ooo++;
            tcpd->ta_recv->unacked_in_rev = 0;
            goto finished_checking_retransmission_type;
        }
    }
    
    if (GT_SEQ(ack, tcpd->fwd->prior_highest_ack)) { 
        if (tcpd->rev->rec_target) {
            /*
               The rev flow is in recovery.  
               
               If there are unACKed retransmissions in the rev flow's ua_rxmts_in_rec_l list,
               remove the entries or portions thereof that this ack covers.
               NOTE: ua_rxmts_in_rec_l is only used to detect RE-retransmissions.
            */
            if (tcpd->rev->ua_rxmts_in_rec_l) { 
                ua_rxmt = tcpd->rev->ua_rxmts_in_rec_l;
          
                while (ua_rxmt) { 
                    if (LE_SEQ(ack, ua_rxmt->seq)) {
                        prev_ua_rxmt = ua_rxmt;
                        ua_rxmt = ua_rxmt->next;
                    } else {                   
                        if (LT_SEQ(ack, ua_rxmt->nextseq)) {            
                            /*
                               This ACK does NOT acknowledge the entire segment.

                               Subtract the number of bytes in the portion of this retransmission that
                               this ACK covers from tcpd->rev->ua_rxmt_bytes_in_rec.
                            */
                            tcpd->rev->ua_rxmt_bytes_in_rec -= (ua_rxmt->nextseq - ack);
                            /*
                               Set ua_rxmt->nextseq to this ACK and continue searching for older segs.
                             */
                            ua_rxmt->nextseq = ack;
                            prev_ua_rxmt = ua_rxmt;
                            ua_rxmt = ua_rxmt->next;
                         } else {
                            /*
                               This ACK acknowledges the entire segment.
                             *
                               Subtract the seglen of this retransmission from tcpd->rev->ua_rxmt_bytes_in_rec.
                             */
                             tcpd->rev->ua_rxmt_bytes_in_rec -= ua_rxmt->seglen;
                             /*
                                Remove this entry from the ua_rxmts_in_rec_l list.
                              */
                            tmp_ua_rxmt = ua_rxmt->next;
                            if (!prev_ua_rxmt) {
                                tcpd->rev->ua_rxmts_in_rec_l = tmp_ua_rxmt;
                            } else {
                                prev_ua_rxmt->next = tmp_ua_rxmt;
                            }
                            TCP_UNACKED_SEG_IN_REC_FREE(ua_rxmt);
                            ua_rxmt = tmp_ua_rxmt;
                        }
                    }
                }   
            }

            /*
               If the rev flow's target recovery seq# (the REV flow's nextseq when it entered recovery)
               has been reached, set the TCP_PARTNER_CAN_EXIT_RECOVERY flag, and store the time spent in
               recovery.
            */
            if (GE_SEQ(ack, tcpd->rev->rec_target)) {  
                /*
                   Don't set the TCP_PARTNER_CAN_EXIT_RECOVERY flag unless the rev flow has retansmitted 
                   a segment. For more info, see commments for rec_target and frame_rec_entered in 
                   packet-tcp.h.
                */
                if (tcpd->rev->frame_rec_entered > 0) {
                    /*
                        TCP_PARTNER_CAN_EXIT_RECOVERY
                     */
                    if (!tcpd->ta_recv) 
                        tcp_analyze_get_ta_recv_struct(frame, TRUE, tcpd);
                    tcpd->ta_recv->flags |= TCP_PARTNER_CAN_EXIT_RECOVERY;
                    tcpd->ta_recv->frame_rec_entered = tcpd->rev->frame_rec_entered;
                    /*
                       Grab the ta_rxmtinfo struct of the frame at which our partner entered recovery
                     */
                    tcp_analyze_get_rxmtinfo_struct(tcpd->ta_recv->frame_rec_entered, FALSE, tcpd);                    
                    if (tcpd->rxmtinfo) {
                        nstime_delta(&tcpd->ta_recv->time_in_rec_dt, 
                            &pinfo->fd->abs_ts, &tcpd->rxmtinfo->first_rxmt_ts);
                        tcpd->rxmtinfo = NULL;
                    } else { 
                        tcpd->ta_recv->time_in_rec_dt.secs = 0;
                        tcpd->ta_recv->time_in_rec_dt.nsecs = 0;
                    }
                    /*
                       If the rev flow transmitted new data before recovery was exited, a subsequent
                       recovery event will be excluded from the Congestion Point Analysis (FCPA)
                       calculations until that sequence number (tcpd->rev->nextseq_upon_exit) is
                       acknowledged. 
                     */
                    tcpd->rev->nextseq_upon_exit = tcpd->rev->nextseq;
                    tcpd->rev->rec_target = 0;
                    tcpd->fwd->snd_fack = 0;
                    tcpd->fwd->partial_ack = FALSE;
                    tcpd->fwd->dupacknum = 0;
                    tcpd->fwd->dupacks_in_rec = 0;
                }
            } else {
                /*
                   The rev flow remains in recovery.
                 *
                   If SACK is *not* supported on this connection, and the last segment was NOT an RTO
                   set the partial ACK flag so that this segment will be labeled "NewReno Retransmission". 
                   NOTE: According to RFC 3782, SACK and NewReno are mutually exclusive. 
                 */
                if(tcpd->sack_supported == FALSE
                && (tcpd->rev->lastsegmentflags & TCP_RTO_RETRANSMISSION) == 0) {
                    tcpd->fwd->partial_ack = TRUE;
                }
            }
        }
    } 

    /************************************* PROCESS THE SEGMENT ****************************************
              
      TCP_PREV_PACKET_UNSEEN

      If seq is greater than the highest nextseq seen thus far in the fwd flow, a previous packet 
      is missing. If the missing segment is eventually seen, the flag on this frame will be changed
      from TCP_PREV_PACKET_UNSEEN to TCP_PREV_PACKET_LOST or TCP_PREV_PACKET_OUT_OF_ORDER.
    */
    if(tcpd->fwd->nextseq > 0
    && seq != tcpd->fwd->firstxmitseq
    && GT_SEQ(seq, tcpd->fwd->nextseq)) {
        guint32 gap_size = seq - tcpd->fwd->nextseq;  

        if (!tcpd->ta_send)
            tcp_analyze_get_ta_send_struct( frame, TRUE, tcpd);
        /*
          Check for a drastic change in the sequence number space of this flow
        */
        if((GT_SEQ(seq, tcpd->fwd->nextseq) && seq - tcpd->fwd->nextseq > 1000000)
        || (GT_SEQ(tcpd->fwd->nextseq, seq) && tcpd->fwd->nextseq - seq > 1000000)) {
            number_space_alert(seq, ack, pinfo, tcpd);
            tcpd->ta_send->flags |= TCP_SEQ_NUMBER_SPACE_ALERT;
            tcpd->fwd->valid_unacked = FALSE;
            goto finished_checking_retransmission_type;
        }
        tcpd->ta_send->flags |= TCP_PREV_PACKET_UNSEEN;
        num_prev_packet_unseen++;
        tcpd->ta_send->gap_size = gap_size;
        tcpd->fwd->valid_unacked = FALSE;
        /*
          Add this segment to the prev_seg_miss_l list in the fwd flow.
        */
        TCP_PREV_SEGMENT_UNSEEN_NEW(psu);
        psu->frame = frame;
        psu->trigger = PSU_BASED_ON_SEQ;
        psu->ack_only_no_sack = FALSE;
        psu->lbound = tcpd->fwd->nextseq;
        psu->ubound = seq;
        psu->seq = 0;  
        psu->ack = ack;
        psu->nextseq = nextseq; 
        psu->ip_id =     (tcpd->fwd->ip_id_valid ? pinfo->ip_id : 0);
        psu->ip_id_high_rev = (tcpd->rev->ip_id_valid ? tcpd->rev->ip_id_highest : 0);
        psu->ts = pinfo->fd->abs_ts;
        psu->unacked = (tcpd->fwd->valid_unacked ? gap_size : 0);

        if (tcpd->fwd->prev_seg_miss_l) {
            psu->next = tcpd->fwd->prev_seg_miss_l;
        } else {
            psu->next = NULL;
        }
        tcpd->fwd->prev_seg_miss_l = psu;
    }
    /*
      If the is_dupack flag is set and this packet carries no data, the checks for other TCP flags can be
      skipped.

      If it *does* carry data and its ACK is the same as that in the prior one, per RFC XXX it was
      not flagged as a dup-ACK above and according to RFC XXX the dup-ACK counter should not be
      incremanted. 
    */
    if((is_dupack || tcpd->fwd->dupacknum > 0)
    && ack == tcpd->fwd->prior_highest_ack
    && window == tcpd->fwd->lastwindow) {
        if (seglen == 0)
            goto finished_checking_retransmission_type;
    } else {
        tcpd->fwd->lastnondupack_frame = frame;
        tcpd->fwd->dupacknum = 0;
    }
    /*
      TCP_KEEP_ALIVE

      A keepalive contains 0 or 1 bytes of data and starts one byte prior to what should be the
      next sequence number.
    */
    if((seglen == 0 || seglen == 1)
    && seq == tcpd->rev->highest_ack - 1) {
        /*
          Since this is a keepalive, remove the gratuitous ACK flag which may or may not be set. \
        */
        if (!tcpd->ta_recv)
            tcp_analyze_get_ta_recv_struct(frame, TRUE, tcpd);
        tcpd->ta_recv->flags &= ~(TCP_GRATUITOUS_ACK);

        /*
          Set the keepalive bit
        */
        if (!tcpd->ta_send)
            tcp_analyze_get_ta_send_struct(frame, TRUE, tcpd);
        tcpd->ta_send->flags |= TCP_KEEP_ALIVE;

        goto finished_checking_retransmission_type;
    }

    /*
      If there was a gap between the ACK in the last out-of-order ACK-only packet and the nextseq of
      the frame it belonged after, the psu for that ACK-only packet was saved in last_ack_only_ooo. If
      this segment falls within that gap, change the ACK-only frame's ta_recv->ooo_belongs_after to
      this packet's frame number.
    */
    if(tcpd->rev->last_ack_only_ooo
    && LE_SEQ(nextseq, tcpd->rev->last_ack_only_ooo->ack)) {
        tcp_analyze_get_ta_recv_struct(tcpd->rev->last_ack_only_ooo->frame, FALSE, tcpd);                                                        
        tcpd->ta_recv->ooo_belongs_after = frame;
        /* Point ta_recv back to this frame's ta_recv if one exists */
        tcpd->ta_recv = NULL;
        /*
           If this segment completes the gap, set last_ack_only_ooo to NULL
        */
        if (nextseq == tcpd->rev->last_ack_only_ooo->ack)
            tcpd->rev->last_ack_only_ooo = NULL;
    }
      
    /* If seq is less than: 
       (1) the highest tcpd->fwd->nextseq, 
       (2) the highest ACK in the rev flow, and 
       (3) the highest SACK block right edge in the rev flow; 
         
       search for the original frame in the ua_segs_l list and if not found, search the
       prev_seg_miss_l list for the frame that follows the gap into which this frame falls;
       then determine if this is a retransmission, a duplicate packet, or was delivered
       out-of-order.  
    */
    if(seglen > 0
    && LT_SEQ(seq, tcpd->fwd->nextseq)) {
        gboolean acked_sacked=FALSE;

        /* Convert ms to ns */
        rto_period = (guint64)tcp_rto_period * 1000000;
        
        if (!tcpd->rxmtinfo)
            tcp_analyze_get_rxmtinfo_struct(frame, TRUE, tcpd);

        tcpd->rxmtinfo->orig_frame = 0; 
        orig_frame_ts.secs = 0;
        orig_frame_ts.nsecs = 0;

        if(tcpd->rev->highest_ack > 0
        && LE_SEQ(nextseq, tcpd->rev->highest_ack)) {        
            /*
              Although this segment has been ACKed, the ua_segment and prev_seg_miss_l lists must 
              still be searched for a matching entry because this frame may have arrived out-of-order
              or been duplicated by the network.
            *
              Note that entries are not purged from either list unless the highest received ACK
              exceeds their left border (seq) by more than one max window size.
            */
            acked_sacked = TRUE;
        }
        /*
           If seq is older than the first seq in the capture, consider this to be a retransmission
           and set orig_frame to 0xffffffff.
        */
        if (LT_SEQ(seq, tcpd->fwd->firstxmitseq)) {
            orig_frame = 0xffffffff;
            tcpd->rxmtinfo->orig_frame = 0xffffffff;
            /*
              See if this segment was delivered out-of-order or was a retransmission
            */
            psu = tcpd->fwd->prev_seg_miss_l;
            
            if (time_from_orig > rto_period) {
                is_rxmt = TRUE;
            
            } else if (psu && psu->trigger == PSU_FIRSTXMITSEQ) {  
                /*
                  A dummy psu entry was created above for the first frame in this flow. It is always
                  the first entry in the prev_seg_miss_l list and psu is that entry. 

                  This frame was delivered out-of-order prior to that packet if the following criteria
                  are met: 
                   o nextseq is less than or equal to the first seq seen in this flow  
                   o If the highest_ack in the rev flow was non-zero when the "dummy" entry for the
                     first frame in this flow was created, nextseq is less than or equal to that ack
                   o If this frame's ip_id is valid, it within 5000 less than psu->ip_id
                */
                if(LE_SEQ(nextseq, tcpd->fwd->firstxmitseq) 
                && (psu->ack > 0 ? LE_SEQ(nextseq, psu->ack) : TRUE)
                && ((tcpd->fwd->ip_id_valid && psu->ip_id > 0 ) ? 
                    LT_ID(pinfo->ip_id, psu->ip_id, 5000) : TRUE))
                {
                    is_ooo = TRUE;
                } else {
                    is_rxmt = TRUE;
                }
            } else {
                is_rxmt = TRUE;
            }
        }
        /*
           Search 'tcpd->fwd->ua_segs_l', the list of unACKed segments, for the frame that 
           contains the originally transmitted segment. Had a psu or SACK frame been received prior
           to the frame that triggered an entry matching this segment, that entry would been 
           flagged as a retransmission or out-of-order and would not have been added to 
           ua_segs_l; consequently, if an entry matching this segment is found in ua_segs_l
           there is no need to check the prev_seg_miss_l and sackb_l lists for a lower numbered
           frame.

           If this is a duplicate segment, flag it as such and store info about the original frame
           in this frame's *ta_send* struct. If instead it is a retransmission, flag it as such,
           store info about it in this frame's *rxmtinfo* struct, and store info about this frame
           in the original frame's *ta_send* struct. 
        */
        for (ua_seg=tcpd->fwd->ua_segs_l; ua_seg && LT_SEQ(seq, ua_seg->nextseq); ua_seg=ua_seg->next) {
            /*
               If seq either falls within this ua_seg entry's range or is less than the highest_ack in the
               rev flow and nextseq falls within this ua_seg's range, we've found a match.
            */
            if((GE_SEQ(seq, ua_seg->seq) && LT_SEQ(seq, ua_seg->nextseq)) || 
                (LT_SEQ(seq, tcpd->rev->highest_ack) 
            && GT_SEQ(nextseq, ua_seg->seq)
            && LE_SEQ(nextseq, ua_seg->nextseq))) {
                orig_frame = ua_seg->frame; 
                /*
                   See if this packet has been duplicated  
                */
                if(ua_seg->ip_id == pinfo->ip_id                   
                && ua_seg->seq == seq
                && ua_seg->nextseq == nextseq
                && ua_seg->ack == ack
                && ua_seg->flags == tcpflags
                && ua_seg->win == window) {
                    /* Grab or create the ta_send struct for *this* frame. */
                    tcp_analyze_get_ta_send_struct(frame, TRUE, tcpd);                    
                    nstime_delta(&tcpd->ta_send->frame_dt, &pinfo->fd->abs_ts, &ua_seg->ts);
                    time_from_orig = (tcpd->ta_send->frame_dt.secs * NANOSECS_PER_SEC) + 
                                        tcpd->ta_send->frame_dt.nsecs;
                    if (time_from_orig < rto_period) {
                        /*
                           TCP_DUPLICATE_FRAME (a duplicated data-carrying frame)
                        */
                        tcpd->ta_send->flags |= TCP_DUPLICATE_FRAME;
                        tcpd->ta_send->orig_frame = ua_seg->frame;
                        tcpd->ta_send->this_frame = frame;
                        return;
                    }
                }
                /*
                   This is a retransmission
                */
                is_rxmt = TRUE;
                tcpd->rxmtinfo->orig_frame = ua_seg->frame;
                orig_frame_ts = ua_seg->ts;
                nstime_delta(&tcpd->rxmtinfo->orig_frame_dt, &pinfo->fd->abs_ts,
                                &orig_frame_ts);
                time_from_orig = (tcpd->rxmtinfo->orig_frame_dt.secs * NANOSECS_PER_SEC) + 
                    tcpd->rxmtinfo->orig_frame_dt.nsecs;
            
                if (acked_sacked) {
                    /*
                       TCP_UNWARRANTED_RETRANSMISSION
                    */
                    tcpd->fwd->unwarranted_rxmt = TRUE;
                    if (!tcpd->rxmtinfo) 
                        tcp_analyze_get_rxmtinfo_struct(frame, TRUE, tcpd);    
                    tcpd->rxmtinfo->flags |= TCP_UNWARRANTED_RETRANSMISSION;
                    if (tcpd->fwd->rec_target > 0)
                        tcpd->rxmtinfo->frame_rec_entered = tcpd->fwd->frame_rec_entered;
                    goto finished_checking_retransmission_type;

                } else {               
                    /*
                       If the following are true, this frame the first frame that was lost in a given TCP
                       Recovery event:

                         o  The first retransmission of the recovery event
                         o  No unacked bytes remain from the previous recovery event
                         o  The 'nextseq_upon_exit' of the previous recovery event, if any, has been ACKed
                            NOTE: If data was transmitted during the previous recovery event, 'nextseq_upon_exit'
                            does not equal the "Target recovery seq#" 

                       Store the number of bytes that were unACKed when the original frame was transmitted.

                       That value is the seq# of this retransmission minus the highest ACK number prior to
                       the transmission of the lost frame. This calculation is accurate regardless of whether
                       or not the lost packed was an LSO segment.   

                       Note: The number of unacked bytes of the original frame of subsequent retransmissions
                       within the same event are meaningless for Fixed Congestion Point Analysis (FCPA).
                    */
                    if(tcpd->fwd->rec_target==0
                    && tcp_track_unacked_and_bif
                    && orig_frame > 0
                    && orig_frame != 0xffffffff
                    && (tcpd->fwd->num_first_rxmts ? ack >= tcpd->fwd->nextseq_upon_exit : TRUE)) {
                        guint i;
                        guint num_prev_frames = pinfo->fd->num - orig_frame; 
                        frame_data  *fd_orig = pinfo->fd;
                        tcp_per_packet_data_t  *tcppd_orig = NULL; 
                        
                        /* Search backwards for the frame data of the original frame */
                        for (i=num_prev_frames; i > 0; i--) 
                            fd_orig = fd_orig->prev;

                        if (fd_orig)
                            tcppd_orig = (tcp_per_packet_data_t *)p_get_proto_data(fd_orig, proto_tcp);
                        
                        if (tcppd_orig)
                            tcpd->rxmtinfo->unacked_of_orig = seq - tcppd_orig->highest_ack_rev;
                    }
                    /*
                       TCP_PACKET_LOST
                    */
                    /* Grab or create the ta_send struct of the *original* frame, set TCP_PACKET_LOST,
                       bump the number of packets lost counter, and store the frame number of this 
                       retransmission. */
                    tcp_analyze_get_ta_send_struct(orig_frame, TRUE, tcpd);
                    if (tcpd->ta_send) { 
                        tcpd->ta_send->flags |= TCP_PACKET_LOST;
                        num_packet_lost++;
                        tcpd->ta_send->rxmt_at_frame = frame;
                    }
                    /* Set the pointer back to the ta_send of the current frame. */
                    tcp_analyze_get_ta_send_struct(frame, FALSE, tcpd);
                }
            }
        } /* End of the 'for' loop search of ua_segs_l */

        if(orig_frame == 0
        && tcpd->fwd->prev_seg_miss_l) {         
            /*
               The original segment was not found in the ua_segs_l list so search for the original
               segment in the 'tcpd->fwd->prev_seg_miss_l' which consists of entries that were added
               based on:
                 o A gap between tcpd->fwd->nextseq and seq (PSU_BASED_ON_SEQ), 
                 o A gap between tcpd->rev->nextseq and ack (PSU_BASED_ON_ACK), 
                 o One or more gaps defined by a frame with SACK blocks (PSU_BASED_ON_SACK). Entries of
                   this type define the gap as the ACK to the highest sackb.sre. For these entries the
                   tcpd->rev->sackb_l list, the list of currently active (unACKed) SACK blocks is used to 
                   determine if this frame is a retransmission or was delivered out-of-order.
             *
               In order to make the fixed congestion point statistic more accurate in cases where the
               sender chooses to transmit a segment that spans multiple gaps, look for the psu with the
               lowest gap within which seq, a portion of the segment, or nextseq falls; in that order.
               NOTE: prev_seg_miss_l is in descending order.
             *
               Find the lowest gap if any into which seq falls
            */
            psu = NULL;
            tmp_psu = tcpd->fwd->prev_seg_miss_l;
            while (tmp_psu) {
                if(GE_SEQ(seq, tmp_psu->lbound)
                && LE_SEQ(seq, tmp_psu->ubound))
                    psu = tmp_psu;
                tmp_psu = tmp_psu->next; 
            }
            if (!psu) {
                /*
                  Find the lowest gap if any into which a portion of this segment falls
                */
                tmp_psu = tcpd->fwd->prev_seg_miss_l;
                while (tmp_psu) {
                    if(LT_SEQ(seq, tmp_psu->lbound)
                    && GT_SEQ(nextseq, tmp_psu->ubound)) 
                        psu = tmp_psu;            
                    tmp_psu = tmp_psu->next; 
                }
            }
            if (!psu) {
                /*
                  Find the lowest gap if any into which nextseq falls
                */
                tmp_psu = tcpd->fwd->prev_seg_miss_l;
                while (tmp_psu) {
                    /*
                      Does nextseq fall within this gap?
                    */
                    if(GT_SEQ(nextseq, tmp_psu->lbound)
                    && LE_SEQ(nextseq, tmp_psu->ubound)) 
                        psu = tmp_psu;            
                    tmp_psu = tmp_psu->next; 
                }
            }   
        }

        if (psu) {
            nstime_delta(&tmp_dt, &pinfo->fd->abs_ts, &psu->ts);               
            time_from_orig = (tmp_dt.secs * NANOSECS_PER_SEC) +
                              tmp_dt.nsecs;               
            if (psu->trigger == PSU_BASED_ON_ACK) { 
                /*
                  Grab the psu frame's saved_sackb_l list if any
                */
                tcp_analyze_get_saved_sackl_struct(psu->frame, FALSE, 0, tcpd);                
                /*
                  This psu packet ACKed an unseen segment. Check if the psu frame or this frame was
                  delivered out-of-order.

                  Label the psu packet as out-of-order if the following criteria are met:
                  o  The RTO period has not been exceeded
                  o  It is an ACK-only packet that does not include any SACK blocks
                  o  seq falls within this psu's gap, and the *psu's* seq is within one max window size greater
                     than the highest nextseq seen in the rev flow
                  o  The psu's ip_id is greater than or equal to the highest ip_id seen in the rev flow.

                     NOTE: If the psu packet was the last packet seen in the rev flow, its ip_id_highest will
                     be equal to its ip_id and that is why GE_ID is used instead of GT_ID.
                */
                if(time_from_orig < rto_period
                && psu->ack_only_no_sack 
                && GE_SEQ(seq, psu->lbound)
                && GE_SEQ(psu->seq, tcpd->rev->nextseq) 
                && (psu->seq - tcpd->rev->nextseq) < tcpd->fwd->max_size_window                    
                && GE_ID(psu->ip_id, tcpd->rev->ip_id_highest, 5000)) {
                    /*
                      TCP_ACK_ONLY_OUT_OF_ORDER (type 2 of 2)
                      
                      Grab ta_recv struct of the frame flagged as TCP_ACK_OF_UNSEEN_SEGMENT
                      and change it to TCP_ACK_ONLY_OUT_OF_ORDER
                    */
                    tcp_analyze_get_ta_recv_struct(psu->frame, FALSE, tcpd);                                                        
                        
                    if (tcpd->ta_recv) {
                        tcpd->ta_recv->flags &= ~(TCP_ACK_OF_UNSEEN_SEGMENT);
                        num_ack_of_unseen--;
                        tcpd->ta_recv->flags |= TCP_ACK_ONLY_OUT_OF_ORDER;
                        num_ack_only_ooo++;
                        tcpd->ta_recv->ooo_belongs_after = frame;          
                        nstime_delta(&tcpd->ta_recv->ooo_ack_dt, &pinfo->fd->abs_ts, &psu->ts);
                        tcpd->ta_recv->unacked_in_rev = 0;
                    }
                    tcpd->ta_recv = NULL;
                    /*
                      If there is a gap between nextseq and psu->ubound (=ACK), change ubound to       
                      *this* frame's nextseq in order to prevent subsequent frames in this flow with
                      segments that fall within that gap from being incorrectly labeled as
                      out-of-order.
                    */
                    if (GT_SEQ(psu->ubound, nextseq)) {
                        psu->ubound = nextseq;
                        tcpd->fwd->nextseq = nextseq;
                        tcpd->rev->last_ack_only_ooo = psu;
                    } else {
                        tcpd->rev->last_ack_only_ooo = NULL;
                    }
                    goto finished_checking_retransmission_type;
                } 
            } 
            orig_frame = psu->frame;
            tcpd->rxmtinfo->orig_frame = orig_frame;
            tcpd->rxmtinfo->orig_frame_dt = tmp_dt;
            tcp_analyze_get_ta_send_struct(frame, TRUE, tcpd);

            if (time_from_orig < rto_period) {
                switch (psu->trigger) {
                case PSU_BASED_ON_SEQ:
                    /*
                      This frame was delivered out-of-order prior to the psu frame if the following
                      criteria are met: 
                        o seq and nextseq fall within this psu's gap
                        o ack is less than or equal to the ack in the psu packet (psu->ack)
                        o ip_id is within 5000 less than psu->ip_id
                          NOTE: psu->ip_id was set to the highest ip_id seen in the fwd flow when that 
                                packet was processed.
                    */
                    if(GE_SEQ(seq, psu->lbound) 
                    && LE_SEQ(seq, psu->ubound)
                    && LE_SEQ(nextseq, psu->ubound) 
                    && LE_SEQ(ack, psu->ack) 
                    && ((tcpd->fwd->ip_id_valid && psu->ip_id > 0 ) ? 
                        LT_ID(pinfo->ip_id, psu->ip_id, 5000) : TRUE))
                    {
                        is_ooo = TRUE;
                    }
                    break;
                case PSU_BASED_ON_ACK:
                    /*
                      This frame was delivered out-of-order prior to this psu frame if the following
                      criteria are met: 
                        o seq and nextseq fall within this psu's gap (NOTE: lbound was set
                          to tcpd->rev->nextseq and ubound was set to the ack) 
                        o ack is equal to or within one max window size less than the psu frame's seq 
                        o ip_id is within 5000 greater than psu->ip_id  
                    */
                    if(GE_SEQ(seq, psu->lbound) 
                    && LE_SEQ(nextseq, psu->ubound)
                    && LE_SEQ(ack, psu->seq) 
                    && (psu->seq - ack) < tcpd->rev->max_size_window 
                    && ((tcpd->fwd->ip_id_valid && psu->ip_id_high_rev > 0) ? 
                        GT_ID(pinfo->ip_id, psu->ip_id_high_rev, 5000) : TRUE)) 
                    {   
                        is_ooo = TRUE;
                    }
                    break;
                case PSU_BASED_ON_SACK:
                    /*
                      If this segment falls entirely within a sackb and it was not seen when that sackb
                      was processed, test to see if this segment was actually sent prior to the sackb 
                      frame but arrived out-of-order.  
                    */
                    if (tcpd->rev->sackb_l) {
                        is_rxmt = TRUE;
                        sackb = tcpd->rev->sackb_l;
                        /*
                          If this segment was not seen prior to the sackb frame's arrival, fully falls
                          within this sackb, and, if the highest ip_id seen in the flow was valid when
                          that psu was processed and this frame's ip_id is greater that that value,
                          mark this frame as out-of-order. 
                        */
                        while(sackb && LT_SEQ(seq, sackb->nextseq)) {
                            if(sackb->sack_of_unseen
                            && GE_SEQ(seq, sackb->seq)
                            && LE_SEQ(nextseq, sackb->nextseq)
                            && ((tcpd->fwd->ip_id_valid && psu->ip_id_high_rev > 0)  ?
                                 GT_ID(pinfo->ip_id, psu->ip_id_high_rev, 5000) : TRUE))
                            { 
                                is_ooo = TRUE;
                                break;            
                            } 
                            sackb = sackb->next;
                        }
                    }
                    break;
                }
            }
            if (is_ooo) {
                /*
                  TCP_OUT_OF_ORDER 
                */
                tcpd->ta_send->flags |= TCP_OUT_OF_ORDER;
                num_ooo_segs++;
                tcpd->ta_send->orig_frame = orig_frame;
                is_rxmt = FALSE;
                tcpd->fwd->valid_unacked = FALSE;

                if (psu->trigger == PSU_BASED_ON_SEQ) {
                    /*
                      TCP_PREV_PACKET_OUT_OF_ORDER
                      
                      Grab the ta_send struct of the frame flagged as TCP_PREV_PACKET_UNSEEN
                      and change it to TCP_PREV_PACKET_OUT_OF_ORDER. Store info about this 
                      frame in the prev_seg_ooo frame's ta_send.
                     */
                    tcp_analyze_get_ta_send_struct(orig_frame, FALSE, tcpd);
                    if (tcpd->ta_send) { 
                        tcpd->ta_send->flags &= ~(TCP_PREV_PACKET_UNSEEN);
                        num_prev_packet_unseen--;
                        tcpd->ta_send->flags |= TCP_PREV_PACKET_OUT_OF_ORDER;
                        num_prev_packet_ooo++;
                        tcpd->ta_send->orig_frame = frame;
                        tcpd->ta_send->this_frame = frame;
                    }
                    tcpd->ta_send = NULL;
                    tcpd->fwd->valid_unacked = FALSE;
                } else {
                    /*
                      TCP_ACK_OF_OUT_OF_ORDER_SEGMENT
                      
                      Grab the ta_recv struct of the frame flagged as TCP_ACK_OF_UNSEEN_SEGMENT
                      and change it to TCP_ACK_OF_OUT_OF_ORDER_SEGMENT.
                    */
                    tcp_analyze_get_ta_recv_struct(orig_frame, FALSE, tcpd);
                    if (tcpd->ta_recv) { 
                        tcpd->ta_recv->flags &= ~(TCP_ACK_OF_UNSEEN_SEGMENT);
                        num_ack_of_unseen--;
                        tcpd->ta_recv->flags |= TCP_ACK_OF_OUT_OF_ORDER_SEGMENT;
                        num_ack_of_ooo_seg++;
                        tcpd->ta_recv->frame_acked = frame;
                        tcpd->ta_recv->unacked_in_rev = 0;
                    }
                    tcpd->ta_recv = NULL;
                }
            } else {
                /*
                  Treat this as a retransmission. 
                */
                is_rxmt = TRUE;
                tcpd->ta_send->seg_falls_in_gap = TRUE;

                if (acked_sacked) {
                    if (psu->trigger == PSU_BASED_ON_ACK) {
                        /*
                           The ACK appears to have been lost. Set a flag to inform the user of this
                           possibility.
                        */
                        tcp_analyze_get_ta_recv_struct(frame, TRUE, tcpd);
                        tcpd->rxmtinfo->ack_lost = TRUE;
                    } 
                    if (time_from_orig < rto_period) {
                        /*
                          TCP_UNWARRANTED_RETRANSMISSION
                        */
                        tcpd->fwd->unwarranted_rxmt = TRUE;
                        if (!tcpd->rxmtinfo) 
                            tcp_analyze_get_rxmtinfo_struct(frame, TRUE, tcpd);    
                        tcpd->rxmtinfo->flags |= TCP_UNWARRANTED_RETRANSMISSION;
                        if (tcpd->fwd->rec_target > 0)
                            tcpd->rxmtinfo->frame_rec_entered = tcpd->fwd->frame_rec_entered; 
                    }
                } else {
                    /*
                      TCP_PREV_PACKET_LOST
                    *
                      Grab the ta_send struct of the frame flagged as TCP_PREV_PACKET_UNSEEN
                      and change it to TCP_PREV_PACKET_LOST.
                    */
                    tcp_analyze_get_ta_send_struct(orig_frame, FALSE, tcpd);
                    if (tcpd->ta_send) {
                        if (psu->trigger == PSU_BASED_ON_SEQ) {
                            tcpd->ta_send->flags &= ~(TCP_PREV_PACKET_UNSEEN);
                            num_prev_packet_unseen--;
                            tcpd->ta_send->flags |= TCP_PREV_PACKET_LOST;
                            num_prev_packet_lost++;
                            tcpd->ta_send->rxmt_at_frame = frame;
                            tcpd->ta_send->this_frame = frame;
                            tcpd->ta_send = NULL;
                            tcpd->fwd->valid_unacked = FALSE;
                        }
                    } 
                }
            }
        }

        if(orig_frame == 0) {
            if (acked_sacked) {
                /*
                  TCP_UNWARRANTED_RETRANSMISSION
                */
                tcpd->fwd->unwarranted_rxmt = TRUE;
                if (!tcpd->rxmtinfo) 
                    tcp_analyze_get_rxmtinfo_struct(frame, TRUE, tcpd);    
                tcpd->rxmtinfo->flags |= TCP_UNWARRANTED_RETRANSMISSION;
                if (tcpd->fwd->rec_target > 0)
                    tcpd->rxmtinfo->frame_rec_entered = tcpd->fwd->frame_rec_entered;
            } else {
                tcpd->rxmtinfo->flags |= TCP_RETRANSMISSION;
                    REPORT_DISSECTOR_BUG(
                        "tcp_analyze_sequence_number(): The original frame could not be determined.");
            }
        }
    } else {
        /*
          This is a new data segment. If this flow is in recovery, flag it as 'new_data_sent_in_rec.'
        */
        if (tcpd->fwd->rec_target > 0) {
            /*
              TCP_NEW_DATA_SENT_IN_REC
            */
            tcp_analyze_get_ta_send_struct(frame, TRUE, tcpd);
            tcpd->ta_send->new_data_sent_in_rec = seglen;
        }
    }
        
    /************************************* PROCESS WINDOW INFO ****************************************
      
      TCP_WINDOW_UPDATE
 
      A window update is a zero size segment with the same SEQ and ACK numbers as the previous segment
      in this flow and a new window size value.
    */
    if(seglen == 0
    && window != tcpd->fwd->lastwindow
    && seq == tcpd->fwd->nextseq
    && ack == tcpd->fwd->prior_highest_ack) {
        if (!tcpd->ta_recv)
            tcp_analyze_get_ta_recv_struct(frame, TRUE, tcpd);
        tcpd->ta_recv->flags |= TCP_WINDOW_UPDATE;
    }

    unacked = nextseq - tcpd->rev->highest_ack - tcpd->rev->totalsacked;
    /*
      TCP_WINDOW_FULL and TCP_WINDOW_EXCEEDED

      o  If tcpd->wsf_announced is TRUE (i.e., the window scale factor (WSF) is present in both the
         SYN and SYN-ACK packets and the scale values have not been truncated,
      o  This segment contains new data (nextseq has increased),
      o  'valid_unacked' is TRUE, and
      o  The number of unACKed/SACKed bytes (unacked) is >= the most recent window size advertized in
         the rev flow;
      Signal a one of these conditions. 
    */
    if(tcpd->wsf_announced
    && tcpd->fwd->valid_unacked
    && GT_SEQ(nextseq, tcpd->fwd->nextseq)) {
        /*
          TCP_WINDOW_FULL
        */
        if (unacked == tcpd->rev->lastwindow) {
            if (!tcpd->ta_recv)
                tcp_analyze_get_ta_recv_struct(frame, TRUE, tcpd);           
            tcpd->ta_recv->flags |= TCP_WINDOW_FULL;

        } else if (unacked > tcpd->rev->lastwindow) {
            tcp_analyze_get_ta_recv_struct(frame, FALSE, tcpd);
            if(tcpd->ta_recv == NULL
            || (tcpd->ta_recv && (tcpd->ta_recv->flags & TCP_ACK_OF_UNSEEN_SEGMENT) == 0)) {
                /*
                  TCP_WINDOW_EXCEEDED

                  This condition is rare and can be caused by a flaw in the rev flow's TCP
                  implementation or that of a TCP proxy device. False positives can occur if the
                  capture was taken on the sender's side and one or more of the receiver's ACKs were
                  lost. For this reason the phrase "*may* have exceeded" is displayed in the tree.  
                */
                if (!tcpd->ta_send)
                    tcp_analyze_get_ta_send_struct(frame, TRUE, tcpd);
                tcpd->ta_send->flags |= TCP_WINDOW_EXCEEDED;
                tcpd->ta_send->lastwindow_from_rev = tcpd->rev->lastwindow;
            }
        }
    }
    /*
      TCP_ZERO_WINDOW
    */
    if (window == 0) {
        if (!tcpd->ta_recv) 
            tcp_analyze_get_ta_recv_struct(frame, TRUE, tcpd);
        tcpd->ta_recv->flags |= TCP_ZERO_WINDOW;
    }
    /*
      TCP_ZERO_WINDOW_PROBE
    *
      This is a zero window probe if the sequence number is the next expected one, the window in the
      rev flow is zero, and the seglen is exactly 1 byte.
    */
    if(seglen == 1
    && seq == tcpd->fwd->nextseq
    && tcpd->rev->lastwindow == 0) {
        if (!tcpd->ta_send)
            tcp_analyze_get_ta_send_struct(frame, TRUE, tcpd);
        tcpd->ta_send->flags |= TCP_ZERO_WINDOW_PROBE;
    }

    if(is_rxmt
    && !tcpd->fwd->unwarranted_rxmt
    && orig_frame > 0) {
        /*
          MSS Estimation
          If a SYN has not been seen in this connection, MSS is set to the largest retransmission
          that is greater than 500 or 512 because LSO is not used with retransmissions.*/
        if (tcpd->mss_opt_seen == FALSE) {
            if (seglen > tcpd->fwd->max_seglen_rxmt) 
                tcpd->fwd->max_seglen_rxmt = seglen;        
            if(seglen > 500 + (guint32)tcpd->ts_optlen
            && seglen > tcpd->fwd->max_seglen_rxmt) 
                tcpd->fwd->s_mss = seglen;
        }
        /*
        Determine the retransmission type (i.e., what triggered it)

        There are several Loss Recovery algorithms that define ways that retransmissions are 
        triggered and how the sender and receiver should behave when the receiver holds noncontiguous
        data. Wireshark can reliably:
        (1) Determine what triggered the retransmission provided that unseen frames don't preclude it,
            and label it accordingly
        (2) Indicate the type of retransmissions sent during Recovery 
        (3) indicate when the sender is able to exit recovery. The term "recovery" is defined as the
        point in time when the sender first detects that the receiver holds noncontiguous data. The
        sender can exit recovery when the receiver has acknowledged all the data that was outstanding
        when recovery was entered which we'll refer to as the "recovery target" sequence number. 

        Retransmissions can be triggered in the following ways:
        1. RTO: (RFC 793) Expiry of the senders retransmission timer   
                Label: [TCP RTO Retransmission] 
        2. Reno: (RFC 5681) 3 duplicate ACKs
                Label: [TCP Fast Retransmission] 
        3. FACK+SACK: (Mathis SIGCOMM’96 and RFC 2018) The ACK and the highest 
                SACKed seq# are more than 3*MSS apart
                Labels: [TCP FACK Retransmission] for the first retransmission 
                        [TCP SACK Retransmission] for subsequent retransmissions during recovery.
        4. Reno+SACK (RFCs 5681 and 2018) 3 duplicate ACKs with SACK ranges
                Labels: [TCP Fast Retransmission] for the first retransmission 
                        [TCP SACK Retransmission] for subsequent retransmissions during recovery
        5. NewReno: (RFC 2582 and RFC 3782) 3 duplicate ACKs and one or more partial 
                acknowledgements following retransmissions. NOTE: SACK and NewReno are mutually
                exclusive.  If either partner does not support SACK neither can use it. When SACK 
                is not supported on the connection, RTOs can be avoided by NewReno where the sender
                retransmits segments in response to partial acknowledgments. Either partner can 
                employ NewReno without the knowledge or consent of the other.  
                Labels: [TCP Fast Retransmission] for the first retransmission in recovery 
                        [TCP NewReno Retransmission] for subsequent retransmissions sent before  
                        recovery is exited
       
        If none of the above criteria is met and the segment is not dupicated, it is simply designated 
        as a "Retransmision".
                Label: [TCP Retransmission].
        Recovery is exited when an ACK arrives that acknowledges all of the data that was outstanding
        at the time when recovery was entered. The following label is displayed in the ACK packet:
                Label: [Partner can exit recovery] 
                
        Clearly defining recovery events allows for congestion point analysis to be performed. See
        "Fixed Congestion Point Analysis" in packet-tcp.h for a description.
        */
        if (time_from_orig >= rto_period) {
            /*
               TCP_RTO_RETRANSMISSION
            */
            tcpd->rxmtinfo->flags |= TCP_RTO_RETRANSMISSION;
            if(tcpd->fwd->rec_target == 0) {
                tcpd->fwd->rec_target = tcpd->fwd->nextseq;
                tcpd->fwd->frame_rec_entered = frame;
                tcpd->rxmtinfo->rec_target = tcpd->fwd->nextseq;
                tcpd->rxmtinfo->frame_rec_entered = frame;            
                tcpd->rxmtinfo->is_first_rxmt = TRUE;
                tcpd->rxmtinfo->first_rxmt_ts = pinfo->fd->abs_ts;
            } else {
                tcpd->rxmtinfo->rec_target = tcpd->fwd->rec_target;
                tcpd->rxmtinfo->frame_rec_entered = tcpd->fwd->frame_rec_entered;            
                tcpd->rxmtinfo->is_first_rxmt = FALSE;
            }
            goto finished_checking_retransmission_type; 
        }

        if (tcpd->rev->snd_fack) {
            /* snd_fack is set in dissect_tcpopt_sack and is always non-relative. */
            snd_fack = tcpd->rev->snd_fack;  
        }
        /*
          If this flow is not already in recovery label this frame as FACK or Fast retransmission; otherwise,
          it will be labeled as a SACK/NewReno rexmit, TCP_OUT_OF_ORDER, or a generic (non-typed) rexmit.
        */
        if(tcpd->fwd->rec_target == 0) {
            /*
              TCP_FACK_RETRANSMISSION

              snd.fack: The forward-most data held by the receiver plus one. If the highest SACKed
              seq# minus the ACK is greater 3*MSS (i.e. if ((snd.fack - snd.una) > (3 * MSS) ) and 
              the original frame was sent less than 100ms ago, label it as a FACK retransmission. 
              NOTE: Don't impose the seglen == 0 requirement because it's perfectly legal to transmit
              data with SACK options. 
            */
            if(tcpd->rev->sackb_l
            && GT_SEQ(snd_fack, tcpd->rev->highest_ack)
            && (snd_fack - tcpd->rev->highest_ack) > (3 * (guint32) tcpd->fwd->s_mss)) {

                tcpd->rxmtinfo->flags |= TCP_FACK_RETRANSMISSION;
                tcpd->fwd->rec_target = tcpd->fwd->nextseq;
                tcpd->rxmtinfo->rec_target = tcpd->fwd->nextseq;
                tcpd->fwd->frame_rec_entered = frame;
                tcpd->rxmtinfo->frame_rec_entered = frame;
                tcpd->rxmtinfo->is_first_rxmt = TRUE;
                tcpd->rxmtinfo->first_rxmt_ts = pinfo->fd->abs_ts;
                /*
                   In order for bytes_in flight to be accurate during recovery, the duplicate ACK 
                   counter must be set/reset to zero upon entering recovery.
                */
                tcpd->rev->dupacknum = 0;
                goto finished_checking_retransmission_type;
            }             
            /*
              TCP_FAST_RETRANSMISSION

              If 2 or more duplicate ACKs have been received from the rev flow (there might be duplicate
              acks missing from the trace) and the sequence number matches those ACKs or falls within 
              a "Previous segments unseen" gap; OR if this flow was placed into recovery when the 3rd
              dup-ACK was seen but a retransmission has not yet been sent, label this segment as a Fast 
              retransmission.
            */
            if (!tcpd->ta_send)
                tcp_analyze_get_ta_send_struct(frame, FALSE, tcpd);
            if(tcpd->rev->dupacknum >= 2 
            && (seq == tcpd->rev->highest_ack || (tcpd->ta_send && tcpd->ta_send->seg_falls_in_gap))) {
                tcpd->rxmtinfo->flags |= TCP_FAST_RETRANSMISSION;
                tcpd->fwd->rec_target = tcpd->fwd->nextseq;
                tcpd->rxmtinfo->rec_target = tcpd->fwd->nextseq;
                tcpd->fwd->frame_rec_entered = frame;
                tcpd->rxmtinfo->frame_rec_entered = frame;
                tcpd->rxmtinfo->is_first_rxmt = TRUE;
                tcpd->rxmtinfo->first_rxmt_ts = pinfo->fd->abs_ts;
                /*
                   In order for bytes_in flight to be accurate during recovery, the duplicate ACK 
                   counter must be set/reset to zero upon entering recovery.
                */
                tcpd->rev->dupacknum = 0;
                goto finished_checking_retransmission_type;
            }
        } else {
            /* We're already in TCP Recovery.
               Don't update rec_target because the target seq# is the highest transmitted seq# at
               the time when the sender entered Recovery. 
            *
               TCP_SACK_RETRANSMISSION 
               If FACK+SACK or Reno+SACK triggered our entry into Recovery and , this segment is
               probably just filling in a gap but even if new data is being transmitted
            */
            if(tcpd->rev->sackb_l 
            && LT_SEQ(tcpd->rev->highest_ack, snd_fack)) {
                tcpd->rxmtinfo->flags |= TCP_SACK_RETRANSMISSION;
                tcpd->rxmtinfo->rec_target = tcpd->fwd->rec_target;
                tcpd->rxmtinfo->frame_rec_entered = tcpd->fwd->frame_rec_entered;
                goto finished_checking_retransmission_type;           
            } 
            /*
              If SACK is not supported on this connection, the last ACK in the rev flow was a partial
              ACK, the delta time between original frame and this frame is less than the RTO period, 
              label this frame as a NewReno rexmit.
            */
            if(!tcpd->sack_supported
            && (tcpd->rev->partial_ack == TRUE)
            && time_from_orig < rto_period) {    
                /*
                   TCP_NEWRENO_RETRANSMISSION
                */
                tcpd->rxmtinfo->flags |= TCP_NEWRENO_RETRANSMISSION;
                tcpd->rxmtinfo->rec_target = tcpd->fwd->rec_target;
                tcpd->rxmtinfo->frame_rec_entered = tcpd->fwd->frame_rec_entered;
                goto finished_checking_retransmission_type;                   
            }
        }
        /*
          TCP_RETRANSMISSION

          The sender has retransmitted this segment for unknown reasons.
        */
        tcpd->rxmtinfo->flags |= TCP_RETRANSMISSION;
        /*
          If this is the first retransmission in this recovery event, enter recovery. 
          NOTE: Just because rec_target is non-zero doesn't mean that this flow is in recovery because
          it gets set if 3 dup-ACKs are seen because the receiver assumes that the sender will enter
          fast recovery at that point and begin to transmit one ACK for every packet it receives.
          However, in order to preserve the accuracy of fixed congestion point stats we don't consider
          the sender to be in recovery until it retransmits a segment. 
        */
        if (tcpd->fwd->frame_rec_entered == 0) {
            tcpd->fwd->rec_target = tcpd->fwd->nextseq;
            tcpd->rxmtinfo->rec_target = tcpd->fwd->nextseq;
            tcpd->fwd->frame_rec_entered = frame;
            tcpd->rxmtinfo->frame_rec_entered = frame;            
            tcpd->rxmtinfo->is_first_rxmt = TRUE;
            tcpd->rxmtinfo->first_rxmt_ts = pinfo->fd->abs_ts;
            /*
                In order for bytes_in flight to be accurate during recovery, the duplicate ACK 
                counter must be set/reset to zero upon entering recovery.
            */
            tcpd->rev->dupacknum = 0;
        } else {
            tcpd->rxmtinfo->rec_target = tcpd->fwd->rec_target;
            tcpd->rxmtinfo->frame_rec_entered = tcpd->fwd->frame_rec_entered;            
        }
    } 
 
finished_checking_retransmission_type:
    
    if (is_rxmt) {
       /*
          Store the bytes remaining before the recovery target seq# is reached
        */
        guint32 totsacked=0, target;

        target = tcpd->rxmtinfo->rec_target; 
        sackb = tcpd->rev->sackb_l;
        while (sackb) {
            if (LT_SEQ(sackb->seq, target)) {
                if (GE_SEQ(sackb->nextseq, target)) {
                    totsacked += target - sackb->seq;
                } else {
                    totsacked += sackb->nextseq - sackb->seq;
                }
            }
            sackb = sackb->next;
        }
        tcpd->rxmtinfo->remaining = target - tcpd->rev->highest_ack - totsacked;
    } 
    /*
      Store the highest nextseq number seen so that gaps in the byte stream can be detected.
    */
    if (!tcpd->ta_send)
        tcp_analyze_get_ta_send_struct(frame, FALSE, tcpd);
    if((tcpd->fwd->nextseq == 0 || GT_SEQ(nextseq, tcpd->fwd->nextseq))
    && (!tcpd->ta_send || (tcpd->ta_send->flags & TCP_ZERO_WINDOW_PROBE) == 0)) {
        /*
          If this is a rexmit and new_data has been appended, store the seq of the new data which will
          trigger the new segment to be added to the ua_segs_l list.
        */
        if(is_rxmt 
        && nextseq > tcpd->fwd->nextseq) {
            new_data_seq = tcpd->fwd->nextseq;
            tcpd->rxmtinfo->new_data_appended = TRUE;
        }
        tcpd->fwd->nextseq = nextseq;   
    }
    if(is_rxmt
    && tcpd->fwd->rec_target) {
        /*
           Store info about this retransmission in the ua_rxmts_in_rec_l list which is used to check
           for RE-retransmissions. 
        */
        TCP_UNACKED_SEG_IN_REC_NEW(ua_rxmt);
        ua_rxmt->next = tcpd->fwd->ua_rxmts_in_rec_l;
        tcpd->fwd->ua_rxmts_in_rec_l = ua_rxmt;
        ua_rxmt->frame = frame;
        ua_rxmt->seq = seq;
        ua_rxmt->nextseq = nextseq;
        ua_rxmt->seglen = seglen;

        /* Add the seglen of this retransmission to tcpd->fwd->all_rxmt_bytes_in_rec and
           ua_rxmt_bytes_in_rec which are used to calculate bytes_in_flight.
        */
        if (LE_SEQ(nextseq, tcpd->fwd->rec_target)) {
            tcpd->fwd->ua_rxmt_bytes_in_rec += seglen;
            tcpd->fwd->all_rxmt_bytes_in_rec += seglen;
        } else { 
            /*
               Add the portion of this retransmission to tcpd->fwd->all_rxmt_bytes_in_rec and 
               all_rxmt_bytes_in_rec that were less than rec_target. These are the number of bytes
               transmitted while in recovery.
            */
            if(LE_SEQ(seq, tcpd->fwd->rec_target)
            && GT_SEQ(nextseq, tcpd->fwd->rec_target))
                tcpd->fwd->ua_rxmt_bytes_in_rec += (tcpd->fwd->rec_target - seq);
                tcpd->fwd->all_rxmt_bytes_in_rec += (tcpd->fwd->rec_target - seq);
        } 
    } 
    /*
       Calculate bytes_in_flight and unACKed bytes in this flow provided that valid_unacked is set (it
       is reset for out-of-order frames) and store them in this frame's tcppd struct.   
    */
    if(tcpd->fwd->valid_unacked
    && tcp_track_unacked_and_bif) {
        /*
          Check for a RE-retransmission.
        */
        if (tcpd->rxmtinfo
        || tcpd->fwd->ua_rxmts_in_rec_l) {
            ua_rxmt = tcpd->fwd->ua_rxmts_in_rec_l;
            while (ua_rxmt) {
                if(ua_rxmt->frame != frame
                && seq == ua_rxmt->seq) {
                    tcpd->rxmtinfo->re_retransmission = TRUE;
                } 
                ua_rxmt = ua_rxmt->next;
            }
        }
        if ( !tcpd->sack_supported ) {
            /*
              With NO active SACK blocks during a particular “fast recovery” event, bytes_in_flight
              equals:
               o The highest sequence number minus the highest acknowledgment number
               o Plus the total number of bytes in ALL the retransmissions sent during that “Fast
                 Recovery” event including those that have been ACKed, those triggered by NewReno, and
                 unwarranted retransmissions (i.e., those with sequence numbers less than the highest
                 ACK seen in the reverse flow)
               o Minus 1*MSS for each duplicate acknowledgment received during “fast recovery” provided
                 that the dup-ack is less than or equal to the highest ACK seen in the reverse flow
                 This check has already been done above.
            */
            if (tcpd->fwd->rec_target)  {
                if (tcpd->rev->highest_ack == 0) {
                    in_flight = (nextseq - tcpd->fwd->firstxmitseq) + tcpd->fwd->all_rxmt_bytes_in_rec;
                } else {
                    in_flight = (tcpd->fwd->nextseq - tcpd->rev->highest_ack) + tcpd->fwd->all_rxmt_bytes_in_rec;
                }
                if (in_flight >= (guint32)(tcpd->rev->dupacks_in_rec * tcpd->fwd->s_mss))
                    in_flight -= tcpd->rev->dupacks_in_rec * tcpd->fwd->s_mss;
            } else {
                if (tcpd->rev->highest_ack == 0) {
                    in_flight = (nextseq - tcpd->fwd->firstxmitseq);
                } else {
                    in_flight = (tcpd->fwd->nextseq - tcpd->rev->highest_ack);
                }
                if (in_flight >= (guint32)(tcpd->rev->dupacks_in_rec * tcpd->fwd->s_mss))
                    in_flight -= tcpd->rev->dupacks_in_rec * tcpd->fwd->s_mss;
            }                      
        } else {
            /*
               With active SACK blocks during a particular “fast recovery” event, bytes_in_flight
               equals:
                o The length (seglen) of the unACKed retransmissions (tcp->fwd
                o Plus the length of any unACKed or unSACKed new data segments transmitted
                  after recovery was entered (tcpd->fwd->nextseq - tcpd->fwd->rec_target).

               When in recovery and SACK blocks are outstanding, bytes in flight should NOT include
               the gap from the ACK to the first SACK block, the gaps between the blocks, or the
               gap between the right edge of the last block and nextseq. When a SACK block
               arrives, the sender concludes that none of the segments that fall within those gaps are
               still "on the wire" and explains why:
                o Gaps are excluded from the in_flight calculation.
                o in_flight and unACKed bytes typically differ during recovery events.
                o Wireshark must maintain separate variables for in_flight and unACKed bytes.  
            */
            if (tcpd->fwd->rec_target) {
                in_flight = tcpd->fwd->ua_rxmt_bytes_in_rec;
                if (tcpd->fwd->nextseq > tcpd->fwd->rec_target)
                    in_flight += tcpd->fwd->nextseq - tcpd->fwd->rec_target;
            } else {
                if (tcpd->rev->snd_fack)
                    in_flight = seglen + (tcpd->fwd->nextseq - tcpd->rev->snd_fack);
                else
                    in_flight = tcpd->fwd->nextseq - tcpd->rev->highest_ack;
            }
        }
        /*
           Store in_flight in this frame's tcppd 
        */
        if(in_flight > 0 
        && in_flight < 2000000000) {
            tcppd = p_get_proto_data(pinfo->fd, proto_tcp);
            if (!tcppd) {
                tcppd = se_alloc(sizeof(struct tcp_per_packet_data_t));
                p_add_proto_data(pinfo->fd, proto_tcp, tcppd);
                tcppd->display_ack = FALSE;
            }
            tcppd->bif = in_flight;
            tcppd->highest_ack_rev = tcpd->rev->highest_ack;
        }
        /*
           Store the number of outstanding (unACKed and unSACKed) bytes in this frame's tcppd struct.
           If greater than the current value of tcpd->fwd->max_size_unacked, set the later to the new
           highest number of outstanding bytes.
        */
        if(tcpd->rev->highest_ack == 0
        && tcpd->fwd->firstxmitseq > 0
        && tcpd->fwd->firstxmitseq < nextseq) {
                tcppd->unacked = nextseq - tcpd->fwd->firstxmitseq;
                tcpd->fwd->max_size_unacked = tcppd->unacked;
        } else {
            tcppd->unacked = tcpd->fwd->nextseq - tcpd->rev->highest_ack - tcpd->rev->totalsacked;
            tcpd->fwd->max_size_unacked = MAX(tcpd->fwd->max_size_unacked, tcppd->unacked);

            /* Sanity check */
            if (tcppd->unacked > 2000000)
                    tcppd->unacked = 0;
        }
        if(!(tcpd->wsf_announced) 
        &&   tcpd->fwd->max_size_unacked > tcpd->rev->max_size_window)
            tcpd->rev->max_size_window = tcpd->fwd->max_size_unacked;


        if(tcpd->fwd->prev_seg_miss_l
        && tcpd->fwd->prev_seg_miss_l->frame == frame)
            tcpd->fwd->prev_seg_miss_l->unacked = tcppd->unacked; 
    }  
    /*
       If this segment advances the the highest nextseq seen in this flow including any new data that
       was appended to a retransmission, add it to the ua_segs_l list.
    */
    if((!is_rxmt || new_data_seq > 0) 
    && (tcpd->rev->highest_ack > 0 ? GT_SEQ(nextseq, tcpd->rev->highest_ack) : TRUE) 
    && (seglen > 0 || (tcpflags & (TH_SYN|TH_FIN)))) {
        TCP_UNACKED_SEG_NEW(ua_seg);
        ua_seg->frame = frame;
        ua_seg->ts=pinfo->fd->abs_ts;
        ua_seg->ip_id = pinfo->ip_id; 
        ua_seg->seq = new_data_seq > 0 ? new_data_seq : seq;
        ua_seg->nextseq = nextseq;
        ua_seg->ack = ack;
        ua_seg->flags = tcpflags;
        ua_seg->win = window;
        if (tcppd) {
            ua_seg->unacked = tcppd->unacked;
        }
        /* If this seg is out-of-order, insert it at the appropriate place in the list; otherwise, add
           it to the top.
        */
        if (is_ooo) {
            prevual = tcpd->fwd->ua_segs_l;
            while(prevual) {
                if (GE_SEQ(seq, prevual->nextseq)) {
                    ua_seg->next = prevual;
                    prevual = ua_seg;
                    break;
                }
                prevual = prevual->next;
            }

        } else {
            ua_seg->next = tcpd->fwd->ua_segs_l;
            tcpd->fwd->ua_segs_l = ua_seg;
        }
    } 

    /* Refer to Section "Required Criteria for Calculating the Fixed Congestion Point Analysis (FCPA)
       Statisics in the First Pass" in 'packet-tcp.h' for more detailed information
    */
    if(is_rxmt
    && tcpd->rxmtinfo->is_first_rxmt
    && (tcpd->fwd->nextseq_upon_exit ? GE_SEQ(tcpd->rev->highest_ack, tcpd->fwd->nextseq_upon_exit) : TRUE)
    && (sender_side_cap==CAP_TAKEN_ON_THE_SENDER || sender_side_cap==AUTO_DETECT_SIDE_CAP_TAKEN) 
    && tcp_track_unacked_and_bif
    && tcpd->rxmtinfo->unacked_of_orig) {
        first_rxmt_t *first_rxmt = NULL; 
        /*
          Create a new first_rxmt entry, store unacked_of_orig, and add it to the tcpd->fwd->first_rxmtl list.
        */
        first_rxmt = (struct first_rxmt_t *)se_alloc0(sizeof(struct first_rxmt_t));
        first_rxmt->unacked_of_orig = tcpd->rxmtinfo->unacked_of_orig;
        if ( !tcpd->fwd->first_rxmtl ) {
            tcpd->fwd->first_rxmtl = first_rxmt;
        } else {
            first_rxmt->next = tcpd->fwd->first_rxmtl;
            tcpd->fwd->first_rxmtl = first_rxmt;
        }
    }

    /* Remember what the ack/window is so we can track window updates and retransmissions 
       provided this ACK has not been reordered by the network.
    */
    if (GE_SEQ(ack, tcpd->fwd->highest_ack)) {
        tcpd->fwd->lastwindow = window;
        tcpd->fwd->lastacktime.secs=pinfo->fd->abs_ts.secs;
        tcpd->fwd->lastacktime.nsecs=pinfo->fd->abs_ts.nsecs;
    }

    if (GT_ID(pinfo->ip_id, tcpd->fwd->ip_id_highest, 32767))
        tcpd->fwd->ip_id_highest = pinfo->ip_id;
    /*
      If the TCP_ZERO_WINDOW_PROBE, TCP_KEEP_ALIVE, TCP_RTO_RETRANSMISSION flags were set for this
      segment, remember them for use by the next segment.
    */
    tcpd->fwd->lastsegmentflags = 0;
    if (tcpd->ta_send)
        tcpd->fwd->lastsegmentflags |= tcpd->ta_send->flags;
    if (tcpd->ta_recv)    
        tcpd->fwd->lastsegmentflags |= tcpd->ta_recv->flags;
    if (tcpd->rxmtinfo)    
        tcpd->fwd->lastsegmentflags |= tcpd->rxmtinfo->flags;
    tcpd->fwd->last_seq = seq;
    /*
      If ip_id is lower than the highest ip_id seen in this flow and this frame is not out-of-order,
      invaldate it as a device for detecting if a segment is out-of-order or a retransmission until
      sanity is restored.  
    */
    if(LT_ID(pinfo->ip_id, tcpd->fwd->ip_id_highest, 32768)
    && !is_ooo)
        tcpd->fwd->ip_id_valid = FALSE;
    /*
       If this ACK acknowledges an entry in the rev flow's ua_segs_l list, store the number of the
       ACKed frame and the delta time between this and the ACKed frame in this frame's ta_recv struct.
       Do this even when only a portion of the segment has been ACKed which is typical when the capture
       is taken on the sending host itself, LSO is enabled, and large segments (e.g., 32KiB and 64KiB)
       are transitted.
    */
    ua_seg = tcpd->rev->ua_segs_l;
    prevual = ua_seg;

    while (ua_seg) {
        if(GT_SEQ(ack, ua_seg->seq)
        && LE_SEQ(ack, ua_seg->nextseq)
        && GT_SEQ(ack, tcpd->fwd->prior_highest_ack)) { 
            tcp_analyze_get_ta_recv_struct(frame, TRUE, tcpd);
            tcpd->ta_recv->frame_acked = ua_seg->frame;
            nstime_delta(&tcpd->ta_recv->delta_ts, &pinfo->fd->abs_ts, &ua_seg->ts);
          
            if (tcpd->rev->scps_capable) {
                /*
                  Track the largest acknowledged segment for SNACK analysis. 
                */
                guint32 size_acked = MIN(ack, ua_seg->nextseq) - ua_seg->seq;
                if (size_acked > tcpd->fwd->max_size_acked) 
                    tcpd->fwd->max_size_acked = size_acked;
            }
        } else {
            /*
               Remove entries from the rev flow's ua_segs_l list whose nextseq is more than one max
               window below this ACK. Keep entries for segments that are within one max window of the
               ACK in order to detect duplicated traffic and to retreive some info for unwarranted
               retransmissions.
            */
            if (GE_SEQ(ack, ua_seg->nextseq + tcpd->fwd->max_size_window)) {
                /*
                  Disconnect the remaining items from the list and free them all */
                if (prevual == ua_seg)
                    tcpd->rev->ua_segs_l = NULL;
                else
                    prevual->next = NULL;
                
                while (ua_seg) { 
                    nextual = ua_seg->next;
                    TCP_UNACKED_SEG_FREE(ua_seg);
                    ua_seg = nextual;
                }
                break;
            }
        }
        prevual = ua_seg;
        ua_seg = ua_seg->next;             
    }
    /*
       Free entries in the prev_seg_miss_l with upper boundaries that are more than 4*max_size_window less
       than the highest ACK received from the rev flow.
    */
    if(tcpd->fwd->prev_seg_miss_l
    && tcpd->rev->highest_ack > 0) {
        prev_psu=NULL;
        psu = tcpd->fwd->prev_seg_miss_l;

        while (psu) {
            if (GE_SEQ(tcpd->rev->highest_ack, psu->ubound + (4*tcpd->rev->max_size_window))) {   
                next_psu = psu->next;
                if (!prev_psu) {
                    tcpd->fwd->prev_seg_miss_l = next_psu;
                } else {
                    prev_psu->next = next_psu;
                }
                TCP_PREV_SEGMENT_UNSEEN_FREE(psu);                
                psu = next_psu;
            } else {
                prev_psu = psu;
                psu = psu->next;
            }                
        }
    }
    tcpd->fwd->ip_id_prev = pinfo->ip_id;
    tcpd->fwd->prev_frame = frame;
    tcpd->fwd->last_seglen = seglen;
}


/************************************ DISPLAY SENDER-RELATED INFO *************************************
   
   Display the results of the sequence number analysis for flags other than those related to
   previous-seg-miss/lost/ooo and retransmissions that are stored in this frame's ta_send struct.
*/
static void
tcp_analyze_seq_print_ta_send_flags_other (packet_info *pinfo, tvbuff_t *tvb, proto_item *parent_item,
    proto_tree *sequence_tree, struct tcp_analysis *tcpd)
{
    ta_send_t *ta_send = tcpd->ta_send;
    tcp_per_packet_data_t *tcppd=NULL;
    proto_item *item;

    if (tcpd->ta_send->flags & TCP_DUPLICATE_FRAME) {
        /*
           TCP_DUPLICATE_FRAME
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, 
            ta_send->orig_frame == 0 ? "[Duplicate frame] " : "[Duplicate of frame #%u] ",
            ta_send->orig_frame);
        if (sequence_tree) {
            proto_item_append_text(parent_item, ", Duplicate frame");
            item = proto_tree_add_none_format(sequence_tree, hf_tcp_analysis_duplicate_frame,
                tvb, 0, 0, "Duplicate frame");
            PROTO_ITEM_SET_GENERATED(item);
            expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE, "Duplicate frame");
  
            if (ta_send->orig_frame) {
                proto_item_append_text(sequence_tree, " of frame %u", ta_send->orig_frame);

                item = proto_tree_add_uint(sequence_tree, hf_tcp_analysis_duplicate_of, 
                    tvb, 0, 0, ta_send->orig_frame);
                PROTO_ITEM_SET_GENERATED(item);

                if (ta_send->frame_dt.secs > 0  || ta_send->frame_dt.nsecs > 0) {
                    item = proto_tree_add_text(sequence_tree, tvb, 0, 0, 
                        "Time from frame %u:  %u.%06u secs", ta_send->orig_frame, 
                        (int)ta_send->frame_dt.secs, (int)(ta_send->frame_dt.nsecs+500)/1000);
                    PROTO_ITEM_SET_GENERATED(item);
                }
            }
        }
    } else if (tcpd->ta_send->flags & TCP_KEEP_ALIVE) {
        /*
           TCP_KEEP_ALIVE
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP Keep-Alive] ");
        if (sequence_tree) {
            proto_item_append_text(parent_item, ",  Keep-Alive");
            item = proto_tree_add_none_format(sequence_tree, hf_tcp_analysis_keep_alive, tvb, 0, 0,
                "This is a TCP Keep-Alive packet" );
            PROTO_ITEM_SET_GENERATED(item);
            expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE, "Keep-Alive");
        }
    } else if (tcpd->ta_send->flags & TCP_ZERO_WINDOW_PROBE) {
        /*
           TCP_ZERO_WINDOW_PROBE 
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP Zero Window Probe] ");
        if (sequence_tree) {
            proto_item_append_text(parent_item, ",  Zero Window Probe");
            item=proto_tree_add_none_format(sequence_tree, hf_tcp_analysis_zero_window_probe, 
                tvb, 0, 0, "This is a TCP Zero-Window Probe" );
            PROTO_ITEM_SET_GENERATED(item);
            expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE, "Zero window probe");
        }
    } else if (ta_send->flags & TCP_SEQ_NUMBER_SPACE_ALERT) {
        /*
           TCP_SEQ_NUMBER_SPACE_ALERT
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[Sequence number space alert] ");
        if (sequence_tree) {
            proto_item_append_text(parent_item, ",  Large change on the sequence number space");
            item = proto_tree_add_none_format(sequence_tree, 
                hf_tcp_analysis_seq_number_space_alert, tvb, 0, 0,
                "This sequence number space in one or both flows has changed by a large amount");
            PROTO_ITEM_SET_GENERATED(item);
            expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE, "Sequence number space alert");
        }
        if (tcpd->ta_send->flags & TCP_WINDOW_EXCEEDED) {
            /*
               TCP_WINDOW_EXCEEDED 
            */
            col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP Window Exceeded] ");
            if (sequence_tree) {
                proto_item_append_text(parent_item, ", Window Size Exceeded");
                tcppd = p_get_proto_data(pinfo->fd, proto_tcp);
                if (tcppd) {
                    item = proto_tree_add_none_format(sequence_tree, hf_tcp_analysis_window_exceeded, tvb, 0, 0,
                        "UnACK/SACKed bytes is %u so the sender *may* have exceeded the receiver's window size of %u",
                        tcppd->unacked, tcpd->ta_send->lastwindow_from_rev);
                    PROTO_ITEM_SET_GENERATED(sequence_tree);
                    expert_add_info_format(pinfo, sequence_tree, PI_SEQUENCE, PI_WARN, 
                        "The number of unACK/SACKed bytes is greater than the receiver's window and *may* have exceeded it");
                }
            }
        }      
    }
}

/*
    Display the results of the sequence number analysis concerning 'previous segment unseen, lost, and
    out-of-order' flags stored in this frame's ta_send struct. 

    It is possible for a packet to have all three of these flags set. If multiple segments were sent in
    the gap prior to this frame, some may have been delivered out-of-order, others may have been lost
    and later retransmitted, and still others may be missing because they were not successfully stored
    in the capture file. If this frame carries data, it's possible that this frame was itself lost and
    later retransmitted, or was delivered out-of-order in which case one of those flags could be set in
    addition to these three flags.    
*/
static void
tcp_analyze_seq_print_ta_send_flags_lost_ooo(packet_info *pinfo, tvbuff_t *tvb, proto_item *parent_item,
    proto_tree *sequence_tree, struct tcp_analysis *tcpd)
{  
    proto_item *item=NULL;
    
    if (tcpd->ta_send->flags & TCP_PACKET_LOST) {
        /*
           TCP_PACKET_LOST
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP Packet lost] ");
        
        if (sequence_tree) {
            item = proto_tree_add_none_format(sequence_tree, hf_tcp_analysis_packet_lost,
                tvb, 0, 0, "TCP Packet lost");
            PROTO_ITEM_SET_GENERATED(item);
            expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE, "This packet was lost.");

            if (tcpd->fwd->seglen > tcpd->fwd->s_mss) { 
                proto_item_append_text(parent_item, 
                    ", All or a portion of this LSO segment was lost and retransmitted ending "
                    "in frame %u",
                tcpd->ta_send->rxmt_at_frame);
                item = proto_tree_add_uint(sequence_tree, hf_tcp_analysis_rxmt_ending_in_frame, 
                                            tvb, 0, 0, tcpd->ta_send->rxmt_at_frame);
                PROTO_ITEM_SET_GENERATED(item);   
            } else {
                if (!tcpd->rxmtinfo)
                    tcp_analyze_get_rxmtinfo_struct(pinfo->fd->num, FALSE, tcpd);
                if(tcpd->rxmtinfo
                && tcpd->rxmtinfo->new_data_appended) {
                    proto_item_append_text(parent_item, 
                        ", Packet lost and retransmitted with new data in frame %u",
                        tcpd->ta_send->rxmt_at_frame);
                } else {
                    proto_item_append_text(parent_item, 
                        ", Packet lost and retransmitted in frame %u",
                        tcpd->ta_send->rxmt_at_frame);
                }
                item = proto_tree_add_uint(sequence_tree, hf_tcp_analysis_rxmt_in_frame, 
                    tvb, 0, 0, tcpd->ta_send->rxmt_at_frame);
                PROTO_ITEM_SET_GENERATED(item);   
            }
        }
    } 
    if (tcpd->ta_send->flags & TCP_OUT_OF_ORDER) {
        /*
           TCP_OUT_OF_ORDER
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, 
            tcpd->ta_send->orig_frame == 0 ? "[TCP Out-Of-Order] " : "[TCP Out-Of-Order <#%u] ",
            tcpd->ta_send->orig_frame);
        if (sequence_tree) {
            proto_item_append_text(parent_item, ", Out-of-order segment");
            item = proto_tree_add_none_format(sequence_tree, hf_tcp_analysis_out_of_order,
                tvb, 0, 0, "Out-of-order segment");
            PROTO_ITEM_SET_GENERATED(item);
            expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE, "Out-of-Order segment");
  
            if (tcpd->ta_send->orig_frame) {
                proto_item_append_text(sequence_tree, " actually sent prior to frame %u ", 
                    tcpd->ta_send->orig_frame);

                item = proto_tree_add_uint(sequence_tree, hf_tcp_analysis_belongs_before_frame, 
                    tvb, 0, 0, tcpd->ta_send->orig_frame);
                PROTO_ITEM_SET_GENERATED(item);

                if (tcpd->ta_send->frame_dt.secs > 0  || tcpd->ta_send->frame_dt.nsecs > 0) {
                    item = proto_tree_add_text(sequence_tree, tvb, 0, 0, "Time from frame %u:  %u.%06u secs",
                        tcpd->ta_send->orig_frame, 
                        (int)tcpd->ta_send->frame_dt.secs, (int)(tcpd->ta_send->frame_dt.nsecs+500)/1000);
                    PROTO_ITEM_SET_GENERATED(item);
                }
            }
        }
    } 
    if (tcpd->ta_send->flags & TCP_PREV_PACKET_LOST) {
        /*
           TCP_PREV_PACKET_LOST
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP Previous packet lost] ");
        if (sequence_tree) {
            proto_item_append_text(parent_item, ", Previous segment lost");
            item = proto_tree_add_none_format(sequence_tree, hf_tcp_analysis_prev_packet_lost,
                tvb, 0, 0, "Previous segment(s) were lost");
            PROTO_ITEM_SET_GENERATED(item);
            expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE,
                "Previous segment(s) were lost in the network and later retransmitted");
            item = proto_tree_add_uint(sequence_tree, hf_tcp_analysis_prev_seg_rxmt_at_frame, 
                tvb, 0, 0, tcpd->ta_send->rxmt_at_frame);
            PROTO_ITEM_SET_GENERATED(item); 
        }
    } 
    if (tcpd->ta_send->flags & TCP_PREV_PACKET_OUT_OF_ORDER) {
        /*
           TCP_PREV_PACKET_OUT_OF_ORDER
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP Previous packet out-of-order] ");
        if (sequence_tree) {
            proto_item_append_text(parent_item, ", Previous segment(s) were received out-of-order");
            item = proto_tree_add_none_format(sequence_tree, hf_tcp_analysis_prev_packet_out_of_order,
                tvb, 0, 0, "Previous segment(s) were received out-of-order");
            PROTO_ITEM_SET_GENERATED(item);
            expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE,
                "Previous segment(s) were received out-of-order");
            item = proto_tree_add_uint(sequence_tree, hf_tcp_analysis_prev_packet_ooo_at_frame, 
                tvb, 0, 0, tcpd->ta_send->orig_frame);
            PROTO_ITEM_SET_GENERATED(item);     
        }
    }     
    if (tcpd->ta_send->flags & TCP_PREV_PACKET_UNSEEN) {
        /*
           TCP_PREV_PACKET_UNSEEN
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP Previous packet unseen] ");
        if (sequence_tree) {
            proto_item_append_text(parent_item, ", Previous segment(s) are missing from the capture");
            item = proto_tree_add_none_format(sequence_tree, hf_tcp_analysis_prev_packet_unseen,
                tvb, 0, 0, "TCP Previous segment(s) unseen");
            PROTO_ITEM_SET_GENERATED(item);
            expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE,
                "Previous segment(s) are missing from this capture but were not actually lost or reordered.");
        }
    }
    if (item) {
        /*
          Display the gap size
        */
        item = proto_tree_add_uint(sequence_tree, hf_tcp_analysis_gap_size, tvb, 0, 0,
                                   tcpd->ta_send->gap_size);
        PROTO_ITEM_SET_GENERATED(item); 
    }
}

/* Display the results of the sequence number analysis concerning retransmissions that have been stored
*  in this frame's ta_send struct.  
*/
static void
tcp_analyze_seq_print_retransmission(packet_info *pinfo, tvbuff_t *tvb, proto_item *tcp_tree, 
    proto_tree *sequence_tree, struct tcp_analysis *tcpd)
{
    guint32 rec_target;
    proto_item *ritem, *item;
    tcp_rxmtinfo_t *rxmtinfo;
    emem_strbuf_t *type = NULL;
    char* re_rexmit = NULL;

    if (!tcpd->rxmtinfo)
        return;

    rxmtinfo = tcpd->rxmtinfo;
    if (rxmtinfo->re_retransmission)
        re_rexmit = " RE-";
    else 
        re_rexmit = " ";
    
    type = ep_strbuf_new_label("");
    
    if (rxmtinfo->flags & TCP_FACK_RETRANSMISSION) {
        ep_strbuf_append_printf(type, "%s", "TCP FACK");
        if (sequence_tree) {
            ritem = proto_tree_add_none_format(sequence_tree, hf_tcp_analysis_fack_retransmission,
                tvb, 0, 0, "FACK retransmission");
            item = proto_tree_add_uint( sequence_tree, hf_tcp_analysis_mss, tvb, 0, 0, tcpd->fwd->s_mss);
            PROTO_ITEM_SET_GENERATED(item);
            if (tcpd->mss_opt_seen == FALSE) {
                proto_item_append_text(item, " (estimated)");
            }        
        }
    } else if (rxmtinfo->flags & TCP_FAST_RETRANSMISSION) {
        ep_strbuf_append_printf(type, "%s", "TCP Fast");
        if (sequence_tree) {
            ritem = proto_tree_add_none_format(sequence_tree, hf_tcp_analysis_fast_retransmission,
                tvb, 0, 0, "Fast retransmission");
        }
    } else if (rxmtinfo->flags & TCP_SACK_RETRANSMISSION) {
        ep_strbuf_append_printf(type, "%s", "TCP SACK");
        if (sequence_tree) {
            ritem = proto_tree_add_none_format(sequence_tree, hf_tcp_analysis_sack_retransmission,
                tvb, 0, 0, "SACK %sretransmission", re_rexmit);
        }
    } else if (rxmtinfo->flags & TCP_NEWRENO_RETRANSMISSION) {
        ep_strbuf_append_printf(type, "%s", "TCP NewReno");
        if (sequence_tree) {
            ritem = proto_tree_add_none_format(sequence_tree, hf_tcp_analysis_newreno_retransmission,
                tvb, 0, 0, "NewReno %sretransmission", re_rexmit);
        }
    } else if (rxmtinfo->flags & TCP_RTO_RETRANSMISSION) {
        ep_strbuf_append_printf(type, "%s", "TCP RTO");
        if (sequence_tree) {
            ritem = proto_tree_add_none_format(sequence_tree, hf_tcp_analysis_rto_retransmission,
                tvb, 0, 0, "RTO %sretransmission", re_rexmit);
            if (rxmtinfo->ack_lost) {
                item = proto_tree_add_text(sequence_tree, tvb, 0, 0,
                    "ACK or SACK in frame #%u may have been lost", rxmtinfo->orig_frame);
                PROTO_ITEM_SET_GENERATED(item);
            }
        }
    } else if (rxmtinfo->flags & TCP_UNWARRANTED_RETRANSMISSION) {
        ep_strbuf_append_printf(type, "%s", "TCP Unwarranted"); 
        if (sequence_tree) {
            ritem = proto_tree_add_none_format(sequence_tree, hf_tcp_analysis_unwarranted_retransmission,
                tvb, 0, 0, "Unwarranted retransmissionx");
        }
    } else if (rxmtinfo->flags & TCP_RETRANSMISSION) {
        ep_strbuf_append_printf(type, "%s", "TCP"); 
        if (sequence_tree) {
            ritem = proto_tree_add_none_format(sequence_tree, hf_tcp_analysis_retransmission,
                tvb, 0, 0, "TCP%sretransmission", re_rexmit);
        }
    }
    ep_strbuf_append_printf(type, "%s", (rxmtinfo->re_retransmission ? " RE-retransmission" : " Retransmission"));

    if (sequence_tree) {
        PROTO_ITEM_SET_GENERATED(ritem);
        expert_add_info_format(pinfo, ritem, PI_SEQUENCE, PI_NOTE, "%s", type->str);        
    }
    
    if (rxmtinfo->orig_frame == 0xffffffff) {
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[%s] ", type->str);
        if (sequence_tree) {
            proto_item_append_text(sequence_tree, 
                ", %s of frame prior to the first frame in the capture ",
                type->str);
        }
    } else if (rxmtinfo->orig_frame == 0) {
        /*
          If this happens, a dissector error was thrown
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[%s] ", type->str);
        if (sequence_tree) {
            proto_item_append_text(sequence_tree, ", %s of an unknown frame", type->str);
        }
    } else {
        /*
         * Display the retransmission type and original frame# in Packet List and header line
         * of the sequence tree
         */
        tcp_analyze_get_ta_send_struct(pinfo->fd->num, FALSE, tcpd);
        
        if(tcpd->ta_send 
        && tcpd->ta_send->seg_falls_in_gap) {
            col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[%s of <#%u] ",
                type->str, rxmtinfo->orig_frame);
            if (sequence_tree)
                proto_item_append_text(sequence_tree, ", %s of segment prior to #%u ", type->str, rxmtinfo->orig_frame);
        } else {
            col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, 
                rxmtinfo->new_data_appended ? "[%s of #%u plus new data] " : "[%s of #%u] ", type->str, rxmtinfo->orig_frame);
            if (sequence_tree) 
                proto_item_append_text(sequence_tree, ", %s of #%u ", type->str, rxmtinfo->orig_frame);
        }

        if (sequence_tree) {
            if(rxmtinfo->rec_target > 0
            && rxmtinfo->orig_frame != 0xffffffff) {
                /*
                 *  Display "First retransmission in this recovery event: True/False"
                 */
                item = proto_tree_add_boolean(sequence_tree, hf_tcp_analysis_first_rxmt, tvb, 0, 0, 
                    (rxmtinfo->is_first_rxmt ? TRUE : FALSE));                                             
                PROTO_ITEM_SET_GENERATED(item); 
                /*
                 *  Display "Recovery entered in frame"
                 */
                item = proto_tree_add_uint(sequence_tree, hf_tcp_analysis_frame_rec_entered, tvb, 0, 0,
                    rxmtinfo->frame_rec_entered);
                if (rxmtinfo->frame_rec_entered == pinfo->fd->num)
                    proto_item_append_text(item, "  (this frame)");
                PROTO_ITEM_SET_GENERATED(item);
                /*
                   Display the target seq# that must be ACKed for this recovery event to end
                 */
                rec_target = (tcp_relative_seq ? (rxmtinfo->rec_target - tcpd->fwd->base_seq) 
                                               :  rxmtinfo->rec_target);
                item = proto_tree_add_uint_format(sequence_tree, hf_tcp_analysis_recovery_target,
                    tvb, 0, 0, rec_target,
                    (tcp_relative_seq ? "Target recovery seq#:  %u (relative)  (%u bytes remaining)" 
                                      : "Target recovery seq#:  %u  (%u bytes remaining)"),
                    rec_target, rxmtinfo->remaining);        
                PROTO_ITEM_SET_GENERATED(item);
            }
            /*
                Provide a link to the original frame
            */
            if(tcpd->ta_send 
            && tcpd->ta_send->seg_falls_in_gap) {
                item = proto_tree_add_uint(sequence_tree, hf_tcp_analysis_orig_frame_prior_to, 
                    tvb, 0, 0, rxmtinfo->orig_frame);
            } else {
                item = proto_tree_add_uint(sequence_tree, hf_tcp_analysis_orig_frame, tvb, 0, 0, 
                    rxmtinfo->orig_frame);
            }
            PROTO_ITEM_SET_GENERATED(item);
            /*
             *  Display the time from the orig frame in the TCP>seq# subtree
             */
            item = proto_tree_add_time(sequence_tree, hf_tcp_analysis_time_from_orig, tvb, 0, 0,
                &rxmtinfo->orig_frame_dt);
            PROTO_ITEM_SET_GENERATED(item);
            /*
             *  Display the number of bytes that were unACKed when the original frame was sent provided this
             *  is the first rexmit of the event.
             */
            if(tcp_track_unacked_and_bif
            && rxmtinfo->is_first_rxmt) {
                item = proto_tree_add_uint( sequence_tree, hf_tcp_analysis_unacked_of_orig, tvb, 0, 0, 
                    rxmtinfo->unacked_of_orig);
                PROTO_ITEM_SET_GENERATED(item); 
            }
            /*
             *  Display the Fixed Congestion Point Analysis (FCPA) stats
             */
            if(tcpd->fwd->fcpa_stats_calculated) {
                item = proto_tree_add_uint(sequence_tree, hf_tcp_analysis_unacked_of_orig_in_first_rxmt, tvb, 0, 0, 
                    tcpd->fwd->first_rxmt_avg);
                proto_item_append_text(item, "  (%d Recovery events; StdDev: %.0f) ", 
                    tcpd->fwd->num_first_rxmts, tcpd->fwd->first_rxmt_stdev);
                PROTO_ITEM_SET_GENERATED(item);
            }
        }
    }
    if (sequence_tree) {
        item = proto_tree_add_none_format(sequence_tree, hf_tcp_analysis_retransmission, tvb, 0, 0, 
            "Retransmission");
        PROTO_ITEM_SET_GENERATED(item);
    }
}

/*
   Display the results of the sequence number analysis concerning TCP acknowledgements that have been
   stored info in this frame's ta_recv struct. 
*/
static void
tcp_analyze_seq_print_ta_recv_flags_ack(packet_info *pinfo, tvbuff_t *tvb, proto_item *parent_item,
    proto_tree *ack_tree, struct tcp_analysis *tcpd)
{
    ta_recv_t *ta_recv = tcpd->ta_recv;
    proto_item *item;

    if (ta_recv->flags & TCP_DUPLICATE_ACK) {
        /*
           TCP_DUPLICATE_ACK
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP Dup ACK %u#%u] ",
            ta_recv->dup_of_ack_in_frame, ta_recv->dupack_num);
        if (ack_tree) {
            proto_item_append_text(parent_item, ", Dup ACK #%u of ACK in frame %u", 
                ta_recv->dupack_num, ta_recv->dup_of_ack_in_frame);
            item = proto_tree_add_none_format(ack_tree, hf_tcp_analysis_duplicate_ack, tvb, 0, 0,
                "This is a TCP duplicate ACK");
            PROTO_ITEM_SET_GENERATED(item);

            item = proto_tree_add_uint(ack_tree, hf_tcp_analysis_duplicate_ack_num, tvb, 0, 0,
                ta_recv->dupack_num);
            PROTO_ITEM_SET_GENERATED(item);        
            expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE, "Duplicate ACK (#%u)",
                ta_recv->dupack_num);
            item=proto_tree_add_uint(ack_tree, hf_tcp_analysis_duplicate_ack_frame, tvb, 0, 0,
                ta_recv->dup_of_ack_in_frame);
            PROTO_ITEM_SET_GENERATED(item);
        }
    }
    if (ta_recv->flags & TCP_ACK_OF_UNSEEN_SEGMENT) {
        /*
           TCP_ACK_OF_UNSEEN_SEGMENT 
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP ACK of unseen segment] ");
        if (ack_tree) {
            proto_item_append_text(parent_item, ",  ACK of unseen sequence number");
            item = proto_tree_add_none_format(ack_tree, hf_tcp_analysis_ack_unseen_segment, tvb, 0, 0,
                "ACK of a unseen sequence number");
            PROTO_ITEM_SET_GENERATED(item);
            expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE,
                "ACK of a segment that is unseen from the capture file");
        }
    } 
    if (ta_recv->flags & TCP_SACK_OF_UNSEEN_SEGMENT) {
        /*
           TCP_SACK_OF_UNSEEN_SEGMENT 
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP SACK of unseen segment] ");
        if (ack_tree) {
            proto_item_append_text(parent_item, ",  SACK of unseen segment");
            item = proto_tree_add_none_format(ack_tree, hf_tcp_analysis_sack_unseen_segment, tvb, 0, 0,
                "SACK of a unseen segment");
            PROTO_ITEM_SET_GENERATED(item);
            expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE,
                "SACK of a segment that is missing from the capture file");        
        }
    }
    if (ta_recv->flags & TCP_ACK_ONLY_OUT_OF_ORDER) {
        /*
           TCP_ACK_ONLY_OUT_OF_ORDER 
        */
        proto_item_append_text(ack_tree, ", ACK out-of-order");
        item = proto_tree_add_none_format(ack_tree, hf_tcp_analysis_out_of_order,
            tvb, 0, 0, "ACK-only packet appears to have been received out-of-order");
        PROTO_ITEM_SET_GENERATED(item);
        expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE,
                    "ACK-only packet was received out-of-order");

        if (ta_recv->ooo_belongs_after) {
            col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP ACK-only out-of-order >#%u] ",
                ta_recv->ooo_belongs_after );
            if (ack_tree) {
                proto_item_append_text(ack_tree, " actually sent after frame %u ",
                    ta_recv->ooo_belongs_after);
                item = proto_tree_add_uint(ack_tree, hf_tcp_analysis_ooo_belongs_after_frame, 
                    tvb, 0, 0, ta_recv->ooo_belongs_after);
                PROTO_ITEM_SET_GENERATED(item);
                if (ta_recv->ooo_ack_dt.secs > 0  || ta_recv->ooo_ack_dt.nsecs > 0) {
                    item = proto_tree_add_text(ack_tree, tvb, 0, 0, 
                        "Time to frame %u:  %u.%06u secs", 
                        ta_recv->ooo_belongs_after, (int)ta_recv->ooo_ack_dt.secs,
                        (int)(ta_recv->ooo_ack_dt.nsecs+500)/1000);
                    PROTO_ITEM_SET_GENERATED(item);
                }
            }
        } else {
            col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP ACK-only out-of-order] ");
            if (ack_tree) {
                item = proto_tree_add_text(ack_tree, tvb, 0, 0, 
                    "Frame was actually transmitted before this point");
                PROTO_ITEM_SET_GENERATED(item);
            }
        }
    } 
    if (ta_recv->flags & TCP_ACK_OF_OUT_OF_ORDER_SEGMENT) {
        /*
           TCP_ACK_OF_OUT_OF_ORDER_SEGMENT 
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP ACK of out-of-order seg] ");
        if (ack_tree) {
            proto_item_append_text(parent_item, ",  ACK of out-of-order segment");
            item = proto_tree_add_uint(ack_tree, hf_tcp_analysis_ack_of_out_of_order_segment, tvb, 0, 0, 
                tcpd->ta_recv->frame_acked);
            PROTO_ITEM_SET_GENERATED(item);
            expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE,
                "ACK of a segment that was delivered out-of-order");
        }
    } 
    if (ta_recv->flags & TCP_PARTNER_CAN_EXIT_RECOVERY) {
        /*
           TCP_PARTNER_CAN_EXIT_RECOVERY 
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP Partner can exit recovery] ");
        if (ack_tree) {
            proto_item_append_text(parent_item, ", Partner can exit TCP recovery");
            item = proto_tree_add_none_format(ack_tree, hf_tcp_analysis_can_exit_recovery, tvb, 0, 0,
                "Partner can exit TCP recovery");
            PROTO_ITEM_SET_GENERATED(item);
            expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE, 
                "The reverse flow may exit TCP Recovery");                            
            item = proto_tree_add_uint(ack_tree, hf_tcp_analysis_frame_rec_entered, tvb, 0, 0,
                ta_recv->frame_rec_entered);
            PROTO_ITEM_SET_GENERATED(item);
            item = proto_tree_add_time(ack_tree, hf_tcp_analysis_time_in_rec, tvb, 0, 0,
                &ta_recv->time_in_rec_dt);
            PROTO_ITEM_SET_GENERATED(item);
        }
    } 
    if (ta_recv->flags & TCP_ACK_OF_KEEP_ALIVE) {
        /*
           TCP_ACK_OF_KEEP_ALIVE
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[ACK of TCP Keep-Alive] ");
        if (ack_tree) {
            proto_item_append_text(parent_item, ",  ACK of Keep-Alive");
            item = proto_tree_add_none_format(ack_tree, hf_tcp_analysis_keep_alive_ack, tvb, 0, 0,
                "ACK of a TCP Keep-Alive packet" );
            PROTO_ITEM_SET_GENERATED(item);
            expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE, "ACK of Keep-Alive");
        }
    } else if (ta_recv->flags & TCP_GRATUITOUS_ACK) {
        /*
           TCP_GRATUITOUS_ACK
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[Gratuitous ACK] ");
        if (ack_tree) {
            proto_item_append_text(parent_item, ",  Gratuitous ACK");
            item = proto_tree_add_none_format(ack_tree, hf_tcp_analysis_gratuitous_ack, tvb, 0, 0,
                "Gratuitous ACK - There is no outstanding data in the reverse flow");
            PROTO_ITEM_SET_GENERATED(item);
            expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE,
                "Gratuitous ACK");        
        } 
    }
}

/*
*  Display results of the sequence number analysis for receiver-related flags concerning the TCP
*  window. 
*/
static void
tcp_analyze_seq_print_ta_recv_flags_window(packet_info *pinfo, tvbuff_t *tvb,
                                           proto_item *parent_item, proto_tree *win_tree,
                                           struct tcp_analysis *tcpd )
{
    proto_item * win_item;

    if (tcpd->ta_recv->flags & TCP_WINDOW_UPDATE) {
        /*
           TCP_WINDOW_UPDATE 
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP Window Update] ");
        if (win_tree) {
            proto_item_append_text(parent_item, ", Window update");
            win_item=proto_tree_add_none_format(win_tree, hf_tcp_analysis_window_update, tvb, 0, 0,
                "This is a TCP Window Update" );
            PROTO_ITEM_SET_GENERATED(win_item);
            expert_add_info_format(pinfo, win_item, PI_SEQUENCE, PI_CHAT, "Window update");
        }    
    } else if (tcpd->ta_recv->flags & TCP_ACK_OF_ZERO_WINDOW_PROBE) {
        /*
           TCP_ACK_OF_ZERO_WINDOW_PROBE
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP ACK of Zero Window Probe] ");
        if (win_tree) {
            proto_item_append_text(parent_item, ", ACK of Zero Window Probe");
            win_item=proto_tree_add_none_format(win_tree, hf_tcp_analysis_zero_window_probe_ack,
                tvb, 0, 0, "This is an ACK of a TCP Zero Window Probe" );
            PROTO_ITEM_SET_GENERATED(win_item);
            expert_add_info_format(pinfo, win_item, PI_SEQUENCE, PI_NOTE, "Zero window probe ACK");
        }    
    } else if (tcpd->ta_recv->flags & TCP_ZERO_WINDOW) {
        /*
           TCP_ZERO_WINDOW
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP Zero Window] ");
        if (win_tree) {
            proto_item_append_text(parent_item, ", Zero Window");
            win_item=proto_tree_add_none_format(win_tree, hf_tcp_analysis_zero_window, tvb, 0, 0,
                "A Zero Window has been advertized");
            PROTO_ITEM_SET_GENERATED(win_item);
            expert_add_info_format(pinfo, win_item, PI_SEQUENCE, PI_NOTE, "Zero window");
        }
    } else if (tcpd->ta_recv->flags & TCP_WINDOW_FULL) {
        /*
           TCP_WINDOW_FULL 
        */
        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP Window Full] ");
        if (win_tree) {
            proto_item_append_text(parent_item, ", Window Full");
            win_item=proto_tree_add_none_format(win_tree, hf_tcp_analysis_window_full, tvb, 0, 0,
                "The TCP window is completely full" );
            PROTO_ITEM_SET_GENERATED(win_item);
            expert_add_info_format(pinfo, win_item, PI_SEQUENCE, PI_NOTE, "Window is full");
        }
    }
}
                                             
static void
print_tcp_fragment_tree(fragment_data *ipfd_head, proto_tree *tree, proto_tree *tcp_tree, packet_info *pinfo, tvbuff_t *next_tvb)
{
    proto_item *tcp_tree_item, *frag_tree_item;

    /*
       The subdissector thought it was completely
       desegmented (although the stuff at the
       end may, in turn, require desegmentation),
       so we show a tree with all segments.
    */
    show_fragment_tree(ipfd_head, &tcp_segment_items,
        tree, pinfo, next_tvb, &frag_tree_item);
    /*
       The toplevel fragment subtree is now
       behind all desegmented data; move it
       right behind the TCP tree.
    */
    tcp_tree_item = proto_tree_get_parent(tcp_tree);
    if (frag_tree_item && tcp_tree_item) {
        proto_tree_move_item(tree, tcp_tree_item, frag_tree_item);
    }
}

/***************************************************************************
   End of tcp sequence number analysis
 ***************************************************************************/


/*
  Minimum TCP header length.
*/
#define TCPH_MIN_LEN            20

/*
  Desegmentation of TCP streams

  Table to hold defragmented TCP streams
*/
static GHashTable *tcp_fragment_table = NULL;
static void
tcp_fragment_init(void)
{
    fragment_table_init(&tcp_fragment_table);
}

/*
  Functions to trace tcp segments
*/
static void
desegment_tcp(tvbuff_t *tvb, packet_info *pinfo, int offset,
              guint32 seq, guint32 nxtseq, guint32 ack, guint32 win,
              guint32 sport, guint32 dport,
              proto_tree *tree, proto_tree *tcp_tree,
              struct tcp_analysis *tcpd)
{
    struct tcpinfo *tcpinfo = pinfo->private_data;
    fragment_data *ipfd_head;
    int last_fragment_len;
    gboolean must_desegment;
    gboolean called_dissector;
    int another_pdu_follows;
    int deseg_offset;
    guint32 deseg_seq;
    gint nbytes;
    proto_item *item;
    struct tcp_multisegment_pdu *msp;
    gboolean cleared_writable = col_get_writable(pinfo->cinfo);

again:
    ipfd_head=NULL;
    last_fragment_len=0;
    must_desegment = FALSE;
    called_dissector = FALSE;
    another_pdu_follows = 0;
    msp=NULL;

    /*
       Initialize these to assume no desegmentation.
       If that's not the case, these will be set appropriately
       by the subdissector.
    */
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = 0;

    /*
       Initialize this to assume that this segment will just be
       added to the middle of a desegmented chunk of data, so
       that we should show it all as data.
       If that's not the case, it will be set appropriately.
    */
    deseg_offset = offset;

    /*
       See if seq is part of a multi-frame PDU 
    */
    if (tcpd) {
        msp = se_tree_lookup32_le(tcpd->fwd->multisegment_pdus, seq);
    }
    if(msp
    && LE_SEQ(msp->seq, seq)
    && GT_SEQ(msp->nxtpdu, seq)) {
        int len;

        if (!pinfo->fd->flags.visited) {
            msp->last_frame=pinfo->fd->num;
            msp->last_frame_time=pinfo->fd->abs_ts;
        }
        /*
           OK, this PDU was found, which means the segment continues
           a higher-level PDU and that we must desegment.
        */
        if (msp->flags&MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT) {
            /*
              The dissector asked for the entire segment
            */
            len=tvb_length_remaining(tvb, offset);
        } else {
            len=MIN(nxtseq, msp->nxtpdu) - seq;
        }
        last_fragment_len = len;

        ipfd_head = fragment_add(tvb, offset, pinfo, msp->first_frame,
            tcp_fragment_table,
            seq - msp->seq,
            len,
            (LT_SEQ (nxtseq,msp->nxtpdu)) );

        if (msp->flags&MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT) {
            msp->flags&=(~MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT);
            /*
               If we consumed the entire segment there is no
               other pdu starting anywhere inside this segment.
               So update nxtpdu to point at least to the start
               of the next segment.
               (If the subdissector asks for even more data we
               will advance nxtpdu even furhter later down in
               the code.)
            */
            msp->nxtpdu=nxtseq;
        }

        if (LT_SEQ(msp->nxtpdu, nxtseq)
        && GE_SEQ(msp->nxtpdu, seq)
        && len > 0) {
            another_pdu_follows=msp->nxtpdu-seq;
        }
    } else {
        /*
           This segment was not found in our table, so it doesn't
           contain a continuation of a higher-level PDU.
           Call the normal subdissector.

           Supply the sequence number of this segment. We set this here
           because this segment could be after another in the same packet,
           in which case seq was incremented at the end of the loop.
        */
        tcpinfo->seq = seq;

        process_tcp_payload(tvb, offset, pinfo, tree, tcp_tree,
                sport, dport, 0, 0, 0, 0, FALSE, tcpd);
        called_dissector = TRUE;

        /* Did the subdissector ask us to desegment some more data
           before it could handle the packet?
           If so we have to create some structures in our table but
           this is something we only do the first time we see this
           packet.
        */
        if (pinfo->desegment_len) {
            if (!pinfo->fd->flags.visited)
                must_desegment = TRUE;

            /*
               Set "deseg_offset" to the offset in "tvb"
               of the first byte of data that the
               subdissector didn't process.
            */
            deseg_offset = offset + pinfo->desegment_offset;
        }
        /*
          Either no desegmentation is necessary, or this is
          segment contains the beginning but not the end of
          a higher-level PDU and thus isn't completely
          desegmented.
        */
        ipfd_head = NULL;
    }


    /* Is it completely desegmented? */
    if (ipfd_head) {
        /*
           Yes, we think it is.
           We only call subdissector for the last segment.
           Note that the last segment may include more than what
           we needed.
        */
        if (ipfd_head->reassembled_in == pinfo->fd->num) {
            /*
              OK, this is the last segment.
              Let's call the subdissector with the desegmented
              data.
            */
            tvbuff_t *next_tvb;
            int old_len;
            /*
              Add an msp entry for the first segment in this PDU to the multisegment_pdus because
              entries are only added for the 2nd thru n frames of the PDU.
            */
            se_tree_insert32(tcpd->fwd->multisegment_pdus, msp->seq, (void *)msp);
            /*
              Create a new TVB structure for desegmented data
            */
            next_tvb = tvb_new_child_real_data(tvb, ipfd_head->data,
                       ipfd_head->datalen, ipfd_head->datalen);

            /*
              Add desegmented data to the data source list
            */
            add_new_data_source(pinfo, next_tvb, "Reassembled TCP");

            /*
              Supply the sequence number of the first of the
              reassembled bytes.
            */
            tcpinfo->seq = msp->seq;

            /* indicate that this is reassembled data */
            tcpinfo->is_reassembled = TRUE;

            /* call subdissector */
            process_tcp_payload(next_tvb, 0, pinfo, tree,
                tcp_tree, sport, dport, 0, 0, 0, 0, FALSE, tcpd);
            called_dissector = TRUE;

            /*
              OK, did the subdissector think it was completely
              desegmented, or does it think we need even more
              data?
            */
            old_len=(int)(tvb_reported_length(next_tvb)-last_fragment_len);
            if(pinfo->desegment_len > 0
            && pinfo->desegment_offset <= old_len) {
                /*
                  "desegment_len" isn't 0, so it needs more
                  data for something - and "desegment_offset"
                  is before "old_len", so it needs more data
                  to dissect the stuff we thought was
                  completely desegmented (as opposed to the
                  stuff at the beginning being completely
                  desegmented, but the stuff at the end
                  being a new higher-level PDU that also
                  needs desegmentation).
                */
                fragment_set_partial_reassembly(pinfo,msp->first_frame,tcp_fragment_table);
                /*
                  Update msp->nxtpdu to point to the new next
                  pdu boundary.
                */
                if (pinfo->desegment_len == DESEGMENT_ONE_MORE_SEGMENT) {
                    /*
                       We want reassembly of at least one
                       more segment so set the nxtpdu
                       boundary to one byte into the next
                       segment.
                       This means that the next segment
                       will complete reassembly even if it
                       is only one single byte in length.
                    */
                    msp->nxtpdu=seq+tvb_reported_length_remaining(tvb, offset) + 1;
                    msp->flags|=MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT;
                } else {
                    msp->nxtpdu=seq + last_fragment_len + pinfo->desegment_len;
                }
                /*
                   Since we need at least some more data
                   there can be no pdu following in the
                   tail of this segment.
                */
                another_pdu_follows=0;
                offset += last_fragment_len;
                seq += last_fragment_len;
                if (tvb_length_remaining(tvb, offset) > 0)
                    goto again;
            } else {
                /*
                   Show the stuff in this TCP segment as
                   just raw TCP segment data.
                */
                nbytes = another_pdu_follows > 0
                    ? another_pdu_follows
                    : tvb_reported_length_remaining(tvb, offset);
                proto_tree_add_text(tcp_tree, tvb, offset, nbytes,
                    "TCP segment data (%u byte%s)", nbytes,
                    plurality(nbytes, "", "s"));

                print_tcp_fragment_tree(ipfd_head, tree, tcp_tree, pinfo, next_tvb);

                /* Did the subdissector ask us to desegment
                   some more data?  This means that the data
                   at the beginning of this segment completed
                   a higher-level PDU, but the data at the
                   end of this segment started a higher-level
                   PDU but didn't complete it.

                   If so, we have to create some structures
                   in our table, but this is something we
                   only do the first time we see this packet.
                */
                if (pinfo->desegment_len) {
                    if (!pinfo->fd->flags.visited)
                        must_desegment = TRUE;

                    /* The stuff we couldn't dissect
                       must have come from this segment,
                       so it's all in "tvb".

                       "pinfo->desegment_offset" is
                       relative to the beginning of
                       "next_tvb"; we want an offset
                       relative to the beginning of "tvb".

                       First, compute the offset relative
                       to the *end* of "next_tvb" - i.e.,
                       the number of bytes before the end
                       of "next_tvb" at which the
                       subdissector stopped.  That's the
                       length of "next_tvb" minus the
                       offset, relative to the beginning
                       of "next_tvb, at which the
                       subdissector stopped.
                    */
                    deseg_offset =
                        ipfd_head->datalen - pinfo->desegment_offset;

                    /* "tvb" and "next_tvb" end at the
                       same byte of data, so the offset
                       relative to the end of "next_tvb"
                       of the byte at which we stopped
                       is also the offset relative to
                       the end of "tvb" of the byte at
                       which we stopped.

                       Convert that back into an offset
                       relative to the beginninng of
                       "tvb", by taking the length of
                       "tvb" and subtracting the offset
                       relative to the end.
                    */
                    deseg_offset=tvb_reported_length(tvb) - deseg_offset;
                }
            }
        }
    }

    if (must_desegment) {
        /*
           If the dissector requested "reassemble until FIN"
           just set this flag for the flow and let reassembly
           proceed as normal.  We will check/pick up these
           reassembled PDUs later down in dissect_tcp() when checking
           for the FIN flag.
        */
        if (pinfo->desegment_len == DESEGMENT_UNTIL_FIN)
            tcpd->fwd->flags |= TCP_FLOW_REASSEMBLE_UNTIL_FIN;
        /*
           The sequence number at which the stuff to be desegmented
           starts is the sequence number of the byte at an offset
           of "deseg_offset" into "tvb".

           The sequence number of the byte at an offset of "offset"
           is "seq", i.e. the starting sequence number of this
           segment, so the sequence number of the byte at
           "deseg_offset" is "seq + (deseg_offset - offset)".
        */
        deseg_seq = seq + (deseg_offset - offset);

        if(tcpd
        && LE_SEQ(nxtseq - deseg_seq, 1048576)
        && !pinfo->fd->flags.visited) {
            if (pinfo->desegment_len == DESEGMENT_ONE_MORE_SEGMENT) {
                /* The subdissector asked to reassemble using the
                   entire next segment.
                   Just ask reassembly for one more byte
                   but set this msp flag so we can pick it up
                   above.
                */
                msp = pdu_store_sequencenumber_of_next_pdu(pinfo,
                    deseg_seq, nxtseq+1, tcpd->fwd->multisegment_pdus);
                msp->flags|=MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT;
            } else {
                msp = pdu_store_sequencenumber_of_next_pdu(pinfo,
                    deseg_seq, nxtseq+pinfo->desegment_len, tcpd->fwd->multisegment_pdus);
            }
            /*
              Add this segment as the first one for this new pdu
            */
            fragment_add(tvb, deseg_offset, pinfo, msp->first_frame,
                tcp_fragment_table,
                0,
                nxtseq - deseg_seq,
                LT_SEQ(nxtseq, msp->nxtpdu));
        }
    }

    if (tree
    && (!called_dissector || pinfo->desegment_len > 0)) {
        if(ipfd_head 
        && ipfd_head->reassembled_in != 0
        && !(ipfd_head->flags & FD_PARTIAL_REASSEMBLY)) {
            /*
               We know what frame this PDU is reassembled in;
               let the user know.
            */
            item=proto_tree_add_uint(tcp_tree, hf_tcp_reassembled_in,
                tvb, 0, 0, ipfd_head->reassembled_in);
            PROTO_ITEM_SET_GENERATED(item);
        }
        /*
           Either we didn't call the subdissector because this is not the last segment of the ULP's PDU
           or the subdissector couldn't dissect any of it because some data was missing (i.e., it set
           "pinfo->desegment_len" to the amount of additional data it needs).
        */
        if (pinfo->desegment_offset == 0) {
            /*
               If ipfd_head->reassembled_in isn't set, it couldn't in fact dissect any of it and the
               first byte it couldn't dissect is at "pinfo->desegment_offset", and that's 0.  In any
               event, just mark this as TCP.
            */
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCP");
            if (tree) {             
                if(ipfd_head                    
                && ipfd_head->reassembled_in != 0) {
                    if (pinfo->can_desegment == 2) 
                        col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[Full PDU in #%u] ",
                        ipfd_head->reassembled_in);
                }
            }            
        }
        /*
          Show what's left in the packet as just raw TCP segment
          data.
          XXX - remember what protocol the last subdissector
          was, and report it as a continuation of that, instead?
        */
        nbytes = tvb_reported_length_remaining(tvb, deseg_offset);
        proto_tree_add_text(tcp_tree, tvb, deseg_offset, -1,
            "TCP segment data (%u byte%s)", nbytes,
            plurality(nbytes, "", "s"));
    }
    pinfo->can_desegment=0;
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = 0;

    if (another_pdu_follows) {
        /*
          There was another pdu following this one.
        */
        pinfo->can_desegment=2;
        /*
           We also have to prevent the dissector from changing the
           PROTOCOL and INFO colums since what follows may be an
           incomplete PDU and we dont want it be changed back from
            <Protocol>   to <TCP>
           XXX There is no good way to block the PROTOCOL column
           from being changed yet so we set the entire row unwritable.
           The flag cleared_writable stores the initial state.
        */
        col_set_fence(pinfo->cinfo, COL_INFO);
        cleared_writable |= col_get_writable(pinfo->cinfo);
        col_set_writable(pinfo->cinfo, FALSE);
        offset += another_pdu_follows;
        seq += another_pdu_follows;
        goto again;
    } else {
        /*
          Remove any blocking set above otherwise the
          proto,colinfo tap will break
        */
        if (cleared_writable)
            col_set_writable(pinfo->cinfo, TRUE);
    }
}

/*
   Loop for dissecting PDUs within a TCP stream; assumes that a PDU
   consists of a fixed-length chunk of data that contains enough information
   to determine the length of the PDU, followed by rest of the PDU.
 *
   The first three arguments are the arguments passed to the dissector
   that calls this routine.
 *
   "proto_desegment" is the dissector's flag controlling whether it should
   desegment PDUs that cross TCP segment boundaries.
 *
   "fixed_len" is the length of the fixed-length part of the PDU.
 *
   "get_pdu_len()" is a routine called to get the length of the PDU from
   the fixed-length part of the PDU; "pinfo", "tvb" and "offset" are passed.
 *
   "dissect_pdu()" is the routine to dissect a PDU.
 */
void
tcp_dissect_pdus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
         gboolean proto_desegment, guint fixed_len,
         guint (*get_pdu_len)(packet_info *, tvbuff_t *, int),
         dissector_t dissect_pdu)
{
    volatile int offset = 0;
    int offset_before;
    guint length_remaining;
    guint plen;
    guint length;
    tvbuff_t *next_tvb;
    proto_item *item=NULL;
    void *pd_save;

    while (tvb_reported_length_remaining(tvb, offset) != 0) {
        /*
           We use "tvb_ensure_length_remaining()" to make sure there actually
           *is* data remaining.  The protocol we're handling could conceivably
           consists of a sequence of fixed-length PDUs, and therefore the
           "get_pdu_len" routine might not actually fetch anything from
           the tvbuff, and thus might not cause an exception to be thrown if
           we've run past the end of the tvbuff.

           This means we're guaranteed that "length_remaining" is positive.
         */
        length_remaining = tvb_ensure_length_remaining(tvb, offset);

        /*
           Can we do reassembly?
        */
        if (proto_desegment && pinfo->can_desegment) {
            /*
              Yes - is the fixed-length part of the PDU split across segment
              boundaries?
            */
            if (length_remaining < fixed_len) {
                /*
                  Yes.  Tell the TCP dissector where the data for this message
                  starts in the data it handed us, and how many more bytes we
                  need, and return.
                */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                return;
            }
        }

        /*
          Get the length of the PDU.
        */
        plen = (*get_pdu_len)(pinfo, tvb, offset);
        if (plen < fixed_len) {
            /*
               Either:

               1) the length value extracted from the fixed-length portion
                  doesn't include the fixed-length portion's length, and
                  was so large that, when the fixed-length portion's
                  length was added to it, the total length overflowed;

               2) the length value extracted from the fixed-length portion
                  includes the fixed-length portion's length, and the value
                  was less than the fixed-length portion's length, i.e. it
                  was bogus.

                Report this as a bounds error.
            */
            show_reported_bounds_error(tvb, pinfo, tree);
            return;
        }

    /*
      Do not display the the PDU length if it crosses the boundary of the 
      packet and no more packets are available
    */
    if ( length_remaining >= plen || pinfo->fd->next != NULL ) {
        /*
          Display the PDU length as a field
        */
        item=proto_tree_add_uint(pinfo->tcp_tree, hf_tcp_pdu_size, 
            tvb, offset, plen, plen);
        PROTO_ITEM_SET_GENERATED(item);
    } else {
        item = proto_tree_add_text(pinfo->tcp_tree, tvb, offset, -1, 
            "PDU Size: %u cut short at %u",plen,length_remaining);
        PROTO_ITEM_SET_GENERATED(item);
    }

        /*
          Give a hint to TCP where the next PDU starts
          so that it can attempt to find it in case it starts
          somewhere in the middle of a segment.
        */
        if (!pinfo->fd->flags.visited && tcp_analyze_seq) {
            guint remaining_bytes;
            remaining_bytes=tvb_reported_length_remaining(tvb, offset);
            if (plen > remaining_bytes) {
                pinfo->want_pdu_tracking=2;
                pinfo->bytes_until_next_pdu=plen-remaining_bytes;
            }
        }

        /*
          Can we do reassembly?
         */
        if (proto_desegment && pinfo->can_desegment) {
            /*
               Yes - is the PDU split across segment boundaries?
            */
            if (length_remaining < plen) {
                /*
                  Yes.  Tell the TCP dissector where the data for this message
                  starts in the data it handed us, and how many more bytes we
                  need, and return.
                */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = plen - length_remaining;
                return;
            }
        }

        /*
           Construct a tvbuff containing the amount of the payload we have
           available.  Make its reported length the amount of data in the PDU.

           XXX - if reassembly isn't enabled. the subdissector will throw a
           BoundsError exception, rather than a ReportedBoundsError exception.
           We really want a tvbuff where the length is "length", the reported
           length is "plen", and the "if the snapshot length were infinite"
           length is the minimum of the reported length of the tvbuff handed
           to us and "plen", with a new type of exception thrown if the offset
           is within the reported length but beyond that third length, with
           that exception getting the "Unreassembled Packet" error.
        */
        length = length_remaining;
        if (length > plen)
            length = plen;
        next_tvb = tvb_new_subset(tvb, offset, length, plen);

        /*
           Dissect the PDU.

           Catch the ReportedBoundsError exception; if this particular message
           happens to get a ReportedBoundsError exception, that doesn't mean
           that we should stop dissecting PDUs within this frame or chunk of
           reassembled data.

           If it gets a BoundsError, we can stop, as there's nothing more to
           see, so we just re-throw it.
        */
        pd_save = pinfo->private_data;
        TRY {
            (*dissect_pdu)(next_tvb, pinfo, tree);
        }
        CATCH(BoundsError) {
            RETHROW;
        }
        CATCH(ReportedBoundsError) {
        /*
           Restore the private_data structure in case one of the
           called dissectors modified it (and, due to the exception,
           was unable to restore it).
        */
        pinfo->private_data = pd_save;
            show_reported_bounds_error(tvb, pinfo, tree);
        }
        ENDTRY;

        /*
           Step to the next PDU.
           Make sure we don't overflow.
        */
        offset_before = offset;
        offset += plen;
        if (offset <= offset_before)
            break;
    }
}


static void
dissect_tcpopt_sack_perm(const ip_tcp_opt *optp _U_, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
    conversation_t      *conv=NULL;
    struct tcp_analysis *tcpd;
    proto_item          *hidden_item = proto_tree_add_boolean(opt_tree, hf_tcp_option_sack_perm, tvb, offset,
                                           optlen, TRUE);

    conv = find_or_create_conversation(pinfo);
    tcpd = get_tcp_conversation_data(conv, pinfo);
    if (tcpd) 
        tcpd->sack_supported = TRUE;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s=%u ", "SACK_PERM", TRUE);
    proto_item_append_text(opt_tree, ", SACK permitted");
}

static void
dissect_tcpopt_mss(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
    proto_item *hidden_item;
    struct tcp_analysis *tcpd=NULL;
    guint16 mss;

    tcpd=get_tcp_conversation_data(NULL,pinfo);

    mss = tvb_get_ntohs(tvb, offset + 2);
    tcpd->fwd->s_mss = mss - tcpd->ts_optlen; 
    tcpd->mss_opt_seen = TRUE;
    /*
      If MSS is zero in the rev flow, set s_mss in the rev flow to the same value for now in the event
      that either the SYN or the SYN-ACK is missing from the capture.
    */
    if (tcpd->rev->s_mss == 0) 
        tcpd->rev->s_mss = mss - tcpd->ts_optlen;

    if (opt_tree) {
        hidden_item = proto_tree_add_boolean(opt_tree, hf_tcp_option_mss, tvb, offset, optlen, TRUE);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        proto_tree_add_uint_format(opt_tree, hf_tcp_option_mss_val, tvb, offset, optlen,
            mss, "%s: %u bytes", optp->name, mss);
        col_append_fstr(pinfo->cinfo, COL_INFO, " MSS=%u ", mss);
        proto_item_append_text(opt_tree, ", MSS: %u", mss);
    }
}

/*
   The window scale extension is defined in RFC 1323
*/
static void
dissect_tcpopt_wscale(const ip_tcp_opt *optp _U_, tvbuff_t *tvb,
    int offset, guint optlen _U_, packet_info *pinfo, proto_tree *opt_tree)
{
    struct tcp_analysis *tcpd=NULL;
    guint8 shift = tvb_get_guint8(tvb, offset + 2);

    tcpd = get_tcp_conversation_data(NULL, pinfo);
    
    tcpd->fwd->win_scale = shift;
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s=%u ", "WSF", 1 << shift);
  
    if (opt_tree) {
        guint8 val;
        proto_item *wscale_item, *geni, *hidden_item;
        proto_tree *wscale_tree;
        
        wscale_item = proto_tree_add_text(opt_tree, tvb, offset, 3, "Window scale: ");
        wscale_tree = proto_item_add_subtree(wscale_item, ett_tcp_option_window_scale);
        hidden_item = proto_tree_add_item(wscale_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_NA);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        offset += 1;
        hidden_item = proto_tree_add_item(wscale_tree, hf_tcp_option_len, tvb, offset, 1, ENC_NA);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        offset += 1;
        proto_tree_add_item(wscale_tree, hf_tcp_option_wscale_shift, tvb, offset, 1, ENC_NA);
        geni = proto_tree_add_uint(wscale_tree, hf_tcp_option_wscale_multiplier, tvb, offset, 1, 1 << shift);
        PROTO_ITEM_SET_GENERATED(geni);
        val = tvb_get_guint8(tvb, offset);
        proto_item_append_text(wscale_item, "%u (multiply by %u)", val, 1 << shift);
        proto_item_append_text(opt_tree, ", Window scale_factor: %u", 1 << shift);
    }
}

static void
sort_sackb_fr(sackb_in_this_frame_t *sackb_fr, guint16 numblks_fr, gboolean ascend)
{
    sackb_in_this_frame_t temp;
    int i , j, first=0; 

    for (i=numblks_fr-1; i > 0; i--) {
        first = 0;

        for (j=1; j<=i; j++) {            
            if (ascend) {
                if (GT_SEQ(sackb_fr[j].sle, sackb_fr[first].sle))
                    first = j;
            } else {
                if (LT_SEQ(sackb_fr[j].sle, sackb_fr[first].sle))
                    first = j;
            }
        }
        temp = sackb_fr[first];
        sackb_fr[first] = sackb_fr[i];
        sackb_fr[i] = temp;
    }
}

/* Don't confuse this routine with "dissect_tcpopt_sack_perm()" which is only called to dissect options
   in the 3-way connection establishment sequence.
*/
static void
dissect_tcpopt_sack(const ip_tcp_opt *optp, tvbuff_t *tvb,
                    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
    conversation_t *conv=NULL;
    struct tcp_analysis *tcpd=NULL;
    sackb_in_this_frame_t sackb_fr[4];
    sackb_t *sackb=NULL, *prev_sackb=NULL, *tmp_sackb=NULL, *next_sackb=NULL;
    saved_sackb_t *ssackb=NULL;
    prev_seg_unseen_t *psu=NULL;
    int num_sackb_fr, i, j, curroff;
    guint16 num_ssackb=0;
    guint32 max_size_window=0, sle, sre, rev_nextseq=0, seq=0, ack=0, gap=0,
            snd_fack=0, totalgaps=0, totalsacked=0, base_seq=0;
    float fgap_div_mss;
    gboolean first_time=TRUE, alldone=FALSE, invalid_blks=FALSE, sackb_updated=FALSE;
    ta_recv_t *ta_recv=NULL;
    proto_tree *sack_tree=NULL, *included_blk_tree=NULL, *active_blk_tree=NULL;
    proto_item *hidden_item, *sacki1, *sacki2, *sacki3, *item;    
    
    /*
      Skip over Kind and Len (2 bytes)
    */
    offset += 2;
    optlen -= 2;

    /*
      If optlen is not divisible by 8, it is truncated and/or corrupt.
    */
    if ( !(optlen % 8 == 0) ) {
        if (opt_tree) 
            proto_item_append_text(sack_tree, "The SACK option list is truncated or corrupt" 
                " (length %d is not a multiple of 8 bytes)", optlen);
        return;
    }

    conv=find_or_create_conversation(pinfo);
    tcpd = get_tcp_conversation_data(conv, pinfo);
    if (tcpd) {
        tcp_analyze_get_ta_recv_struct(pinfo->fd->num, TRUE, tcpd);
        ta_recv = tcpd->ta_recv;
        tcpd->sack_supported = TRUE;
    }

    seq = tvb_get_ntohl(tvb, 4);
    ack = tvb_get_ntohl(tvb, 8);
    rev_nextseq = tcpd->rev->nextseq;

    num_sackb_fr = optlen/8;
    if (num_sackb_fr == 0)
        return;

    curroff = offset;
    tcpd->fwd->dsack = FALSE;
    /*
      Load the SACK blocks within this packet into sack_fr[] in the order that they appear in the packet.  
    */
    for (i=0; i<num_sackb_fr; i++) {        
        sackb_fr[i].offset = curroff;
        sackb_fr[i].sle = tvb_get_ntohl(tvb, curroff);
        sackb_fr[i].sre = tvb_get_ntohl(tvb, curroff + 4);
        sackb_fr[i].dsack_blk = FALSE;
        sackb_fr[i].sack_of_unseen = FALSE;
        curroff+=8;
    }
    /*
      There is no need to re-dissect the SACK info in this frame after the first pass.
    */
    if (pinfo->fd->flags.visited)
        goto display_sack_info;  /* Better than a giant "if" clause or dividing this routine in two. */

    if (tcpd->wsf_announced)
        max_size_window = tcpd->fwd->max_size_window;
    else
        max_size_window = 1000000;

    if (tcp_analyze_seq) { 
        for (i=0; i<num_sackb_fr; i++) {
            /*
              If this block falls more than one max window size above or below the ack, 
              set invalid_blks = TRUE.
            */
            if((LE_SEQ(sackb_fr[i].sre, ack) && GT_SEQ(ack - sackb_fr[i].sre, max_size_window))
            || (GE_SEQ(sackb_fr[i].sle, ack) && GT_SEQ(sackb_fr[i].sle - ack, max_size_window))) {
                invalid_blks = TRUE;
            } else { 
                if (i == 0) {             
                    /*
                      Label this as a DSACK block if its right edge is less than the ACK (RFC 2883
                      Section 4.1.1 or falls within the bounds of the second block (RFC 2883 Sections
                      4.0, 4.1.3 and 4.2.3). 
                    */
                    if(LE_SEQ(sackb_fr[0].sre, ack)
                    || (num_sackb_fr > 1 && GE_SEQ(sackb_fr[0].sle, sackb_fr[1].sle) 
                                         && LE_SEQ(sackb_fr[0].sre, sackb_fr[1].sre))) {
                        ta_recv->triggered_by |= TRIGGER_DSACK;
                        sackb_fr[0].dsack_blk = TRUE;
                        tcpd->fwd->dsack = TRUE;
                        sackb_fr[0].offset = offset;
                    }
                }
                /*
                   If this block's right edge is greater than hightest nextseq in the rev flow:
                     1. Set nextseq in the rev flow to this SACK block's right edge, so that we won't
                        get this indication again for the same block. 
                     2. Set the TCP_SACK_OF_UNSEEN_SEGMENT flag. 
                */
                if (GT_SEQ(sackb_fr[i].sle, rev_nextseq)) {
                    tcpd->rev->nextseq = sackb_fr[i].sre;
                    rev_nextseq = tcpd->rev->nextseq;
                    tcpd->ta_recv->flags |= TCP_SACK_OF_UNSEEN_SEGMENT;
                    tcpd->ta_recv->unacked_in_rev = 0;
                    sackb_fr[i].sack_of_unseen = TRUE;
                    num_sack_of_unseen++;
                }
            }
        }
    }

    if(tcp_analyze_seq) {
        if (invalid_blks) {
            tcp_analyze_get_saved_sackl_struct(pinfo->fd->num, TRUE, 0, tcpd);
            tcpd->saved_sackb_l->invalid_blks = TRUE;
            tcpd->fwd->totalsacked = 0;  
        } else {
            if (tcpd->ta_recv->flags & TCP_SACK_OF_UNSEEN_SEGMENT) {
                /*
                  Add an entry to the tcpd->fwd->prev_seg_miss_l list defining the gap as the ack
                  through the highest sre in this frame. If a segment arrives that falls within those
                  bounds, 'orig_frame' will be set to this frame and sackb_l, the active SACK block
                  list, will be used to determine if that frame is a retransmission or delivered
                  out-of-order.
                */
                TCP_PREV_SEGMENT_UNSEEN_NEW(psu);
                psu->frame = pinfo->fd->num;
                psu->trigger = PSU_BASED_ON_SACK;
                psu->ack_only_no_sack = FALSE;
                psu->lbound = ack;
                psu->ubound = 0;
                for (i=0; i<num_sackb_fr; i++) {  
                    if (sackb_fr[i].sre > psu->ubound)
                        psu->ubound = sackb_fr[i].sre;
                }
                psu->seq = seq;
                psu->ack = 0; 
                psu->nextseq = 0;
                psu->ip_id     = (tcpd->fwd->ip_id_valid ? tcpd->fwd->ip_id_highest : 0);
                psu->ip_id_high_rev = (tcpd->rev->ip_id_valid ? tcpd->rev->ip_id_highest : 0);
                psu->ts = pinfo->fd->abs_ts;
                psu->unacked = 0;  

                if (tcpd->rev->prev_seg_miss_l)
                    psu->next = tcpd->rev->prev_seg_miss_l;
                else 
                    psu->next = NULL;
                tcpd->rev->prev_seg_miss_l = psu;
            }

            if (num_sackb_fr > 1) {
                /*
                  Sort the SACK blocks included in this packet in ascending order.
                */
                sort_sackb_fr(sackb_fr, num_sackb_fr, TRUE);
            }
            /*
              Zero the offsets in sackb_l
            */
            sackb = tcpd->fwd->sackb_l; 
            if (sackb) {
                while (sackb) {
                    sackb->offset = 0;
                    sackb = sackb->next;
                }
            } 

            if(ack == tcpd->fwd->highest_ack
            && GT_SEQ(ack, tcpd->fwd->prior_highest_ack))
                ta_recv->triggered_by |= TRIGGER_ACK;
            
            if (GT_SEQ(ack, tcpd->fwd->prior_highest_ack)) { 
                /*
                  Remove or truncate all the SACK block entries in sackb_l (the active SACK block list)
                  that fall below this ACK.
                */
                if (tcpd->fwd->sackb_l) { 
                    prev_sackb = NULL;
                    sackb = tcpd->fwd->sackb_l;

                    while (sackb) {
                        if (LE_SEQ(ack, sackb->seq)) {
                            prev_sackb = sackb;
                            sackb = sackb->next;
                        } else {
                            if (GE_SEQ(ack, sackb->nextseq)) {            
                                /*
                                  Remove the entire block
                                */
                                tcpd->fwd->totalsacked -= (sackb->nextseq - sackb->seq);
                                tmp_sackb = sackb->next;
                                if (!prev_sackb)
                                    tcpd->fwd->sackb_l = tmp_sackb;
                                else
                                    prev_sackb->next = tmp_sackb;

                                TCP_SACKED_FREE(sackb);
                                tcpd->fwd->num_ssackb--;
                                sackb = tmp_sackb;
                            } else {
                                /*
                                  The ACK falls somewhere within the range of this SACK block which   
                                  may indicate that the receiver has reneged (thrown away previously
                                  SACKed data) which should rarely happen. Truncate this block.
                                */
                                sackb->nextseq = ack;
                                prev_sackb = sackb;
                                sackb = sackb->next;
                            }
                        }
                    }   
                }
            }
            /*
               Copy each sackb_fr[] block that resides in this frame to a (sackb_t) sackb and store
               the sackb in the sackb_l list.

               NOTE: sackb_l has already been updated in tcp_analyze_sequence_number() per the ACK. The
                     absence of an unACKed SACK block that was seen in an earlier frame does not mean
                     the block is no longer active because the receiver is not required to include blocks
                     that have not changed.
            */
            num_ssackb = tcpd->fwd->num_ssackb; 
            prev_sackb = NULL;
            /*
              The outside loop selects each sackb_fr included in this frame. */
            for (i=num_sackb_fr-1; i>=0; i--) {              
                /*
                  Skip a D-SACK block, continue to the next sackb_fr, and check for non-D-SACK blocks
                  that might follow. According to D-SACK RFC 2883 it is legal to combine D-SACKs with
                  normal SACK blocks in the same packet.
                */
                if (sackb_fr[i].dsack_blk)
                    continue;

                sle = sackb_fr[i].sle;
                sre = sackb_fr[i].sre;
                /*
                  If sackb_l is empty, create a new sackb, add this sackb and move to the next sackb_fr[] if any. 
                */
                if (!tcpd->fwd->sackb_l) {
                    TCP_SACKED_NEW(sackb);
                    sackb->frame = pinfo->fd->num;
                    sackb->seq = sle;
                    sackb->nextseq = sre;
                    sackb->sack_of_unseen = sackb_fr[i].sack_of_unseen;
                    sackb->offset = sackb_fr[i].offset;
                    sackb->p_sackb_bytes = se_alloc0(8);
                    tvb_memcpy(tvb, sackb->p_sackb_bytes, sackb->offset, 8);
                    sackb->next = NULL;                        
                    tcpd->fwd->sackb_l = sackb;
                    num_ssackb++;
                    ta_recv->triggered_by |= TRIGGER_NEW_SACK_BLOCK;
                    continue;
                } else {
                    sackb = tcpd->fwd->sackb_l;
                }
                /*
                   Copy the info in each sackb_fr[] block to a (sackb_t) sackb struct and store 
                   it in the sackb_l list. The sackb entries in sackb_l are in descending
                   order. The the upper and lower boundaries of each sackb are identified as "seq"
                   and "nextseq". The blocks in sackb_fr[] are in ascending order and the boundaries
                   of each are identified as sLe and sRe.

                   As a general rule, existing sackb borders in sackb_l are not reduced by new
                   SACK info otherwise a frame that arrives out-of-order could corrupt the list. 

                   The inside loop selects each sackb from sackb_l, the active SACK block list.
                */
                while (sackb) {                    
                    if (GT_SEQ(sle, sackb->nextseq)
                    || (LT_SEQ(sre, sackb->seq) && !(sackb->next))) {
                        tmp_sackb = sackb;
                        TCP_SACKED_NEW(sackb);
                        sackb->frame = pinfo->fd->num;
                        sackb->seq = sle;
                        sackb->nextseq = sre;
                        sackb->sack_of_unseen = sackb_fr[i].sack_of_unseen;
                        sackb->offset = sackb_fr[i].offset;
                        sackb->p_sackb_bytes = se_alloc0(8);
                        tvb_memcpy(tvb, sackb->p_sackb_bytes, sackb->offset, 8);
                        ta_recv->triggered_by |= TRIGGER_NEW_SACK_BLOCK;
                        sackb->next = NULL;

                        if (GT_SEQ(sle, tmp_sackb->nextseq)) {
                            /*
                              A.1. The entire sackb_fr falls above this sackb so insert it before this
                                   sackb.
                            */
                            sackb->next = tmp_sackb;
                            if (!prev_sackb) 
                                tcpd->fwd->sackb_l = sackb;
                            else
                                prev_sackb->next = sackb;

                        } else {
                            /*
                              A.2. The entire sackb_fr falls below this sackb and this sackb is the
                                   last sackb in the list. Insert this sackb_fr *after* this sackb.
                            */
                            tmp_sackb->next = sackb;
                        }
                        num_ssackb++;
                        break; /* Process the next sack_fr. */
                    } 
                    if (LT_SEQ(sre, sackb->seq)) {
                        /*
                          B. The entire sackb_fr block falls below this sackb, loop to the next *sackb*
                             where A.1. will be retested and this sackb will be inserted above that
                             one.
                        */
                        prev_sackb = sackb;
                        sackb = sackb->next;
                        continue;
                    }
                    /*
                       C. The sLe, sRe, or both fall within this sackb.  

                       C.1. If sRe is > sackb's nextseq, set nextseq = sRe 
                    */
                    sackb_updated = FALSE;
                    if (GT_SEQ(sre, sackb->nextseq)) {
                        sackb->nextseq = sre;
                        sackb_updated = TRUE;
                    }
                    /*
                       C.2. If sLe is < sackb's seq, set seq = sLe. 
                            sackb->seq might now be less than one or more sackb's below it.      
                    */
                    if (LT_SEQ(sle, sackb->seq)) {
                        sackb->seq = sle;
                        sackb_updated = TRUE;
                    } 

                    if (sackb_updated) {
                        if (ta_recv->triggered_by == 0)
                            ta_recv->triggered_by |= TRIGGER_SACK_BLOCK_UPDATE;
                        sackb->offset = sackb_fr[i].offset;
                        sackb->p_sackb_bytes = se_alloc0(8);
                        tvb_memcpy(tvb, sackb->p_sackb_bytes, sackb->offset, 8);
                    } 
                    sackb->offset = sackb_fr[i].offset;
                    /*
                       C.3. Remove the next sackb and any sackbs below it within which sLe falls
                            (borders included).

                            If a sackb does not follow this one or if sLe falls above the next sackb's
                            nextseq, there's nothing to remove. Process the next sack_fr. 
                    */
                    next_sackb = sackb->next;
                    if (!next_sackb || GT_SEQ(sle, next_sackb->nextseq)) 
                        break; /* Process the next sack_fr */
                    /*
                      sLe falls within or below the next_sackb.             
                    */
                    while (next_sackb) {
                        /*
                          If sle falls within the next sackb (borders included), set seq to the next
                          sackb's seq. The sLe will usually equal the sackb's left border (seq) but in
                          order to prevent previously SACKed data from being unSACKed, we must perform
                          this step.
                        */
                        if(GE_SEQ(sle, next_sackb->seq) 
                        && LE_SEQ(sle, next_sackb->nextseq)) {
                            sackb->seq = next_sackb->seq;
                            /*
                               Remove the next_sackb.  
                            */
                            sackb->next = next_sackb->next;
                            TCP_SACKED_FREE(next_sackb);
                            num_ssackb--;
                            next_sackb = sackb->next;
                        } else {
                            sackb = next_sackb;
                            next_sackb = sackb->next;
                        }
                    }
                    break; /* Process the next sack_fr */
                } /* End of while loop  */
            } /* End of for loop */
        
            if (ta_recv->triggered_by == 0) {
                if (tcpd->fwd->seglen > 0) 
                    ta_recv->triggered_by |= TRIGGER_NEW_DATA;
                else
                    ta_recv->triggered_by |= TRIGGER_UNKNOWN;
            }

            if (num_ssackb > 0) {
                /*
                  Store a snapshot of the active SACK block list in *ascending* order for display in the 
                  tree and if the previous packet was seen, store the sum of the bytes in all of the gaps
                  and the total number of SACKed bytes in this flow for the calculation of the unACKed
                  bytes in the rev flow. 
                */
                tcpd->saved_sackb_l = se_tree_lookup32(tcpd->saved_sackl_table, pinfo->fd->num);
                if (tcpd->saved_sackb_l) {
                    REPORT_DISSECTOR_BUG("dissect_tcpopt_sack(): tcpd->saved_sackb_l is non-NULL");
                    return;
                }
                totalgaps = 0;
                totalsacked = 0;
                sackb = tcpd->fwd->sackb_l;

                if (sackb) {
                    tcp_analyze_get_saved_sackl_struct(pinfo->fd->num, TRUE, num_ssackb, tcpd);
                    if (GT_SEQ(rev_nextseq, sackb->nextseq)) 
                        totalgaps = rev_nextseq - sackb->nextseq;
         
                    for (i=num_ssackb-1; i>=0; i--) {
                        tcpd->saved_sackb_l->arr[i].offset = sackb->offset;
                        tcpd->saved_sackb_l->arr[i].seq = sackb->seq; 
                        tcpd->saved_sackb_l->arr[i].nextseq = sackb->nextseq;
                        if (sackb->offset == 0)
                            tcpd->saved_sackb_l->arr[i].p_sackb_bytes = sackb->p_sackb_bytes;
                        else
                            tcpd->saved_sackb_l->arr[i].p_sackb_bytes = NULL;
                        if (i == 0) 
                            totalgaps += (sackb->seq - ack);
                        else 
                            totalgaps += (sackb->seq - sackb->next->nextseq);
                        totalsacked += (sackb->nextseq - sackb->seq);
                        sackb = sackb->next;
                    }

                    tcpd->saved_sackb_l->num_active_blks = num_ssackb;
                    tcpd->saved_sackb_l->rev_nextseq = rev_nextseq;
                    if (tcpd->rev->rec_target)
                        tcpd->saved_sackb_l->rev_in_recovery = TRUE;
                    tcpd->fwd->num_ssackb = num_ssackb;
                    tcpd->fwd->totalsacked = totalsacked;
                    tcpd->fwd->sackl_rev_nextseq = rev_nextseq;

                    if (tcpd->fwd->snd_fack == 0) 
                        tcpd->fwd->snd_fack = tcpd->fwd->sackb_l->nextseq;
                    else if (GT_SEQ(tcpd->fwd->sackb_l->nextseq, tcpd->fwd->snd_fack)) 
                        tcpd->fwd->snd_fack = tcpd->fwd->sackb_l->nextseq;
                }
            }
        }
    }

   /*************************************************************************************************
    ********************* DISPLAY SACK INFO in the PACKET DETAILS AND PACKET LIST *******************
    *************************************************************************************************/

display_sack_info:

    if(tcp_analyze_seq
    && tcp_relative_seq) 
        base_seq = tcpd->rev->base_seq;

    if (tcp_analyze_seq) {
        tcpd->saved_sackb_l = NULL;
        tcp_analyze_get_saved_sackl_struct(pinfo->fd->num, FALSE, 0, tcpd);

        if(tcpd->saved_sackb_l 
        && tcpd->saved_sackb_l->invalid_blks) 
            col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[Invalid SACK range] ");   
    }
    /*
       Display the UNsorted sackb_fr blocks in the Packet List; unsorted because the first
       block indicates the block if any that changed. We need to write to the Info column
       both during the initial load of the capture and afterward so that the text can be searched.  
    */
    for (i=0; i<num_sackb_fr; i++) { 
        sle = sackb_fr[i].sle - base_seq;
        sre = sackb_fr[i].sre - base_seq;

        if (i == 0) {
            if (ta_recv->triggered_by & TRIGGER_DSACK) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", DSACK=(%u-%u) ",sle, sre);
                if (num_sackb_fr > 1)
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", SACK=");
                proto_item_append_text(opt_tree, ", DSACK");
            } else {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", SACK=(%u-%u)", sle, sre);
                proto_item_append_text(opt_tree, ", SACK");

            }
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%u-%u)", sle, sre);
        }
    }

    /*
      If this is the first pass, we can return because there are no COL_INFOs below.
    */
    if(!pinfo->fd->flags.visited
    || !opt_tree) 
        return;
    
    sacki1 = proto_tree_add_boolean_format(opt_tree, hf_tcp_option_sack, tvb, offset,
        optlen, 1, "SACK: ");
    sack_tree = proto_item_add_subtree(sacki1, ett_tcp_option_sack);
    if(tcp_analyze_seq) 
        expert_add_info_format(pinfo, sacki1, PI_SEQUENCE, PI_NOTE,
            "SACK (Selectively ACKnowlegded sequence ranges)");
    /*
       Read the option kind and length.
       The caller, 'dissect_ip_tcp_options()', ensures that there are at least 2 bytes
       available to be read.
    */
    hidden_item = proto_tree_add_item(sack_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_NA);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    offset += 1;
    hidden_item = proto_tree_add_item(sack_tree, hf_tcp_option_len, tvb, offset, 1, ENC_NA);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    offset += 1;
    optlen -= 2;  /* subtract size of type and length */

    /*
      Display what triggered this packet to be sent. There can be multiple triggers (e.g., DSACK,
      updated ACK, and updated SACK block). 
    */
    if (tcp_analyze_seq) {        
        
        if (ta_recv->triggered_by & TRIGGER_DSACK) {
            sle = sackb_fr[0].sle - base_seq;
            sre = sackb_fr[0].sre - base_seq;
            proto_item_append_text(sack_tree, " (DSACK: %u-%u)", sle, sre);
            item = proto_tree_add_bytes_format(sack_tree,
                hf_tcp_option_sack_triggered_by_dsack, tvb, sackb_fr[0].offset, 8, NULL,
                "Triggered by:  DSACK block (%u-%u) %s", sle, sre,
                (tcp_relative_seq && tcp_analyze_seq) ? "(relative)" : "");
            expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE, 
            "DSACK (A duplicate segment was received)");
        }
        if (ta_recv->triggered_by & TRIGGER_ACK) {
            item = proto_tree_add_bytes_format(
                sack_tree, hf_tcp_option_sack_triggered_by_ack, tvb, 0x8, 4, NULL,
                "Triggered by: ACK update (%u)", ack - base_seq);
            PROTO_ITEM_SET_GENERATED(item);
        } 
        if (ta_recv->triggered_by & TRIGGER_NEW_DATA) {
            item = proto_tree_add_none_format(
                sack_tree, hf_tcp_option_sack_triggered_by_data, tvb, optlen+1, tcpd->fwd->seglen,
                "Triggered by: New data (%u bytes) sent", tcpd->fwd->seglen);
            PROTO_ITEM_SET_GENERATED(item);
        }

        tcp_analyze_get_saved_sackl_struct(pinfo->fd->num, FALSE, 0, tcpd);
        if (tcpd->saved_sackb_l)
            num_ssackb = tcpd->saved_sackb_l->num_active_blks;

        for (i=0; i<num_ssackb; i++) {
            /*
              If offset is zero, this block was active (unACKed) but not included in this packet and
              thus could not have triggered this SACK packet to be sent. If zero, skip it.
            */
            if (tcpd->saved_sackb_l->arr[i].offset == 0)
                continue;
            ssackb = &tcpd->saved_sackb_l->arr[i];
            sle = ssackb->seq - base_seq;
            sre = ssackb->nextseq - base_seq;

            if (ta_recv->triggered_by & TRIGGER_NEW_SACK_BLOCK) {
                item = proto_tree_add_bytes_format(sack_tree,
                    hf_tcp_option_sack_triggered_by_new_block, tvb, ssackb->offset, 8, NULL,
                    "Triggered by: New block (%u-%u) %s", sle, sre,
                    (tcp_relative_seq && tcp_analyze_seq) ? "(relative)" : "");
                PROTO_ITEM_SET_GENERATED(item);
            
            } else if (ta_recv->triggered_by & TRIGGER_SACK_BLOCK_UPDATE) {
                item = proto_tree_add_bytes_format(sack_tree, 
                    hf_tcp_option_sack_triggered_by_block_update, tvb, ssackb->offset, 8, NULL,
                    "Triggered by: Block update (%u-%u) %s", sle, sre,
                    (tcp_relative_seq && tcp_analyze_seq) ? "(relative)" : "");
                PROTO_ITEM_SET_GENERATED(item);
            
            } else if (ta_recv->triggered_by & TRIGGER_UNKNOWN) {
                item = proto_tree_add_bytes_format(sack_tree,
                    hf_tcp_option_sack_triggered_by_unknown, tvb, ssackb->offset, 8, NULL,
                    "Triggered by: Unknown reasons");
                PROTO_ITEM_SET_GENERATED(item);
            }
        }

        if (num_sackb_fr > 1) {
            /*
              Sort the SACK blocks included in this packet in ascending order for display in the next
              section. Unless this packet was triggered by a change in the ACK or new data sent by
              the receiver, the first block in the packet shows what block changed and triggered this
              packet. The order of the SACK blocks is preserved in Packet List but the blocks that
              appear in Packet Details are sorted and "Triggered by:" is also displayed. 
            */
            sort_sackb_fr(sackb_fr, num_sackb_fr, TRUE);
        }
    }

    /* Display the SACK blocks *included* in this packet. 
    */
    sacki2 = proto_tree_add_boolean_format(sack_tree, hf_tcp_option_included_sackblks, tvb, 
        offset, optlen, 1, "Included SACK blocks: ");
    included_blk_tree = proto_item_add_subtree(sacki2, ett_tcp_option_included_sackblks);

    for (i=0; i<num_sackb_fr; i++) { 
        sle = sackb_fr[i].sle - base_seq;
        sre = sackb_fr[i].sre - base_seq;
        if (!sackb_fr[i].dsack_blk)
            proto_item_append_text(sack_tree, " (%u-%u)", sle, sre);
        proto_item_append_text(included_blk_tree, " (%u-%u)", sle, sre);
        
        proto_tree_add_uint_format(included_blk_tree, hf_tcp_option_sack_sle, tvb, 
            sackb_fr[i].offset, 4, sle, "Left edge = %u%s%s", sle,
            ((tcp_relative_seq && tcp_analyze_seq) ? " (relative)" : ""),
            (sackb_fr[i].dsack_blk ? " (DSACK)" : ""));
        
        proto_tree_add_uint_format(included_blk_tree, hf_tcp_option_sack_sre, tvb,
            sackb_fr[i].offset+4, 4, sre, "Right edge = %u%s%s", sre,
            ((tcp_relative_seq && tcp_analyze_seq) ? " (relative)" : ""),
            (sackb_fr[i].dsack_blk ? " (DSACK)" : ""));
    }
    
    if(tcp_analyze_seq
    && tcpd->saved_sackb_l) { 
        if (tcpd->saved_sackb_l->invalid_blks) {
            proto_item_append_text(sack_tree, " [Invalid SACK range]");
            proto_item_append_text(included_blk_tree, " [Invalid SACK range]");
            /*
               FIX ME  1. there are two possibilities not one (see .h file)
                       2. display this block although invalid in the tree
            */
            item = proto_tree_add_none_format(included_blk_tree, hf_tcp_option_sack_invalid_block,
                tvb, 0, 0,
                "Invalid SACK block: "
                "The right edge of a SACK block is less than the ACK by more than one max window "
                "size.");
            PROTO_ITEM_SET_GENERATED(item);          
        } else {
            /*
              Display the list of *active* SACK blocks along with the gaps in this flow's byte stream.
              This list is made up of the blocks included in this packet along with those that remain  
              active because their ranges are greater than the ACK.    
            */
            sacki3 = proto_tree_add_boolean_format(sack_tree, hf_tcp_option_active_sackblks, 
                tvb, 0, 0, 1, "Active SACK blocks and gaps");
            PROTO_ITEM_SET_GENERATED(sacki3);
            active_blk_tree = proto_item_add_subtree(sacki3, ett_tcp_option_active_sackblks);

            num_ssackb = tcpd->saved_sackb_l->num_active_blks;
            item = proto_tree_add_uint_format(active_blk_tree, hf_tcp_option_sack_total_blocks, tvb,
                0, 0, num_ssackb, "Total blocks: %u", num_ssackb);
            PROTO_ITEM_SET_GENERATED(item);

            gap = tcpd->saved_sackb_l->arr[0].seq - ack;
            item = proto_tree_add_text(active_blk_tree, tvb, 0, 0,
                "ACK (%u) to Block 1  <%u byte gap>", ack - base_seq, gap);
            PROTO_ITEM_SET_GENERATED(item);
            totalgaps = gap; 
               
            for (j=0; j<num_ssackb; j++) {
                ssackb = &tcpd->saved_sackb_l->arr[j];
                sle = ssackb->seq - base_seq;
                sre = ssackb->nextseq - base_seq;
                proto_item_append_text(active_blk_tree, " (%u-%u)", sle, sre);
                gap = 0;
                if (j < num_ssackb-1) {
                    gap = tcpd->saved_sackb_l->arr[j+1].seq - tcpd->saved_sackb_l->arr[j].nextseq;
                    totalgaps += gap;
                }
                if (tcpd->saved_sackb_l->arr[j].offset == 0) {
                    item = proto_tree_add_bytes_format(active_blk_tree, hf_tcp_option_sack_block, tvb,
                        0, 8, ssackb->p_sackb_bytes,
                        "Block %u:  %u-%u %s", j+1, sle, sre, 
                        (tcp_relative_seq && tcp_analyze_seq) ? "(relative)" : "");
                    PROTO_ITEM_SET_GENERATED(item);
                } else {
                    item = proto_tree_add_bytes_format(active_blk_tree, hf_tcp_option_sack_block, tvb,
                        ssackb->offset, 8, NULL,
                        "Block %u:  %u-%u %s", j+1, sle, sre, 
                        (tcp_relative_seq && tcp_analyze_seq) ? "(relative)" : "");
                }
                if (gap > 0) {
                    proto_item_append_text(item, "  <%u byte gap>", gap);
                }
            }        
            rev_nextseq = tcpd->saved_sackb_l->rev_nextseq;
            if (GT_SEQ(rev_nextseq, tcpd->saved_sackb_l->arr[num_ssackb-1].nextseq)) {
                gap = rev_nextseq - tcpd->saved_sackb_l->arr[num_ssackb-1].nextseq;
                proto_item_append_text(item, "  <%u byte gap>  NextSeq (%u)", gap,
                    rev_nextseq - base_seq);
                totalgaps += gap;
            }

            tcp_analyze_get_ta_send_struct(pinfo->fd->num, FALSE, tcpd);
            if (!(tcpd->ta_send->flags & TCP_PREV_PACKET_UNSEEN)) {
                proto_item_append_text(active_blk_tree, ", Total Gaps: %u bytes", totalgaps);
                item = proto_tree_add_uint_format(active_blk_tree, hf_tcp_option_sack_total_gaps, tvb,
                    0, 0, totalgaps, "Total gaps: %u bytes", totalgaps);
                PROTO_ITEM_SET_GENERATED(item);
            } else {
                item = proto_tree_add_text(active_blk_tree, tvb, 0, 0, 
                    "Total gaps unknown because previous packet is missing");
                PROTO_ITEM_SET_GENERATED(item);
            }

            if (!tcpd->saved_sackb_l->rev_in_recovery) {
                gap = tcpd->saved_sackb_l->arr[num_ssackb-1].nextseq - ack;
                fgap_div_mss = (float)gap / tcpd->rev->s_mss;
                item = proto_tree_add_uint_format(active_blk_tree, hf_tcp_option_sack_ack_to_fack, tvb,
                    0, 0, gap, "ACK to snd.fack: %u bytes (divided by %s of %u = %.1f%s", gap,
                    (tcpd->mss_opt_seen ? "MSS" : "est. MSS"), tcpd->rev->s_mss, fgap_div_mss,
                    (fgap_div_mss > 3.0 ? ", enough to trigger a FACK retransmission)"
                                        : ", too small to trigger a FACK retransmission)"));
                PROTO_ITEM_SET_GENERATED(item);
            }
        }
    }
}

static void
dissect_tcpopt_echo(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
    proto_item *hidden_item;
    guint32 echo;

    echo = tvb_get_ntohl(tvb, offset + 2);
    hidden_item = proto_tree_add_boolean(opt_tree, hf_tcp_option_echo, tvb, offset,
                                         optlen, TRUE);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    proto_tree_add_text(opt_tree, tvb, offset,      optlen,
                        "%s: %u", optp->name, echo);
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s=%u ", "ECHO", echo);
}

static void
dissect_tcpopt_timestamp(const ip_tcp_opt *optp _U_, tvbuff_t *tvb,
    int offset, guint optlen _U_, packet_info *pinfo, proto_tree *opt_tree)
{
    proto_item *ti;
    proto_tree *ts_tree;
    guint32 ts_val, ts_ecr;
    proto_item *hidden_item;

    proto_item_append_text(opt_tree, ", Timestamps");    
    ti = proto_tree_add_boolean_format(opt_tree, hf_tcp_option_timestamps, tvb, offset, 10, 1, "Timestamps: ");
    ts_tree = proto_item_add_subtree(ti, ett_tcp_option_timestamps);

    hidden_item = proto_tree_add_item(ts_tree, hf_tcp_option_kind, tvb, offset, 1, ENC_NA);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    offset += 1;

    hidden_item = proto_tree_add_item(ts_tree, hf_tcp_option_len, tvb, offset, 1, ENC_NA);
    PROTO_ITEM_SET_HIDDEN(hidden_item); 
    offset += 1;

    proto_tree_add_item(ts_tree,  hf_tcp_option_timestamp_tsval, tvb, offset,
                        4, ENC_BIG_ENDIAN);
    ts_val = tvb_get_ntohl(tvb, offset);
    offset += 4;

    proto_tree_add_item(ts_tree,  hf_tcp_option_timestamp_tsecr, tvb, offset,
                        4, ENC_BIG_ENDIAN);
    ts_ecr = tvb_get_ntohl(tvb, offset);
    offset += 4;

    proto_item_append_text(ti, "TSval %u, TSecr %u", ts_val, ts_ecr);

    if (tcp_display_timestamps_in_summary) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s=%u", "TSval", ts_val);
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s=%u", "TSecr", ts_ecr);
    }
    
    if (tcp_analyze_seq) {
        struct tcp_analysis *tcpd;
        tcpd = get_tcp_conversation_data(NULL, pinfo);
        tcpd->ts_optlen = 12;
    }
}

static void
dissect_tcpopt_cc(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
    proto_item *hidden_item;
    guint32 cc;

    cc = tvb_get_ntohl(tvb, offset + 2);
    hidden_item = proto_tree_add_boolean(opt_tree, hf_tcp_option_cc, tvb, offset,
                                         optlen, TRUE);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    proto_tree_add_text(opt_tree, tvb, offset,      optlen,
                        "%s: %u", optp->name, cc);
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s=%u ", "CC", cc);
}

static void
dissect_tcpopt_qs(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
    /*
      Quick-Start TCP option, as defined by RFC4782
    */
    static const value_string qs_rates[] = {
        { 0, "0 bit/s"},
        { 1, "80 kbit/s"},
        { 2, "160 kbit/s"},
        { 3, "320 kbit/s"},
        { 4, "640 kbit/s"},
        { 5, "1.28 Mbit/s"},
        { 6, "2.56 Mbit/s"},
        { 7, "5.12 Mbit/s"},
        { 8, "10.24 Mbit/s"},
        { 9, "20.48 Mbit/s"},
        {10, "40.96 Mbit/s"},
        {11, "81.92 Mbit/s"},
        {12, "163.84 Mbit/s"},
        {13, "327.68 Mbit/s"},
        {14, "655.36 Mbit/s"},
        {15, "1.31072 Gbit/s"},
        {0, NULL}
    };

    static value_string_ext qs_rates_ext = VALUE_STRING_EXT_INIT(qs_rates);
    proto_item *hidden_item;
    guint8 rate = tvb_get_guint8(tvb, offset + 2) & 0x0f;
    hidden_item = proto_tree_add_boolean(opt_tree, hf_tcp_option_qs, tvb, offset,
                                         optlen, TRUE);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    proto_tree_add_text(opt_tree, tvb, offset,      optlen,
                        "%s: Rate response, %s, TTL diff %u ", optp->name,
                        val_to_str_ext(rate, &qs_rates_ext, "Unknown"),
                        tvb_get_guint8(tvb, offset + 3));
    col_append_fstr(pinfo->cinfo, COL_INFO, " QSresp=%s", val_to_str_ext(rate, &qs_rates_ext, "Unknown"));
}


static void
dissect_tcpopt_scps(const ip_tcp_opt *optp, tvbuff_t *tvb,
            int offset, guint optlen, packet_info *pinfo,
            proto_tree *opt_tree)
{
    struct tcp_analysis *tcpd;
    proto_tree *field_tree = NULL;
    tcp_flow_t *flow;
    int         direction;
    proto_item *tf = NULL, *hidden_item;
    gchar       flags[64] = "<None>";
    gchar      *fstr[] = {"BETS", "SNACK1", "SNACK2", "COMP", "NLTS", "RESV1", "RESV2", "RESV3"};
    gint        i, bpos;
    guint8      capvector;
    guint8      connid;

    tcpd = get_tcp_conversation_data(NULL,pinfo);

    /*
      Check direction and get ua lists
    */
    direction=CMP_ADDRESS(&pinfo->src, &pinfo->dst);

    /*
      If the addresses are equal, match the ports instead
    */
    if (direction == 0)
        direction= (pinfo->srcport > pinfo->destport) ? 1 : -1;

    if (direction>=0)
        flow =&(tcpd->flow1);
    else
        flow =&(tcpd->flow2);

    /*
       If the option length == 4, this is a real SCPS capability option
       See "CCSDS 714.0-B-2 (CCSDS Recommended Standard for SCPS Transport Protocol
       (SCPS-TP)" Section 3.2.3 for definition.
    */
    if (optlen == 4) {
        capvector = tvb_get_guint8(tvb, offset + 2);
        flags[0] = '\0';

        /*
          Decode the capabilities vector for display
        */
        for (i=0; i<5; i++) {
            bpos = 128 >> i;
            if (capvector & bpos) {
                if (flags[0]) {
                    g_strlcat(flags, ", ", 64);
                }
                g_strlcat(flags, fstr[i], 64);
            }
        }
        /*
          If lossless header compression is offered, there will be a
          single octet connectionId following the capabilities vector
        */
        if (capvector & 0x10)
            connid    = tvb_get_guint8(tvb, offset + 3);
        else
            connid    = 0;

        tf = proto_tree_add_uint_format(opt_tree, hf_tcp_option_scps_vector, tvb,
                                        offset, optlen, capvector,
                                        "%s: 0x%02x (%s)",
                                        optp->name, capvector, flags);
        hidden_item = proto_tree_add_boolean(opt_tree, hf_tcp_option_scps,
                                             tvb, offset, optlen, TRUE);
        PROTO_ITEM_SET_HIDDEN(hidden_item);

        field_tree = proto_item_add_subtree(tf, ett_tcp_option_scps);

        proto_tree_add_boolean(field_tree, hf_tcp_scpsoption_flags_bets, tvb,
                               offset + 13, 1, capvector);
        proto_tree_add_boolean(field_tree, hf_tcp_scpsoption_flags_snack1, tvb,
                               offset + 13, 1, capvector);
        proto_tree_add_boolean(field_tree, hf_tcp_scpsoption_flags_snack2, tvb,
                               offset + 13, 1, capvector);
        proto_tree_add_boolean(field_tree, hf_tcp_scpsoption_flags_compress, tvb,
                               offset + 13, 1, capvector);
        proto_tree_add_boolean(field_tree, hf_tcp_scpsoption_flags_nlts, tvb,
                               offset + 13, 1, capvector);
        proto_tree_add_boolean(field_tree, hf_tcp_scpsoption_flags_resv1, tvb,
                               offset + 13, 1, capvector);
        proto_tree_add_boolean(field_tree, hf_tcp_scpsoption_flags_resv2, tvb,
                               offset + 13, 1, capvector);
        proto_tree_add_boolean(field_tree, hf_tcp_scpsoption_flags_resv3, tvb,
                               offset + 13, 1, capvector);

        col_append_fstr(pinfo->cinfo, COL_INFO, "%s=%u ", "SCPS", flags);

        flow->scps_capable = 1;

        if (connid)
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s=%u ", "Connection ID", connid);
    }
    else {
        /*
           The option length != 4, so this is an infamous "extended capabilities
           option. See "CCSDS 714.0-B-2 (CCSDS Recommended Standard for SCPS
           Transport Protocol (SCPS-TP)" Section 3.2.5 for definition.

           As the format of this option is only partially defined (it is
           a community (or more likely vendor) defined format beyond that, so
           at least for now, we only parse the standardized portion of the option.
        */
        guint8 local_offset = 2;
        guint8 binding_space;
        guint8 extended_cap_length;

        if (flow->scps_capable != 1) {
            /*
              There was no SCPS capabilities option preceeding this
            */
            tf = proto_tree_add_uint_format(opt_tree, hf_tcp_option_scps_vector,
                                            tvb, offset, optlen, 0, "%s: (%d %s)",
                                            "Illegal SCPS Extended Capabilities",
                                            (optlen),
                                            "bytes");
        }
        else {
            tf = proto_tree_add_uint_format(opt_tree, hf_tcp_option_scps_vector,
                                            tvb, offset, optlen, 0, "%s: (%d %s)",
                                            "SCPS Extended Capabilities",
                                            (optlen),
                                            "bytes");
            field_tree=proto_item_add_subtree(tf, ett_tcp_option_scps_extended);
            /*
               There may be multiple binding spaces included in a single option,
               so we will semi-parse each of the stacked binding spaces - skipping
               over the octets following the binding space identifier and length.
            */
            while (optlen > local_offset) {
                /*
                  1st octet is Extended Capability Binding Space
                */
                binding_space = tvb_get_guint8(tvb, (offset + local_offset));
                /*
                   2nd octet (upper 4-bits) has binding space length in 16-bit words.
                   As defined by the specification, this length is exclusive of the
                   octets containing the extended capability type and length
                */
                extended_cap_length =
                    (tvb_get_guint8(tvb, (offset + local_offset + 1)) >> 4);
                /*
                  Convert the extended capabilities length into bytes for display
                */
                extended_cap_length = (extended_cap_length << 1);

                proto_tree_add_text(field_tree, tvb, offset + local_offset, 2,
                                    "\tBinding Space %u",
                                    binding_space);
                hidden_item = proto_tree_add_uint(field_tree, hf_tcp_option_scps_binding,
                                                  tvb, (offset + local_offset), 1,
                                                  binding_space);

                PROTO_ITEM_SET_HIDDEN(hidden_item);
                /*
                  Step past the binding space and length octets
                */
                local_offset += 2;

                proto_tree_add_text(field_tree, tvb, offset + local_offset,
                                    extended_cap_length,
                                    "\tBinding Space Data (%u bytes)",
                                    extended_cap_length);

                col_append_fstr(pinfo->cinfo, COL_INFO, "%s=%u ", "EXCAP", binding_space);

                /*
                   Step past the Extended capability data
                   Treat the extended capability data area as opaque;
                   If one desires to parse the extended capability data
                   (say, in a vendor aware build of wireshark), it would
                   be trigged here.
                */
                local_offset += extended_cap_length;
            }
        }
    }
}

static void
dissect_tcpopt_user_to(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
    proto_item *hidden_item, *tf;
    proto_tree *field_tree;
    gboolean g;
    guint16 to;

    g = tvb_get_ntohs(tvb, offset + 2) & 0x8000;
    to = tvb_get_ntohs(tvb, offset + 2) & 0x7FFF;
    hidden_item = proto_tree_add_boolean(opt_tree, hf_tcp_option_user_to, tvb, offset,
                                         optlen, TRUE);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    tf = proto_tree_add_uint_format(opt_tree, hf_tcp_option_user_to_val, tvb, offset,
                               optlen, to, "%s: %u %s", optp->name, to, g ? "minutes" : "seconds");
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    proto_tree_add_item(field_tree, hf_tcp_option_user_to_granularity, tvb, offset + 2, 2, FALSE);
    proto_tree_add_item(field_tree, hf_tcp_option_user_to_val, tvb, offset + 2, 2, FALSE);

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s=%u ", "USER_TO", to);
}

/*
   This is called for SYN+ACK packets and the purpose is to verify that
   the SCPS capabilities option has been successfully negotiated for the flow.
   If the SCPS capabilities option was offered by only one party, the
   proactively set scps_capable attribute of the flow (set upon seeing
   the first instance of the SCPS option) is revoked.
*/
static void
verify_scps(packet_info *pinfo,  proto_item *tf_syn, struct tcp_analysis *tcpd)
{
    tf_syn = 0x0;

    if (tcpd) {
        if ((!(tcpd->flow1.scps_capable)) || (!(tcpd->flow2.scps_capable))) {
            tcpd->flow1.scps_capable = 0;
            tcpd->flow2.scps_capable = 0;
        }
        else {
            expert_add_info_format(pinfo, tf_syn, PI_SEQUENCE, PI_NOTE,
                                   "Connection establish request (SYN-ACK): SCPS Capabilities Negotiated");
        }
    }
}

/*
   See "CCSDS 714.0-B-2 (CCSDS Recommended Standard for SCPS
   Transport Protocol (SCPS-TP)" Section 3.5 for definition of the SNACK option
*/
static void
dissect_tcpopt_snack(const ip_tcp_opt *optp, tvbuff_t *tvb,
            int offset, guint optlen, packet_info *pinfo,
            proto_tree *opt_tree)
{
    struct tcp_analysis *tcpd=NULL;
    guint16 relative_hole_offset;
    guint16 relative_hole_size;
    guint16 base_mss = 0;
    guint32 ack;
    guint32 hole_start;
    guint32 hole_end;
    char    null_modifier[] = "\0";
    char    relative_modifier[] = "(relative)";
    char   *modifier = null_modifier;
    proto_item *hidden_item;

    tcpd = get_tcp_conversation_data(NULL,pinfo);

    /* The SNACK option reports missing data with a granualarity of segments. */
    relative_hole_offset = tvb_get_ntohs(tvb, offset + 2);
    relative_hole_size = tvb_get_ntohs(tvb, offset + 4);

    hidden_item = proto_tree_add_boolean(opt_tree, hf_tcp_option_snack, tvb,
                                         offset, optlen, TRUE);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    hidden_item = proto_tree_add_uint(opt_tree, hf_tcp_option_snack_offset,
                                      tvb, offset, optlen, relative_hole_offset);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    hidden_item = proto_tree_add_uint(opt_tree, hf_tcp_option_snack_size,
                                      tvb, offset, optlen, relative_hole_size);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    proto_tree_add_text(opt_tree, tvb, offset, optlen,
                        "%s: Offset %u, Size %u", optp->name,
                        relative_hole_offset, relative_hole_size);

    ack   = tvb_get_ntohl(tvb, 8);

    if (tcp_relative_seq) {
        ack -= tcpd->rev->base_seq;
        modifier = relative_modifier;
    }
    /*
       To aid analysis, we can use a simple but generally effective heuristic
       to report the most likely boundaries of the missing data.  If the
       flow is scps_capable, we track the maximum sized segment that was
       acknowledged by the receiver and use that as the reporting granularity.
       This may be different from the negotiated MTU due to PMTUD or flows
       that do not send max-sized segments.
    */
    base_mss = tcpd->fwd->max_size_acked;

    if (base_mss) {
        /* Scale the reported offset and hole size by the largest segment acked */
        hole_start = ack + (base_mss * relative_hole_offset);
        hole_end   = hole_start + (base_mss * relative_hole_size);

        hidden_item = proto_tree_add_uint(opt_tree, hf_tcp_option_snack_le,
                                          tvb, offset, optlen, hole_start);
        PROTO_ITEM_SET_HIDDEN(hidden_item);

        hidden_item = proto_tree_add_uint(opt_tree, hf_tcp_option_snack_re,
                                          tvb, offset, optlen, hole_end);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        proto_tree_add_text(opt_tree, tvb, offset, optlen,
                            "\tMissing Sequence %u - %u %s",
                            hole_start, hole_end, modifier);

        col_append_fstr(pinfo->cinfo, COL_INFO, "%s=%u ", "SNLE", hole_start);
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s=%u ", "SNRE", hole_end);

        expert_add_info_format(pinfo, NULL, PI_SEQUENCE, PI_NOTE,
                               "SNACK Sequence %u - %u %s",
                               hole_start, hole_end, modifier);
    }
}

static void
dissect_tcpopt_mood(const ip_tcp_opt _U_*optp, tvbuff_t *tvb,
            int offset, guint optlen, packet_info *pinfo,
            proto_tree *opt_tree)
{
    /*
      Mood TCP option, as defined by RFC5841
    */
    static const string_string mood_type[] = {
        { ":)",  "Happy" },
        { ":(",  "Sad" },
        { ":D",  "Amused" },
        { "%(",  "Confused" },
        { ":o",  "Bored" },
        { ":O",  "Surprised" },
        { ":P",  "Silly" },
        { ":@",  "Frustrated" },
        { ">:@", "Angry" },
        { ":|",  "Apathetic" },
        { ";)",  "Sneaky" },
        { ">:)", "Evil" },
        { NULL, NULL }
    };

    proto_item *hidden_item;
    proto_item *mood_item;
    gchar *mood;
    mood = tvb_get_ephemeral_string(tvb, offset + 2, optlen-2);

    hidden_item = proto_tree_add_boolean(opt_tree, hf_tcp_option_mood, tvb, offset+2, optlen-2, TRUE);

    PROTO_ITEM_SET_HIDDEN(hidden_item);

    mood_item = proto_tree_add_string_format_value(opt_tree, hf_tcp_option_mood_val, tvb, offset+2, optlen-2, mood,"%s (%s)", mood, str_to_str(mood, mood_type, "Unknown") );
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s=%u ", "Mood", mood);

    expert_add_info_format(pinfo, mood_item, PI_PROTOCOL, PI_NOTE, "The packet Mood is %s (%s) (RFC 5841)", mood, str_to_str(mood, mood_type, "Unknown"));

}

enum
{
    PROBE_VERSION_UNSPEC = 0,
    PROBE_VERSION_1      = 1,
    PROBE_VERSION_2      = 2,
    PROBE_VERSION_MAX
};

/* Probe type definition. */
enum
{
    PROBE_QUERY          = 0,
    PROBE_RESPONSE       = 1,
    PROBE_INTERNAL       = 2,
    PROBE_TRACE          = 3,
    PROBE_QUERY_SH       = 4,
    PROBE_RESPONSE_SH    = 5,
    PROBE_QUERY_INFO     = 6,
    PROBE_RESPONSE_INFO  = 7,
    PROBE_QUERY_INFO_SH  = 8,
    PROBE_QUERY_INFO_SID = 9,
    PROBE_RST            = 10,
    PROBE_TYPE_MAX
};

static const value_string rvbd_probe_type_vs[] = {
    { PROBE_QUERY,          "Probe Query" },
    { PROBE_RESPONSE,       "Probe Response" },
    { PROBE_INTERNAL,       "Probe Internal" },
    { PROBE_TRACE,          "Probe Trace" },
    { PROBE_QUERY_SH,       "Probe Query SH" },
    { PROBE_RESPONSE_SH,    "Probe Response SH" },
    { PROBE_QUERY_INFO,     "Probe Query Info" },
    { PROBE_RESPONSE_INFO,  "Probe Response Info" },
    { PROBE_QUERY_INFO_SH,  "Probe Query Info SH" },
    { PROBE_QUERY_INFO_SID, "Probe Query Info Store ID" },
    { PROBE_RST,            "Probe Reset" },
    { 0, NULL }
};


#define PROBE_OPTLEN_OFFSET            1

#define PROBE_VERSION_TYPE_OFFSET      2
#define PROBE_V1_RESERVED_OFFSET       3
#define PROBE_V1_PROBER_OFFSET         4
#define PROBE_V1_APPLI_VERSION_OFFSET  8
#define PROBE_V1_PROXY_ADDR_OFFSET     8
#define PROBE_V1_PROXY_PORT_OFFSET    12
#define PROBE_V1_SH_CLIENT_ADDR_OFFSET 8
#define PROBE_V1_SH_PROXY_ADDR_OFFSET 12
#define PROBE_V1_SH_PROXY_PORT_OFFSET 16

#define PROBE_V2_INFO_OFFSET           3

#define PROBE_V2_INFO_CLIENT_ADDR_OFFSET 4
#define PROBE_V2_INFO_STOREID_OFFSET   4

#define PROBE_VERSION_MASK          0x01

/* Probe Query Extra Info flags */
#define RVBD_FLAGS_PROBE_LAST       0x01
#define RVBD_FLAGS_PROBE_NCFE       0x04

/* Probe Response Extra Info flags */
#define RVBD_FLAGS_PROBE_SERVER     0x01
#define RVBD_FLAGS_PROBE_SSLCERT    0x02
#define RVBD_FLAGS_PROBE            0x10

static void
rvbd_probe_decode_version_type(const guint8 vt, guint8 *ver, guint8 *type)
{
    if (vt & PROBE_VERSION_MASK) {
        *ver = PROBE_VERSION_1;
        *type = vt >> 4;
    } else {
        *ver = PROBE_VERSION_2;
        *type = vt >> 1;
    }
}

static void
rvbd_probe_resp_add_info(proto_item *pitem, packet_info *pinfo, guint32 ip, guint16 port)
{
    proto_item_append_text(pitem, ", Server Steelhead: %s:%u", ip_to_str((guint8 *)&ip), port);

    col_append_str(pinfo->cinfo, COL_INFO, "SA+, ");
}

static void
dissect_tcpopt_rvbd_probe(const ip_tcp_opt *optp _U_, tvbuff_t *tvb, int offset,
                          guint optlen, packet_info *pinfo, proto_tree *opt_tree)
{
    guint8 ver, type;
    proto_tree *field_tree;
    proto_item *pitem;

    rvbd_probe_decode_version_type(
        tvb_get_guint8(tvb, offset + PROBE_VERSION_TYPE_OFFSET),
        &ver, &type);

    pitem = proto_tree_add_boolean_format_value(
        opt_tree, hf_tcp_option_rvbd_probe, tvb, offset, optlen, 1,
        "%s", val_to_str(type, rvbd_probe_type_vs, "Probe Unknown"));

    if (type >= PROBE_TYPE_MAX)
        return;

    /* optlen, type, ver are common for all probes */
    field_tree = proto_item_add_subtree(pitem, ett_tcp_opt_rvbd_probe);
    proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_optlen, tvb,
                        offset + PROBE_OPTLEN_OFFSET, 1, FALSE);

    if (ver == PROBE_VERSION_1) {
        guint32 ip;
        guint16 port;

        proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_type1, tvb,
                            offset + PROBE_VERSION_TYPE_OFFSET, 1, FALSE);
        proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_version1, tvb,
                            offset + PROBE_VERSION_TYPE_OFFSET, 1, FALSE);

        if (type == PROBE_INTERNAL)
            return;
          
        proto_tree_add_text(field_tree, tvb, offset + PROBE_V1_RESERVED_OFFSET,
                            1, "Reserved");

        ip = tvb_get_ipv4(tvb, offset + PROBE_V1_PROBER_OFFSET);
        proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_prober, tvb,
                            offset + PROBE_V1_PROBER_OFFSET, 4, FALSE);

        switch (type) {

        case PROBE_QUERY:
        case PROBE_QUERY_SH:
        case PROBE_TRACE:
            proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_appli_ver, tvb,
                                offset + PROBE_V1_APPLI_VERSION_OFFSET, 2,
                                FALSE);

            proto_item_append_text(pitem, ", CSH IP: %s", ip_to_str((guint8 *)&ip));

            if (check_col(pinfo->cinfo, COL_INFO)) {
                /* Small look-ahead hack to distinguish S+ from S+* */
#define PROBE_V1_QUERY_LEN    10
                const guint8 qinfo_hdr[] = { 0x4c, 0x04, 0x0c };
                int not_cfe = 0;
                /*
                  tvb_memeql seems to be the only API that doesn't throw
                  an exception in case of an error
                */
                if (tvb_memeql(tvb, offset + PROBE_V1_QUERY_LEN,
                               qinfo_hdr, sizeof(qinfo_hdr)) == 0) {
                        not_cfe = tvb_get_guint8(tvb, offset + PROBE_V1_QUERY_LEN +
                                                 sizeof(qinfo_hdr)) & RVBD_FLAGS_PROBE_NCFE;
                }
                col_append_fstr(pinfo->cinfo, COL_INFO, "S%s, ",
                                 type == PROBE_TRACE ? "#" :
                                 not_cfe ? "+*" : "+");
           }
           break;

        case PROBE_RESPONSE:
            ip = tvb_get_ipv4(tvb, offset + PROBE_V1_PROXY_ADDR_OFFSET);
            proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_proxy, tvb,
                                offset + PROBE_V1_PROXY_ADDR_OFFSET, 4, FALSE);

            port = tvb_get_ntohs(tvb, offset + PROBE_V1_PROXY_PORT_OFFSET);
            proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_proxy_port, tvb,
                                offset + PROBE_V1_PROXY_PORT_OFFSET, 2, FALSE);

            rvbd_probe_resp_add_info(pitem, pinfo, ip, port);
            break;

        case PROBE_RESPONSE_SH:
            proto_tree_add_item(field_tree,
                                hf_tcp_option_rvbd_probe_client, tvb,
                                offset + PROBE_V1_SH_CLIENT_ADDR_OFFSET, 4,
                                FALSE);

            ip = tvb_get_ipv4(tvb, offset + PROBE_V1_SH_PROXY_ADDR_OFFSET);
            proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_proxy, tvb,
                                offset + PROBE_V1_SH_PROXY_ADDR_OFFSET, 4, FALSE);

            port = tvb_get_ntohs(tvb, offset + PROBE_V1_SH_PROXY_PORT_OFFSET);
            proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_proxy_port, tvb,
                                offset + PROBE_V1_SH_PROXY_PORT_OFFSET, 2, FALSE);

            rvbd_probe_resp_add_info(pitem, pinfo, ip, port);
            break;
        }
    }
    else if (ver == PROBE_VERSION_2) {
        proto_item *ver_pi;
        proto_item *flag_pi;
        proto_tree *flag_tree;
        guint8 flags;

        proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_type2, tvb,
                            offset + PROBE_VERSION_TYPE_OFFSET, 1, FALSE);

        proto_tree_add_uint_format_value(
            field_tree, hf_tcp_option_rvbd_probe_version2, tvb,
            offset + PROBE_VERSION_TYPE_OFFSET, 1, ver, "%u", ver);
        /*
          Use version1 for filtering purposes because version2 packet
          value is 0, but filtering is usually done for value 2
        */
        ver_pi = proto_tree_add_uint(field_tree, hf_tcp_option_rvbd_probe_version1, tvb,
                                     offset + PROBE_VERSION_TYPE_OFFSET, 1, ver);
        PROTO_ITEM_SET_HIDDEN(ver_pi);

        switch (type) {

        case PROBE_QUERY_INFO:
        case PROBE_QUERY_INFO_SH:
        case PROBE_QUERY_INFO_SID:
            flags = tvb_get_guint8(tvb, offset + PROBE_V2_INFO_OFFSET);
            flag_pi = proto_tree_add_uint(field_tree, hf_tcp_option_rvbd_probe_flags,
                                          tvb, offset + PROBE_V2_INFO_OFFSET,
                                          1, flags);

            flag_tree = proto_item_add_subtree(flag_pi, ett_tcp_opt_rvbd_probe_flags);
            proto_tree_add_item(flag_tree,
                                hf_tcp_option_rvbd_probe_flag_not_cfe,
                                tvb, offset + PROBE_V2_INFO_OFFSET, 1, FALSE);
            proto_tree_add_item(flag_tree,
                                hf_tcp_option_rvbd_probe_flag_last_notify,
                                tvb, offset + PROBE_V2_INFO_OFFSET, 1, FALSE);

            if (type == PROBE_QUERY_INFO_SH)
                proto_tree_add_item(flag_tree,
                                    hf_tcp_option_rvbd_probe_client, tvb,
                                    offset + PROBE_V2_INFO_CLIENT_ADDR_OFFSET,
                                    4, FALSE);
            else if (type == PROBE_QUERY_INFO_SID)
                proto_tree_add_item(flag_tree,
                                    hf_tcp_option_rvbd_probe_storeid, tvb,
                                    offset + PROBE_V2_INFO_STOREID_OFFSET,
                                    4, FALSE);

            if (type != PROBE_QUERY_INFO_SID &&
                check_col(pinfo->cinfo, COL_INFO) &&
                (tvb_get_guint8(tvb, 13) & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK) &&
                (flags & RVBD_FLAGS_PROBE_LAST)) {
                col_append_str(pinfo->cinfo, COL_INFO, "SA++, ");
            }

            break;

        case PROBE_RESPONSE_INFO:
            flag_pi = proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_flags,
                                          tvb, offset + PROBE_V2_INFO_OFFSET,
                                          1, FALSE);

            flag_tree = proto_item_add_subtree(flag_pi, ett_tcp_opt_rvbd_probe_flags);
            proto_tree_add_item(flag_tree,
                                hf_tcp_option_rvbd_probe_flag_probe_cache,
                                tvb, offset + PROBE_V2_INFO_OFFSET, 1, FALSE);
            proto_tree_add_item(flag_tree,
                                hf_tcp_option_rvbd_probe_flag_sslcert,
                                tvb, offset + PROBE_V2_INFO_OFFSET, 1, FALSE);
            proto_tree_add_item(flag_tree,
                                hf_tcp_option_rvbd_probe_flag_server_connected,
                                tvb, offset + PROBE_V2_INFO_OFFSET, 1, FALSE);
            break;

        case PROBE_RST:
            flag_pi = proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_flags,
                                  tvb, offset + PROBE_V2_INFO_OFFSET,
                                  1, FALSE);
            break;
        }
    }
}

enum {
    TRPY_OPTNUM_OFFSET        = 0,
    TRPY_OPTLEN_OFFSET        = 1,

    TRPY_OPTIONS_OFFSET       = 2,
    TRPY_SRC_ADDR_OFFSET      = 4,
    TRPY_DST_ADDR_OFFSET      = 8,
    TRPY_SRC_PORT_OFFSET      = 12,
    TRPY_DST_PORT_OFFSET      = 14,
    TRPY_CLIENT_PORT_OFFSET   = 16,
};

/*
  Trpy Flags
*/
#define RVBD_FLAGS_TRPY_MODE         0x0001
#define RVBD_FLAGS_TRPY_OOB          0x0002
#define RVBD_FLAGS_TRPY_CHKSUM       0x0004
#define RVBD_FLAGS_TRPY_FW_RST       0x0100
#define RVBD_FLAGS_TRPY_FW_RST_INNER 0x0200
#define RVBD_FLAGS_TRPY_FW_RST_PROBE 0x0400

static const true_false_string trpy_mode_str = {
    "Port Transparency",
    "Full Transparency"
};

static void
dissect_tcpopt_rvbd_trpy(const ip_tcp_opt *optp _U_, tvbuff_t *tvb,
                        int offset, guint optlen, packet_info *pinfo,
                        proto_tree *opt_tree)
{
    proto_tree *field_tree;
    proto_tree *flag_tree;
    proto_item *pitem;
    proto_item *flag_pi;
    guint32 src, dst;
    guint16 sport, dport, flags;
    static dissector_handle_t sport_handle = NULL;

    col_append_str(pinfo->cinfo, COL_INFO, "TRPY, ");

    pitem = proto_tree_add_boolean_format_value(
        opt_tree, hf_tcp_option_rvbd_trpy, tvb, offset, optlen, 1,
        "%s", "");

    field_tree = proto_item_add_subtree(pitem, ett_tcp_opt_rvbd_trpy);
    proto_tree_add_item(field_tree, hf_tcp_option_rvbd_probe_optlen, tvb,
                        offset + PROBE_OPTLEN_OFFSET, 1, FALSE);

    flags = tvb_get_ntohs(tvb, offset + TRPY_OPTIONS_OFFSET);
    flag_pi = proto_tree_add_item(field_tree, hf_tcp_option_rvbd_trpy_flags,
                                  tvb, offset + TRPY_OPTIONS_OFFSET,
                                  2, FALSE);

    flag_tree = proto_item_add_subtree(flag_pi, ett_tcp_opt_rvbd_trpy_flags);
    proto_tree_add_item(flag_tree, hf_tcp_option_rvbd_trpy_flag_fw_rst_probe,
                        tvb, offset + TRPY_OPTIONS_OFFSET, 2, FALSE);
    proto_tree_add_item(flag_tree, hf_tcp_option_rvbd_trpy_flag_fw_rst_inner,
                        tvb, offset + TRPY_OPTIONS_OFFSET, 2, FALSE);
    proto_tree_add_item(flag_tree, hf_tcp_option_rvbd_trpy_flag_fw_rst,
                        tvb, offset + TRPY_OPTIONS_OFFSET, 2, FALSE);
    proto_tree_add_item(flag_tree, hf_tcp_option_rvbd_trpy_flag_chksum,
                        tvb, offset + TRPY_OPTIONS_OFFSET, 2, FALSE);
    proto_tree_add_item(flag_tree, hf_tcp_option_rvbd_trpy_flag_oob,
                        tvb, offset + TRPY_OPTIONS_OFFSET, 2, FALSE);
    proto_tree_add_item(flag_tree, hf_tcp_option_rvbd_trpy_flag_mode,
                        tvb, offset + TRPY_OPTIONS_OFFSET, 2, FALSE);

    src = tvb_get_ipv4(tvb, offset + TRPY_SRC_ADDR_OFFSET);
    proto_tree_add_item(field_tree, hf_tcp_option_rvbd_trpy_src,
                        tvb, offset + TRPY_SRC_ADDR_OFFSET, 4, FALSE);

    dst = tvb_get_ipv4(tvb, offset + TRPY_DST_ADDR_OFFSET);
    proto_tree_add_item(field_tree, hf_tcp_option_rvbd_trpy_dst,
                        tvb, offset + TRPY_DST_ADDR_OFFSET, 4, FALSE);

    sport = tvb_get_ntohs(tvb, offset + TRPY_SRC_PORT_OFFSET);
    proto_tree_add_item(field_tree, hf_tcp_option_rvbd_trpy_src_port,
                        tvb, offset + TRPY_SRC_PORT_OFFSET, 2, FALSE);

    dport = tvb_get_ntohs(tvb, offset + TRPY_DST_PORT_OFFSET);
    proto_tree_add_item(field_tree, hf_tcp_option_rvbd_trpy_dst_port,
                        tvb, offset + TRPY_DST_PORT_OFFSET, 2, FALSE);

    proto_item_append_text(pitem, "%s:%u -> %s:%u",
                           ip_to_str((guint8 *)&src), sport,
                           ip_to_str((guint8 *)&dst), dport);

    /* Client port only set on SYN: optlen == 18 */
    if ((flags & RVBD_FLAGS_TRPY_OOB) && (optlen > TCPOLEN_RVBD_TRPY_MIN))
        proto_tree_add_item(field_tree, hf_tcp_option_rvbd_trpy_client_port,
                            tvb, offset + TRPY_CLIENT_PORT_OFFSET, 2, FALSE);
    /*
       We need to map this TCP session on our own dissector instead of what
       Wireshark thinks runs on these ports
    */
    if (sport_handle == NULL) {
        sport_handle = find_dissector("sport");
    }
    if (sport_handle != NULL) {
        conversation_t *conversation;
        conversation = find_conversation(pinfo->fd->num,
            &pinfo->src, &pinfo->dst, pinfo->ptype,
            pinfo->srcport, pinfo->destport, 0);
        if (conversation == NULL) {
            conversation = conversation_new(pinfo->fd->num,
                &pinfo->src, &pinfo->dst, pinfo->ptype,
                pinfo->srcport, pinfo->destport, 0);
        }
        if (conversation->dissector_handle != sport_handle) {
            conversation_set_dissector(conversation, sport_handle);
        }
    }
}

static const ip_tcp_opt tcpopts[] = {
    {
        TCPOPT_EOL,
        "End of Option List (EOL)",
        NULL,
        NO_LENGTH,
        0,
        NULL,
    },
    {
        TCPOPT_NOP,
        "No-Operation (NOP)",
        NULL,
        NO_LENGTH,
        0,
        NULL,
    },
    {
        TCPOPT_MSS,
        "Maximum segment size",
        NULL,
        FIXED_LENGTH,
        TCPOLEN_MSS,
        dissect_tcpopt_mss
    },
    {
        TCPOPT_WINDOW,
        "Window scale",
        NULL,
        FIXED_LENGTH,
        TCPOLEN_WINDOW,
        dissect_tcpopt_wscale
    },
    {
        TCPOPT_SACK_PERM,
        "SACK permitted",
        NULL,
        FIXED_LENGTH,
        TCPOLEN_SACK_PERM,
        dissect_tcpopt_sack_perm,
    },
    {
        TCPOPT_SACK,
        "SACK",
        &ett_tcp_option_sack,
        VARIABLE_LENGTH,
        TCPOLEN_SACK_MIN,
        dissect_tcpopt_sack
    },
    {
        TCPOPT_ECHO,
        "Echo",
        NULL,
        FIXED_LENGTH,
        TCPOLEN_ECHO,
        dissect_tcpopt_echo
    },
    {
        TCPOPT_ECHOREPLY,
        "Echo reply",
        NULL,
        FIXED_LENGTH,
        TCPOLEN_ECHOREPLY,
        dissect_tcpopt_echo
    },
    {
        TCPOPT_TIMESTAMP,
        "Timestamps",
        NULL,
        FIXED_LENGTH,
        TCPOLEN_TIMESTAMP,
        dissect_tcpopt_timestamp
    },
    {
        TCPOPT_CC,
        "CC",
        NULL,
        FIXED_LENGTH,
        TCPOLEN_CC,
        dissect_tcpopt_cc
    },
    {
        TCPOPT_CCNEW,
        "CC.NEW",
        NULL,
        FIXED_LENGTH,
        TCPOLEN_CCNEW,
        dissect_tcpopt_cc
    },
    {
        TCPOPT_CCECHO,
        "CC.ECHO",
        NULL,
        FIXED_LENGTH,
        TCPOLEN_CCECHO,
        dissect_tcpopt_cc
    },
    {
        TCPOPT_MD5,
        "TCP MD5 signature",
        NULL,
        FIXED_LENGTH,
        TCPOLEN_MD5,
        NULL
    },
    {
        TCPOPT_SCPS,
        "SCPS capabilities",
        &ett_tcp_option_scps,
        VARIABLE_LENGTH,
        TCPOLEN_SCPS,
        dissect_tcpopt_scps
    },
    {
        TCPOPT_SNACK,
        "Selective Negative Acknowledgement",
        NULL,
        FIXED_LENGTH,
        TCPOLEN_SNACK,
        dissect_tcpopt_snack
    },
    {
        TCPOPT_RECBOUND,
        "SCPS record boundary",
        NULL,
        FIXED_LENGTH,
        TCPOLEN_RECBOUND,
        NULL
    },
    {
        TCPOPT_CORREXP,
        "SCPS corruption experienced",
        NULL,
        FIXED_LENGTH,
        TCPOLEN_CORREXP,
        NULL
    },
    {
        TCPOPT_MOOD,
        "Packet Mood",
        NULL,
        VARIABLE_LENGTH,
        TCPOLEN_MOOD_MIN,
        dissect_tcpopt_mood
    },
    {
        TCPOPT_QS,
        "Quick-Start",
        NULL,
        FIXED_LENGTH,
        TCPOLEN_QS,
        dissect_tcpopt_qs
    },
    {
        TCPOPT_USER_TO,
        "User Timeout",
        &ett_tcp_option_user_to,
        FIXED_LENGTH,
        TCPOLEN_USER_TO,
        dissect_tcpopt_user_to
  },
  {
        TCPOPT_RVBD_PROBE,
        "Riverbed Probe",
        NULL,
        VARIABLE_LENGTH,
        TCPOLEN_RVBD_PROBE_MIN,
        dissect_tcpopt_rvbd_probe
  },
  {
        TCPOPT_RVBD_TRPY,
        "Riverbed Transparency",
        NULL,
        FIXED_LENGTH,
        TCPOLEN_RVBD_TRPY_MIN,
        dissect_tcpopt_rvbd_trpy
        }
};

#define N_TCP_OPTS  (sizeof tcpopts / sizeof tcpopts[0])

/* Determine if there is a sub-dissector and call it; return TRUE
   if there was a sub-dissector, FALSE otherwise.

   This has been separated into a stand alone routine to other protocol
   dissectors can call to it, e.g., SOCKS. */

/* this function can be called with tcpd == NULL as from the msproxy dissector */
gboolean
decode_tcp_ports(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, int src_port, int dst_port,
    struct tcp_analysis *tcpd)
{
    tvbuff_t *next_tvb;
    int low_port, high_port;
    int save_desegment_offset;
    guint32 save_desegment_len;
    /*
      Dont call subdissectors for keepalive or zerowindowprobes
      even though they do contain payload "data"
      keeaplives just contain garbage and contain too little data (1 byte)
      so why bother.
     */
    if (tcpd->ta_send) {
        if (tcpd->ta_send->flags & (TCP_ZERO_WINDOW_PROBE | TCP_KEEP_ALIVE)) {
            return TRUE;
        }
    }

    next_tvb = tvb_new_subset_remaining(tvb, offset);

    /*
      Determine if this packet is part of a conversation and call dissector
      for the conversation if available
    */
    if (try_conversation_dissector(&pinfo->src, &pinfo->dst, PT_TCP,
                                   src_port, dst_port, next_tvb, pinfo, tree)) {
        pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
        return TRUE;
    }

    if (try_heuristic_first) {
        /* do lookup with the heuristic subdissector table */
        save_desegment_offset = pinfo->desegment_offset;
        save_desegment_len = pinfo->desegment_len;
        if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree)) {
            pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
            return TRUE;
        }
        /*
          They rejected the packet; make sure they didn't also request
          desegmentation (we could just override the request, but
          rejecting a packet *and* requesting desegmentation is a sign
          of the dissector's code needing clearer thought, so we fail
          so that the problem is made more obvious).
        */
        DISSECTOR_ASSERT(save_desegment_offset == pinfo->desegment_offset &&
                         save_desegment_len == pinfo->desegment_len);
    }
    /*
       Do lookups with the subdissector table.
       We try the port number with the lower value first, followed by the
       port number with the higher value.  This means that, for packets
       where a dissector is registered for *both* port numbers:

       1) we pick the same dissector for traffic going in both directions;

       2) we prefer the port number that's more likely to be the right
       one (as that prefers well-known ports to reserved ports);

       although there is, of course, no guarantee that any such strategy
       will always pick the right port number.

       XXX - we ignore port numbers of 0, as some dissectors use a port
       number of 0 to disable the port.
    */
    if (src_port > dst_port) {
        low_port = dst_port;
        high_port = src_port;
    } else {
        low_port = src_port;
        high_port = dst_port;
    }
    if (low_port != 0 &&
        dissector_try_uint(subdissector_table, low_port, next_tvb, pinfo, tree)) {
        pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
        return TRUE;
    }
    if (high_port != 0 &&
        dissector_try_uint(subdissector_table, high_port, next_tvb, pinfo, tree)) {
        pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
        return TRUE;
    }

    if (!try_heuristic_first) {
        /* do lookup with the heuristic subdissector table */
        save_desegment_offset = pinfo->desegment_offset;
        save_desegment_len = pinfo->desegment_len;
        if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree)) {
            pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
            return TRUE;
        }
        /*
          They rejected the packet; make sure they didn't also request
          desegmentation (we could just override the request, but
          rejecting a packet *and* requesting desegmentation is a sign
          of the dissector's code needing clearer thought, so we fail
          so that the problem is made more obvious).
        */
        DISSECTOR_ASSERT(save_desegment_offset == pinfo->desegment_offset &&
                         save_desegment_len == pinfo->desegment_len);
    }

    /*
      Oh, well, we don't know this; dissect it as data.
    */
    call_dissector(data_handle,next_tvb, pinfo, tree);

    pinfo->want_pdu_tracking -= !!(pinfo->want_pdu_tracking);
    return FALSE;
}

static void
process_tcp_payload(tvbuff_t *tvb, volatile int offset, packet_info *pinfo,
    proto_tree *tree, proto_tree *tcp_tree, int src_port, int dst_port,
    guint32 seq, guint32 nxtseq, guint32 ack, guint32 win, 
    gboolean is_tcp_segment, struct tcp_analysis *tcpd)
{
    pinfo->want_pdu_tracking=0;

    TRY {
        if (is_tcp_segment) {
            /*qqq   see if it is an unaligned PDU */
            if(tcpd 
            && tcp_analyze_seq
            && !tcp_desegment) {
                if (seq > 0 || nxtseq > 0) {
                    offset=scan_for_next_pdu(tvb, tcp_tree, pinfo, offset,
                        seq, nxtseq, tcpd->fwd->multisegment_pdus);
                }
            }
        }
        /*
           If offset is -1 this means that this segment is known
           to be fully inside a previously detected pdu
           so we dont even need to try to dissect it either.
        */
        if(offset != -1
        && decode_tcp_ports(tvb, offset, pinfo, tree, src_port, dst_port, tcpd)) {
            /*
               We succeeded in handing off to a subdissector.
               Is this a TCP segment or a reassembled chunk of
               TCP payload?
            */
            if (is_tcp_segment) {
                /*
                  If !visited, check want_pdu_tracking and
                  store it in table 
                */
                if(tcpd 
                && !pinfo->fd->flags.visited 
                && tcp_analyze_seq
                && pinfo->want_pdu_tracking) {
                    if (seq > 0  || nxtseq > 0) {
                        pdu_store_sequencenumber_of_next_pdu(
                            pinfo,
                            seq,
                            nxtseq+pinfo->bytes_until_next_pdu,
                            tcpd->fwd->multisegment_pdus);
                    }
                }
            }
        }
    }
    CATCH_ALL {
        /*
           We got an exception. At this point the dissection is
           completely aborted and execution will be transfered back
           to (probably) the frame dissector.
           Here we have to place whatever we want the dissector
           to do before aborting the tcp dissection.

           Is this a TCP segment or a reassembled chunk of TCP
           payload?
        */
        if (is_tcp_segment) {
            /*
               It's from a TCP segment.

               if !visited, check want_pdu_tracking and store it
               in table
            */
            if(tcpd 
            && !pinfo->fd->flags.visited
            && tcp_analyze_seq
            && pinfo->want_pdu_tracking) {
                if (seq > 0  || nxtseq > 0) {
                    pdu_store_sequencenumber_of_next_pdu(pinfo,
                        seq,
                        nxtseq+pinfo->bytes_until_next_pdu,
                        tcpd->fwd->multisegment_pdus);
                }
            }
        }
        RETHROW;
    }
    ENDTRY;
}

void
dissect_tcp_payload(tvbuff_t *tvb, packet_info *pinfo, int offset, guint32 seq,
            guint32 nxtseq, guint32 ack, guint32 win, guint32 sport, guint32 dport,
            proto_tree *tree, proto_tree *tcp_tree,
            struct tcp_analysis *tcpd)
{
    gboolean save_fragmented;

    /*
      Can we desegment this segment?
    */
    if (pinfo->can_desegment) {
        /* Yes. */
        desegment_tcp(tvb, pinfo, offset, seq, nxtseq, ack, win, sport, dport, tree,
                      tcp_tree, tcpd);
    } else {
        /*
           No - just call the subdissector.
           Mark this as fragmented, so if somebody throws an exception,
           we don't report it as a malformed frame.
        */
        save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;
        process_tcp_payload(tvb, offset, pinfo, tree, tcp_tree, sport, dport,
                            seq, nxtseq, ack, win, TRUE, tcpd);
        pinfo->fragmented = save_fragmented;
    }
}

static void
dissect_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    const gchar *flags[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECN", "CWR", "NS"};
    int      offset = 0;  
    gint     i;
    guint    bpos, optlen=0, reported_len, length_remaining;
    guint8   th_off_x2; /* combines th_off and th_x2 */
    guint16  th_sum, th_urp, computed_cksum, real_window;
    guint32  phdr[2], nxtseq=0;
    gboolean desegment_ok, old_seq=FALSE, first_flag;
    struct tcp_analysis *tcpd=NULL;
    struct tcpinfo tcpinfo;
    struct tcpheader *tcph;
    tcp_per_packet_data_t *tcppd=NULL;
    ta_send_t *ta_send=NULL;
    ta_recv_t *ta_recv=NULL;
    tcp_rxmtinfo_t *rxmtinfo=NULL;
    vec_t    cksum_vec[4];    
    conversation_t *conv=NULL;
    proto_item *item, *ti=NULL, *tf=NULL, *seqi=NULL, *acki=NULL, *chki=NULL, *chki2=NULL, *wini=NULL, *opti=NULL;
    proto_item *tf_syn=NULL, *tf_fin=NULL, *tf_rst=NULL;
    proto_tree *tcp_tree=NULL, *sequence_tree=NULL, *ack_tree=NULL;
    proto_tree *flags_tree=NULL, *window_tree=NULL, *checksum_tree=NULL, *options_tree=NULL;
    proto_tree *process_tree=NULL, *hidden_item=NULL;
    emem_strbuf_t *flags_strbuf = ep_strbuf_new_label("<None>");

    tcph=ep_alloc(sizeof(struct tcpheader));
    SET_ADDRESS(&tcph->ip_src, pinfo->src.type, pinfo->src.len, pinfo->src.data);
    SET_ADDRESS(&tcph->ip_dst, pinfo->dst.type, pinfo->dst.len, pinfo->dst.data);

    pinfo->ptype = PT_TCP;
    tcph->th_sport = tvb_get_ntohs(tvb, offset);
    tcph->th_dport = tvb_get_ntohs(tvb, offset + 2);
    /*
       Set the source and destination port numbers as soon as we get them,
       so that they're available to the "Follow TCP Stream" code even if
       we throw an exception dissecting the rest of the TCP header.
    */
    pinfo->srcport = tcph->th_sport;
    pinfo->destport = tcph->th_dport;
    tcph->th_seq = tvb_get_ntohl(tvb, offset + 4);
    tcph->th_ack = tvb_get_ntohl(tvb, offset + 8);
    th_off_x2 = tvb_get_guint8(tvb, offset + 12);
    tcph->th_flags = tvb_get_ntohs(tvb, offset + 12) & 0x01FF;
    tcph->th_win = tvb_get_ntohs(tvb, offset + 14);
    real_window = tcph->th_win;
    tcph->th_hlen = hi_nibble(th_off_x2) * 4;  /* TCP header length, in bytes */
    /*
       find(or create if needed) the conversation for this tcp session
    */
    conv = find_or_create_conversation(pinfo);
    tcpd = get_tcp_conversation_data(conv, pinfo);

    if (!tcpd) {
        REPORT_DISSECTOR_BUG(
            "dissect_tcp(): The tcpd struct could not be created.");
        return;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCP");
    col_clear(pinfo->cinfo, COL_INFO);
    
    if (display_ports_in_packet_list)
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "%s > %s ", get_tcp_port(tcph->th_sport), get_tcp_port(tcph->th_dport));
    col_set_fence(pinfo->cinfo, COL_INFO);

    if (tree) {
        if (summary_in_tcp_tree_header) {
            if (prefs.name_resolve & RESOLV_TRANSPORT) {
                ti = proto_tree_add_protocol_format(tree, proto_tcp, tvb, 0, -1,
                    "Transmission Control Protocol  Src Port: %s (%u)  Dst Port: %s (%u)  ",
                    get_tcp_port(tcph->th_sport), tcph->th_sport,
                    get_tcp_port(tcph->th_dport), tcph->th_dport);
            } else {
                ti = proto_tree_add_protocol_format(tree, proto_tcp, tvb, 0, -1,
                    "Transmission Control Protocol  Src Port: %u  Dst Port: %u  ", tcph->th_sport, tcph->th_dport);
            }
        } else {
            ti = proto_tree_add_item(tree, proto_tcp, tvb, 0, -1, FALSE);
        }
        tcp_tree = proto_item_add_subtree(ti, ett_tcp);
        pinfo->tcp_tree = tcp_tree;

        /* Source and Destination Ports */
        if (prefs.name_resolve & RESOLV_TRANSPORT) {
            proto_tree_add_uint_format(tcp_tree, hf_tcp_srcport, tvb, offset, 2, tcph->th_sport,
                                        "Source port: %s (%u)", get_tcp_port(tcph->th_sport), tcph->th_sport);
            proto_tree_add_uint_format(tcp_tree, hf_tcp_dstport, tvb, offset + 2, 2, tcph->th_dport,
                                        "Destination port: %s (%u)", get_tcp_port(tcph->th_dport), tcph->th_dport);
        } else {
            proto_tree_add_uint_format(tcp_tree, hf_tcp_srcport, tvb, offset, 2, tcph->th_sport,
                                        "Source port: %u", tcph->th_sport);
            proto_tree_add_uint_format(tcp_tree, hf_tcp_dstport, tvb, offset + 2, 2, tcph->th_dport,
                                        "Destination port: %u", tcph->th_dport);
        }
        hidden_item = proto_tree_add_uint(tcp_tree, hf_tcp_port, tvb, offset, 2, tcph->th_sport);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        hidden_item = proto_tree_add_uint(tcp_tree, hf_tcp_port, tvb, offset + 2, 2, tcph->th_dport);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        
        /* Stream index */
        item = proto_tree_add_uint(tcp_tree, hf_tcp_stream, tvb, offset, 0, conv->index);
        PROTO_ITEM_SET_GENERATED(item);

        /*
          Header length
        */
        if (tcph->th_hlen >= TCPH_MIN_LEN) {
            proto_tree_add_uint_format(tcp_tree, hf_tcp_hdr_len, tvb, offset + 12, 1, tcph->th_hlen,
                "Header length: %u bytes", tcph->th_hlen);
        } else {
            /*
               The source and destination ports were displayed in the tree before fetching the header length,
               so that they'll show up if this is in the failing packet of an ICMP error packet, but if the 
               header length is bogus, it's time to give up.
            */
            col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, 
                "[Bogus TCP header length %u, must be at least %u] ", tcph->th_hlen, TCPH_MIN_LEN);
            if (tree)
                proto_tree_add_uint_format( tcp_tree, hf_tcp_hdr_len, tvb, offset + 12, 1, tcph->th_hlen,
                    "Header length: %u bytes is bogus. It must be at least %u bytes)",
                    tcph->th_hlen, TCPH_MIN_LEN);
            return;
        }

        /*
          If we're dissecting the headers of a TCP packet in an ICMP packet then go ahead and put the
          sequence numbers in Packet Details now (because they won't be put in later because the ICMP
          ICMP packet only contains up to the sequence number). We should only need to do this for
          IPv4 since IPv6 will hopefully carry enough TCP payload for this dissector to put the
          sequence numbers in via the regular code path.
        */
        if (pinfo->layer_names != NULL && pinfo->layer_names->str != NULL) {
            /*
              Use strstr because g_strrstr is only present in glib2.0 and
              g_str_has_suffix in glib2.2
            */
            if (strstr(pinfo->layer_names->str, "icmp:ip") != NULL)
                proto_tree_add_item(tcp_tree, hf_tcp_seq, tvb, offset + 4, 4, FALSE);
        }
    }

    if (!tcpd->ta_send)
        tcp_analyze_get_ta_send_struct(pinfo->fd->num, TRUE, tcpd);        
    ta_send = tcpd->ta_send;

    /*
       Calculate delta time info
    */
    if (tcp_calculate_ts) {
        tcppd = p_get_proto_data(pinfo->fd, proto_tcp);
        if (!(pinfo->fd->flags.visited)) {
            if ( !tcppd ) {
                tcppd = se_alloc(sizeof(struct tcp_per_packet_data_t));
                p_add_proto_data(pinfo->fd, proto_tcp, tcppd);
                tcppd->bif = 0;
                tcppd->unacked = 0;
                tcppd->display_ack = FALSE;
            }
         tcp_calc_delta_time_info(pinfo, tcpd, tcppd);
       }
    }
    /*
       If we've been handed an IP fragment, we don't know how big the TCP
       segment is, so don't do anything that requires that we know that.

       The same applies if we're part of an error packet.  (XXX - if the
       ICMP and ICMPv6 dissectors could set a "this is how big the IP
       header says it is" length in the tvbuff, we could use that; such
       a length might also be useful for handling packets where the IP
       length is bigger than the actual data available in the frame; the
       dissectors should trust that length, and then throw a
       ReportedBoundsError exception when they go past the end of the frame.)

       We also can't determine the segment length if the reported length
       of the TCP packet is less than the TCP header length.
    */
    reported_len = tvb_reported_length(tvb);
    
    if (!pinfo->fragmented && !pinfo->in_error_pkt) {
        if (reported_len < tcph->th_hlen) {
            if (tree) {
                proto_item *pi;
                pi = proto_tree_add_text(tcp_tree, tvb, offset, 0,
                    "Short segment. Segment/fragment does not contain a full TCP header\n"
                    "(frames might have been sliced too short, NMAP, or host deliberately sent unusual packets)");
                PROTO_ITEM_SET_GENERATED(pi);
                expert_add_info_format(pinfo, pi, PI_MALFORMED, PI_WARN, "Short segment");
            }
        } else {
            /* Compute the length of this segment. */
            if((tcph->th_flags & TH_SYN)
            || ((tcph->th_flags & TH_FIN) && reported_len - tcph->th_hlen == 0)) {
                tcph->th_seglen = 1;
                tcpd->fwd->seglen = 1;
            } else {
                tcph->th_seglen = reported_len - tcph->th_hlen;
                tcpd->fwd->seglen = tcph->th_seglen;
            }
            if (GE_SEQ(tcph->th_ack, tcpd->fwd->highest_ack)) {
                tcpd->fwd->prior_highest_ack = tcpd->fwd->highest_ack;
                tcpd->fwd->highest_ack = tcph->th_ack;
            }
            /*
              If this is the first pass, load the options info so that they can be displayed in the second
              pass and (2) tcp_analyze_sequence_number() can use the SACK info.
            */
            if (!pinfo->fd->flags.visited) {
                /*
                   Decode TCP options provided that options such as SACK have not been truncated (sliced off).
                */
                if (tcph->th_hlen > TCPH_MIN_LEN) {
                    guint bc = (guint)tvb_length_remaining(tvb, offset + 20);
                    
                    optlen = MIN(bc, (guint)tcph->th_hlen - TCPH_MIN_LEN); /* length of options, in bytes */

                    if (optlen) {
                        tcpd->saved_sackb_l = NULL;

                        /* dissect_ip_tcp_options() must be called in both passes because it displays info in the 
                           Packet List with col_append_fstr() and in order for that info to be searchable in the
                           COL_INFO column, col_append_fstr() has to be called in both passes.
                        */ 
                        dissect_ip_tcp_options(tvb, offset + 20, optlen,
                            tcpopts, N_TCP_OPTS, TCPOPT_EOL, pinfo, options_tree, tf);

                        /* NOTE: If *both* the SYN and SYN-ACK packets in this connection were captured, neither
                                 Window Scale Factor (WSF) was truncated or omitted indicating that the
                                 host did not support RFC 1323 window scaling, tcpd->wsf_announced is set to TRUE.
                                 The scale factors of each flow, which are permitted to differ, are applied to all
                                 the windows except those in the SYN and SYN-ACK packets. 
                     
                                 If a flow with the SYN flag omitted the WSF option, according to RFC 1323 while
                                 the opposite was permitted to specify a WSF it must be ignored. For this reason
                                 if the SYN or SYN-ACK packet is missing, if the WSF option is intact in a 
                                 the surviving SYN or SYN-ACK packet, one cannot assume that window scaling was
                                 supported in that connection so that WSF is ignored.
                        */
                       if((tcph->th_flags&TH_SYN)
                       && (tcph->th_flags&TH_ACK)==0) {
                            tcpd->syn_seen = TRUE;                        
                            tcpd->wsf_announced = FALSE; /* ... because we haven't seen the SYN-ACK yet */
                            if (tcpd->fwd->win_scale < 0) { 
                                /* 
                                  The SYN packet was captured but doesn't include a WSF option which means the
                                  host does not support RFC 1323 window scaling so window scaling is not
                                  supported in this connection.
                                */
                                tcpd->fwd->win_scale = UNSUPPORTED;
                            } 
                        } else {
                           if((tcph->th_flags&TH_SYN)
                           && (tcph->th_flags&TH_ACK))   {
                                tcpd->syn_ack_sent = TRUE;
                                if(tcpd->fwd->win_scale >= 0
                                && tcpd->rev->win_scale >= 0) {
                                    tcpd->wsf_announced = TRUE;
                                } else {
                                    /* 
                                      The SYN-ACK packet was captured but doesn't include a WSF option which means
                                      the host does not support RFC 1323 window scaling so window scaling is not
                                      supported in this connection.
                                    */
                                    tcpd->wsf_announced = FALSE;
                                    tcpd->fwd->win_scale = UNSUPPORTED;
                                }
                            }
                        }
                    }
                }
            }

            /* If tcpd->wsf_announced is TRUE, re-calculate window size based on the WSF. */
            if((tcph->th_flags&TH_SYN)==FALSE
            &&  tcpd->wsf_announced
            &&  tcpd->fwd->win_scale > 0) {
                (tcph->th_win)<<=tcpd->fwd->win_scale;
            } 
            
            /*
              If tcpd->wsf_announced is FALSE and the maximum number of unACKed bytes seen in
              the opposite flow is greater than the largest window size seen in this flow, set
              tcpd->fwd->max_size_window to tcpd->rev->max_size_unacked. The value of
              max_size_window is used to detect such things as the TCP_REUSED_PORTS, WINDOW_FULL
              and WINDOW_EXCEEDED conditions.  
            */
            if(tcpd->wsf_announced) {
                if (tcph->th_win > tcpd->fwd->max_size_window)
                    tcpd->fwd->max_size_window = tcph->th_win;
            } else {
                /* In this case max_size_window is still used but is not used to detect 
                   WINDOW_FULL and WINDOW_EXCEEDED conditions. */
                if (tcpd->rev->max_size_unacked > tcpd->fwd->max_size_window)
                    tcpd->fwd->max_size_window = tcpd->rev->max_size_unacked;
            }

            /*
              If desired and not already conducted, perform TCP sequence number analysis or a Fixed Congestion
              Point Analysis (FCPA). 
            */
            if (tcp_analyze_seq) {
                if (!pinfo->fd->flags.visited) {
                    tcp_analyze_sequence_number(pinfo, tcph->th_seq, tcph->th_ack, tcph->th_seglen, 
                        tcph->th_flags, tcph->th_win, optlen, tcpd, tcppd);
                
                } else if (tcpd->fwd->first_rxmtl && !tcpd->fwd->fcpa_stats_calculated) {
                    gboolean is_sender_side_cap = FALSE;
                    /*
                      The capture has been fully loaded. Since the 'tcpd->fwd->first_rxmtl' exists we know that the
                      "Criteria for Calculating the Fixed Congestion Point Analysis (FCPA) Statisics in the First
                      Pass" in packet-tcp.h have been met. 


                      If 'sender_side_cap' is set to AUTO_DETECT_SIDE_CAP_TAKEN, employ the procedure in Section
                      "Criteria used for Auto-detection in the Second Pass" in 'packet-tcp.h' to detect if this
                      capture was taken on or near the sender.
                    */
                    if(sender_side_cap >= AUTO_DETECT_SIDE_CAP_TAKEN) {
                        
                        if (num_packet_lost
                        || num_ooo_segs
                        || num_ack_only_ooo) {
                            is_sender_side_cap = TRUE; 
                        } 
                    } else if (sender_side_cap==CAP_TAKEN_ON_THE_SENDER) {
                           is_sender_side_cap = TRUE; 
                    }

                    if (is_sender_side_cap) {
                        /*
                          Calculate the average bytes that were in flight when the original frame of the first
                          retransmission in each recovery event was transmitted, and calculate the standard deviation
                          (using a great soviet one-pass method).
                        */
                        int num_unacked_orig_frames=0;
                        double unacked_of_orig, sum_unacked_of_orig=0.0, first_rxmt_avg=0.0, first_rxmt_stdev=0.0;
                        long double sum_sq=0;              
                        first_rxmt_t *first_rxmt = tcpd->fwd->first_rxmtl; 

                        while (first_rxmt) {
                            num_unacked_orig_frames++;
                            unacked_of_orig = first_rxmt->unacked_of_orig;
                            sum_unacked_of_orig += unacked_of_orig;             
                            sum_sq += unacked_of_orig * unacked_of_orig; 
                            first_rxmt = first_rxmt->next;
                        }
                        first_rxmt_avg = (sum_unacked_of_orig / num_unacked_orig_frames) + 0.5;
                        first_rxmt_stdev = (sum_sq / num_unacked_orig_frames) - (first_rxmt_avg * first_rxmt_avg);
                        if (first_rxmt_stdev > 0.0) {
                            first_rxmt_stdev = sqrt(first_rxmt_stdev);
                        } else {
                            first_rxmt_stdev = 0.0;
                        }

                        tcpd->fwd->num_first_rxmts = num_unacked_orig_frames;
                        tcpd->fwd->first_rxmt_avg = (guint32)first_rxmt_avg;
                        tcpd->fwd->first_rxmt_stdev = first_rxmt_stdev;
                        tcpd->fwd->fcpa_stats_calculated = TRUE;
                    }

                    /*
                      The SLAB
                    */
                    release_all_non_persistent_lists(tcpd);
                }

                if (tcp_relative_seq) {
                    if (ta_send && (ta_send->flags & TCP_OLD_SEQ)) {
                        (tcph->th_seq) -= tcpd->fwd->base_seq_old;
                        (tcph->th_ack) -= tcpd->rev->base_seq_old;
                        old_seq = TRUE;

                    } else {
                        (tcph->th_seq) -= tcpd->fwd->base_seq;
                        (tcph->th_ack) -= tcpd->rev->base_seq;
                        old_seq = FALSE;
                    }
                }
            }

            /*
               Compute the sequence number of next octet after this segment. SYNs and FINs count as one byte.
            */
            if (tcph->th_flags  & (TH_SYN|TH_FIN)) 
                nxtseq = tcph->th_seq + 1;  
            else
                if (tcph->th_seglen > 0) 
                    nxtseq = tcph->th_seq + tcph->th_seglen; 
        }
    }
    
    /*
       Remove "ACK" from the flags string unless any of the following is true:
         - "only_display_ack_flag_in_packet_list_when_needed" is FALSE
         - tcppd->display_ack is TRUE
         - SYN or FIN flag is set
         - An ACK-only packet which ACKs a FIN 
         - An ACK-only packet which ACKs a SYN-ACK and the ACK is 1 greater than the
           reverse flow's base sequence number 

       NOTE: If the "Display TCP summary info in Packet Details" is TRUE, all the info 
       including "ACK" are displayed regardless of other settings.
    */
    if(!(only_display_ack_flag_in_packet_list_when_needed)
    || (tcppd && tcppd->display_ack)
    || (tcph->th_flags & (TH_SYN|TH_FIN))
    || (tcph->th_seglen == 0 && tcpd->fin_sent)
    || (tcph->th_seglen == 0 && tcpd->syn_ack_sent && (tcph->th_ack == (tcp_relative_seq ? 1 : tcpd->rev->base_seq + 1)))) { 

        /* Convert all of the TCP flags to text */
        first_flag = TRUE;
        for (i = 0; i < 9; i++) {
            bpos = 1 << i;
            if (tcph->th_flags & bpos) {
                if (first_flag) {
                    ep_strbuf_truncate(flags_strbuf, 0);
                }
                ep_strbuf_append_printf(flags_strbuf, "%s%s", first_flag ? "" : ", ", flags[i]);
                first_flag = FALSE;
            }
        }
        if (!(pinfo->fd->flags.visited)) {
            if (tcpd->syn_ack_sent || tcpd->fin_sent) {
                tcppd = p_get_proto_data(pinfo->fd, proto_tcp);
                if ( !tcppd ) {
                    tcppd = se_alloc(sizeof(struct tcp_per_packet_data_t));
                    p_add_proto_data(pinfo->fd, proto_tcp, tcppd);
                    tcppd->bif = 0;
                    tcppd->unacked = 0;
                }
                /* Store display_ack in tcppd, a persistent list (Note: tcpd is persistent by connection, not frame) */
                tcppd->display_ack = TRUE;
                tcpd->syn_ack_sent = FALSE;
                tcpd->fin_sent = FALSE;
            }
        
            if ((tcph->th_flags & TH_SYN) && (tcph->th_flags & TH_ACK))
                tcpd->syn_ack_sent = TRUE;
            else if (tcph->th_flags & TH_FIN)
                tcpd->fin_sent = TRUE;
        }
        col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] ", flags_strbuf->str);

    } else {
        /*
          Convert all TCP flags except ACK to text
        */
        first_flag = TRUE;
        for (i = 0; i < 9; i++) {
            bpos = 1 << i;
            if(i != 4
            && tcph->th_flags & bpos) {
                if (first_flag) {
                    ep_strbuf_truncate(flags_strbuf, 0);
                }
                ep_strbuf_append_printf(flags_strbuf, "%s%s", first_flag ? "" : ", ", flags[i]);
                first_flag = FALSE;
            }
        }
        if(tcph->th_flags 
        && tcph->th_flags != 0x10)
            col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] ", flags_strbuf->str);
    }

    /*
      TCP Flags in Packet Detail TCP header
    */
    if (tree && summary_in_tcp_tree_header) {
        if (tcph->th_flags == 0x10)
            flags_strbuf->str = "ACK";
        proto_item_append_text(ti, "[%s]  ", flags_strbuf->str);  
    }

    if (pinfo->fd->flags.visited) {
        /*
           TCP flags 
        */
        tf = proto_tree_add_uint_format(tcp_tree, hf_tcp_flags, tvb, offset + 12, 2,
            tcph->th_flags, "Flags: 0x%02x (%s)", tcph->th_flags, flags_strbuf->str);
        flags_tree = proto_item_add_subtree(tf, ett_tcp_flags);
        proto_tree_add_boolean(flags_tree, hf_tcp_flags_res, tvb, offset + 12, 1, tcph->th_flags);
        proto_tree_add_boolean(flags_tree, hf_tcp_flags_ns, tvb, offset + 12, 1, tcph->th_flags);
        proto_tree_add_boolean(flags_tree, hf_tcp_flags_cwr, tvb, offset + 13, 1, tcph->th_flags);
        proto_tree_add_boolean(flags_tree, hf_tcp_flags_ecn, tvb, offset + 13, 1, tcph->th_flags);
        proto_tree_add_boolean(flags_tree, hf_tcp_flags_urg, tvb, offset + 13, 1, tcph->th_flags);
        proto_tree_add_boolean(flags_tree, hf_tcp_flags_ack, tvb, offset + 13, 1, tcph->th_flags);
        proto_tree_add_boolean(flags_tree, hf_tcp_flags_push, tvb, offset + 13, 1, tcph->th_flags);
        tf_rst = proto_tree_add_boolean(flags_tree, hf_tcp_flags_reset, tvb, offset + 13, 1, tcph->th_flags);
        tf_syn = proto_tree_add_boolean(flags_tree, hf_tcp_flags_syn, tvb, offset + 13, 1, tcph->th_flags);
        tf_fin = proto_tree_add_boolean(flags_tree, hf_tcp_flags_fin, tvb, offset + 13, 1, tcph->th_flags);
 
        if (tcph->th_flags & TH_SYN) {
            if (tcph->th_flags & TH_ACK) {
                expert_add_info_format(pinfo, tf_syn, PI_SEQUENCE, PI_CHAT, 
                    "Connection establish acknowledge (SYN+ACK): server port %s", get_tcp_port(tcph->th_sport));
            } else {
                expert_add_info_format(pinfo, tf_syn, PI_SEQUENCE, PI_CHAT, 
                    "Connection establish request (SYN): server port %s", get_tcp_port(tcph->th_dport));
            }
        } 
        if (tcph->th_flags & TH_FIN)
            /* XXX - find a way to know the server port and output only that one */
            expert_add_info_format(pinfo, tf_fin, PI_SEQUENCE, PI_CHAT, "Connection finish (FIN)");
        if (tcph->th_flags & TH_RST)
            /* XXX - find a way to know the server port and output only that one */
            expert_add_info_format(pinfo, tf_rst, PI_SEQUENCE, PI_CHAT, "Connection reset (RST)");
    }


    /* Seq */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[Seq=%u", tcph->th_seq);
    
    if (old_seq) 
        col_append_fstr(pinfo->cinfo, COL_INFO, " (from previous conversation)");

    if (tree && summary_in_tcp_tree_header) 
        proto_item_append_text(ti, "[Seq: %u", tcph->th_seq);  

    if (nxtseq > 0) {
        if (display_len_in_packet_list)
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Next=%u, Len=%u]", nxtseq, tcph->th_seglen);
        else
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Next=%u]", nxtseq);

        if (tree && summary_in_tcp_tree_header) 
                proto_item_append_text(ti, ", Next: %u, Len: %u]", nxtseq, tcph->th_seglen);  
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, "]");
        if (tree && summary_in_tcp_tree_header) 
            proto_item_append_text(ti, "]");  

    }

    /*
      Win and Ack

      Display Win= and Ack= in the Packet List and if desired appended to the TCP header in the tree
    */
    col_append_fstr(pinfo->cinfo, COL_INFO, " [Win=%u", tcph->th_win);
    if (tree && summary_in_tcp_tree_header) 
        proto_item_append_text(ti, " [Win: %u", tcph->th_win);

    if (tcph->th_flags & TH_ACK) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Ack=%u", tcph->th_ack);
        if (tree && summary_in_tcp_tree_header) 
            proto_item_append_text( ti, ", Ack: %u", tcph->th_ack);
    } else {
        col_append_str(pinfo->cinfo, COL_INFO, " Ack=none");
        if (tree && summary_in_tcp_tree_header) 
            proto_item_append_text( ti, ", Ack: none");
    }
    

    if (tree) {
        proto_item_set_len(ti, tcph->th_hlen);
        if (!ta_send) {
            tcp_analyze_get_ta_send_struct(pinfo->fd->num, FALSE, tcpd);
            ta_send = tcpd->ta_send;
        }

        /* Sequence number */
        seqi = proto_tree_add_uint(tcp_tree, hf_tcp_seq, tvb, offset + 4, 4, tcph->th_seq);
        
        if (tcp_analyze_seq && tcp_relative_seq) 
            proto_item_append_text(seqi, "  (relative)");

        if (old_seq) 
            proto_item_append_text(seqi, " (from previous connection)"); 

        if (tcp_analyze_seq) {   
            sequence_tree = proto_item_add_subtree(seqi, ett_tcp_sequence_analysis);

            if(ta_send
            && ta_send->new_data_sent_in_rec > 0) {
                item=proto_tree_add_uint(sequence_tree, hf_tcp_analysis_new_data_sent_in_rec, tvb, 0, 0,
                    ta_send->new_data_sent_in_rec);
                PROTO_ITEM_SET_HIDDEN(item);     
            }
        }

        /* Next sequence number */
        if (nxtseq > 0) {
            tf = proto_tree_add_uint( tcp_tree, hf_tcp_nxtseq, tvb, offset, 0, nxtseq);
    
            if (tcp_analyze_seq && tcp_relative_seq) 
                proto_item_append_text( tf, "  (relative)");
            PROTO_ITEM_SET_GENERATED(tf);
        }

        /* Acknowledgement number */
        if (tcph->th_flags & TH_ACK) {
            acki = proto_tree_add_uint( tcp_tree, hf_tcp_ack, tvb, offset+8, 4, tcph->th_ack);

            if (tcp_analyze_seq && tcp_relative_seq) 
                proto_item_append_text( acki, "  (relative)");
            
        } else {
            /* Verify that the ACK field is zero */
            if (tvb_get_ntohl(tvb, offset+8) != 0) {
                item = proto_tree_add_text(tcp_tree, tvb, offset+8, 4,
                    "Acknowledgement number:  %u  [Should be zero because the ACK flag is not set]", tcph->th_ack);
                expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE, 
                    "Should be zero because the ACK flag isn't set");  
            }
        }
    }

    if (pinfo->fd->flags.visited) {
        /*
          Decode the TCP options or as many as have not been truncated by frame-slicing.
        
          See if there are any TCP options to decode.
        */
        gint bc = tvb_length_remaining(tvb, offset + TCPH_MIN_LEN);
       
        if (bc > 0) { 
            optlen = MIN((guint)bc, (guint)tcph->th_hlen - TCPH_MIN_LEN); /* length of options, in bytes */            
        
            if (tcp_tree) {
                if (bc < (gint)optlen) {
                    if (bc >= 4) {
                        tf = proto_tree_add_boolean_format(tcp_tree, hf_tcp_options, tvb, offset + 20,
                                optlen, (guint32)optlen, "Options: (%u bytes but truncated to %u bytes)", optlen, bc);
                    } else {
                        proto_tree_add_text(tcp_tree, tvb, 0, 0, "Options: Do not exist due to frame truncation)");
                        tf = NULL;
                    }
                } else {
                    tf = proto_tree_add_boolean_format(tcp_tree, hf_tcp_options, tvb, offset + 20,
                            optlen, (guint32)optlen, "Options: (%u bytes)", optlen);
                }
                if (tf) {
                    options_tree = proto_item_add_subtree(tf, ett_tcp_options);
                    opti = proto_tree_add_uint(options_tree, hf_tcp_options_len, tvb, offset + 20, optlen,
                        (guint32) optlen);                      
                    PROTO_ITEM_SET_GENERATED(opti);
                        
                    dissect_ip_tcp_options(tvb, offset + 20, optlen,
                        tcpopts, N_TCP_OPTS, TCPOPT_EOL, pinfo, options_tree, tf);
                }
            }
        }
    } else {
        if ((tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
            /* If the SYN or the SYN+ACK offered SCPS capabilities,
                validate the flow's bidirectional scps capabilities.
                The or protects against broken implementations offering
                SCPS capabilities on SYN+ACK even if it wasn't offered with the SYN
            */
            if (tcpd->rev->scps_capable || tcpd->fwd->scps_capable) {
                verify_scps(pinfo, tf_syn, tcpd);
            }
        }
    }

    tcpd->fwd->last_tcpflags = tcph->th_flags;
    tcpinfo.tcp_flags = flags_strbuf;
    /*
       dissect_ip_tcp_options() calls get_tcp_conversation_data() which causes tcpd->ta_send 
       to be set to NULL. Reconnect ta_send. */
    tcpd->ta_send = ta_send;

    /* Retransmissions, OOO, and other conditions */
    if (tcp_analyze_seq) {
        /*
           TCP_REUSED_PORTS
        */
        if(ta_send
        && ta_send->flags & TCP_REUSED_PORTS) {
            col_insert_fstr_after_fence(pinfo->cinfo, COL_INFO, "[TCP Port numbers reused] ");
            if (tree) {
                item = proto_tree_add_none_format(tcp_tree, hf_tcp_analysis_reused_ports, tvb, 0, 0,
                    "New TCP connection established with the same port numbers as a previous one");
                PROTO_ITEM_SET_GENERATED(item);
                expert_add_info_format(pinfo, item, PI_SEQUENCE, PI_NOTE,
                    "TCP Port numbers reused for new session");
            }
        }

        if (!tcpd->rxmtinfo)
            tcp_analyze_get_rxmtinfo_struct(pinfo->fd->num, FALSE, tcpd);
        rxmtinfo = tcpd->rxmtinfo; 

        if (rxmtinfo && rxmtinfo->flags)
            tcp_analyze_seq_print_retransmission(pinfo, tvb, seqi, sequence_tree, tcpd);

        if (ta_send && ta_send->flags) {
            if (ta_send->flags < TCP_PACKET_LOST)
                tcp_analyze_seq_print_ta_send_flags_other(pinfo, tvb, seqi, sequence_tree, tcpd);            
            if (ta_send->flags >= TCP_PACKET_LOST)
                tcp_analyze_seq_print_ta_send_flags_lost_ooo(pinfo, tvb, seqi, sequence_tree, tcpd);
        }

        /* Bytes-in-Flight (bif) */
        if (tree && tcppd) {
            if (tcppd->bif > 0) {
                /*
                   Bytes considered to be still on the wire (traversing the network)
                */
                item = proto_tree_add_uint( sequence_tree, hf_tcp_analysis_bytes_in_flight, tvb, 0, 0,
                    tcppd->bif);
                PROTO_ITEM_SET_GENERATED(item);            
                
            } else {
                if( ta_send 
                && (ta_send->flags & TCP_PREV_PACKET_LOST)
                && tcph->th_seglen > 0) {
                        item = proto_tree_add_text(sequence_tree, tvb, 0, 0,
                            "Bytes_in_flight invalid due to previous packet unseen/lost/out_of_order");
                        PROTO_ITEM_SET_GENERATED(item);
                }
            }

            /* Outstanding (unACKed and unSACKed) bytes for this flow */
            if (tcppd->unacked > 0) {          
                item = proto_tree_add_uint( sequence_tree, hf_tcp_analysis_unacked_bytes, tvb, 0, 0,
                    tcppd->unacked);
                PROTO_ITEM_SET_GENERATED(item);   
            }
        }
    }

    if (tree) {
        if (tcph->th_flags & TH_ACK) {
            if (tcp_analyze_seq) {                
                if (!tcpd->ta_recv)
                    tcp_analyze_get_ta_recv_struct(pinfo->fd->num, FALSE, tcpd);
                ta_recv = tcpd->ta_recv;
                if (ta_recv) {
                    ack_tree = proto_item_add_subtree(acki, ett_tcp_ack_analysis);
                    /*
                       Display the frame# that has been ACKed and the delta time from that frame to this.
                    */
                    if (ta_recv->frame_acked > 0) {
                        /*
                          NOTE: The receiver might not (and is not required to) ACK the entire TCP payload.
                          If the capture was taken on the sender host and the sender transmitted an LSO segment larger
                          than 2*MSS, you will typically see multiple ACKs for that segment that point to the same frame#.
                        */
                        proto_item_append_text( acki, ", ACK of seq# in frame %u", ta_recv->frame_acked);
                        item = proto_tree_add_uint( ack_tree, hf_tcp_analysis_acks_frame, tvb, 0, 0, ta_recv->frame_acked);
                        PROTO_ITEM_SET_GENERATED(item);
                        /*
                           Display ACK RTT if the delta time between the segment ACKed and this ACK is non-zero
                        */
                        if (ta_recv->delta_ts.secs || ta_recv->delta_ts.nsecs ) {
                            proto_item_append_text( acki, " took %2d.%06d secs", (gint) ta_recv->delta_ts.secs,
                                (ta_recv->delta_ts.nsecs+500)/1000 );
                            item = proto_tree_add_time( ack_tree, hf_tcp_analysis_ack_rtt, tvb, 0, 0, &ta_recv->delta_ts);
                            PROTO_ITEM_SET_GENERATED(item);
                        }
                    }                
                    if(tcph->th_seglen == 0
                    && ta_recv->unacked_in_rev > 0
                    && ((ta_send ? (ta_send->flags & 0x7C000)==0 : TRUE))) {
                        item = proto_tree_add_uint( ack_tree, hf_tcp_analysis_unacked_in_rev_flow, tvb, 0, 0,
                            ta_recv->unacked_in_rev);
                        PROTO_ITEM_SET_GENERATED(item);
                    }
                }
            }
        }

        /*
           XXX - what, if any, of this should we do if this is included in an
           error packet?  It might be nice to see the details of the packet
           that caused the ICMP error, but it might not be nice to have the
           dissector update state based on it.
           Also, we probably don't want to run TCP taps on those packets.
        */
        if((tcph->th_flags & TH_RST) 
        &&  tcph->th_seglen > 0) {
            length_remaining = tvb_length_remaining(tvb, tcph->th_hlen);            
            if (length_remaining > 0) {
                /*
                  RFC1122 Section 4.2.2.12 and RFC-793 Section 3.4:
                     "A TCP SHOULD allow a received RST segment to include data."

                  DISCUSSION
                    It has been suggested that a RST segment could contain
                    ASCII text that encoded and explained the cause of the
                    RST.  No standard has yet been established for such
                    data so for segments with RST we just display the data as text.
                */
                proto_tree_add_text(tcp_tree, tvb, offset, length_remaining, "Reset cause: %s",
                    tvb_format_text(tvb, offset, length_remaining));
            }
        }
    }

    /* Window Size */
    if (tcp_tree) {
        /* 
          If this is a SYN or SYN-ACK packet, just print the raw window size because although they 
          may have a window scale factor, (WSF) it is not applied to these packets. 
        */
        if (tcph->th_flags & TH_SYN) {
            proto_tree_add_uint(tcp_tree, hf_tcp_window_size_value, tvb, offset + 14, 2, real_window);

        } else {  

            if (tcpd->wsf_announced) {
                /* Window scaling is supported (wsf_announced==TRUE) in this connection */
                wini = proto_tree_add_uint_format(tcp_tree, hf_tcp_window_size_scaled, tvb, 
                    offset + 14, 2, tcph->th_win, "Window size: %d (scaled)", tcph->th_win);
                window_tree = proto_item_add_subtree(wini, ett_tcp_window_size_scale);
               
                proto_tree_add_uint(window_tree, hf_tcp_window_size_value, tvb, offset + 14, 2, real_window);
                item = proto_tree_add_int_format(window_tree, hf_tcp_window_scalefactor, 
                    tvb, 0, 0, 1<<tcpd->fwd->win_scale, 
                    "Window size scale factor: %d  (2**%d)", 1<<tcpd->fwd->win_scale, tcpd->fwd->win_scale);
                PROTO_ITEM_SET_GENERATED(item);
                item = proto_tree_add_uint(window_tree, hf_tcp_window_size_scaled, tvb, offset + 14, 2, tcph->th_win);
                PROTO_ITEM_SET_GENERATED(item);
            
            } else {
                if (tcpd->fwd->win_scale >= 0)
                    tcpd->fwd->win_scale = UNSUPPORTED;
                    
                switch (tcpd->fwd->win_scale) {

                case UNKNOWN:
                    wini = proto_tree_add_uint_format(tcp_tree, hf_tcp_window_size_scale_unknown, 
                        tvb, offset + 14, 2, tcph->th_win,
                        "Window size: %d (scale factor UNKNOWN in this flow)", tcph->th_win);
                    break;

                case UNSUPPORTED:
                    if (tcpd->rev->win_scale==UNKNOWN) {
                        wini = proto_tree_add_uint_format(tcp_tree, hf_tcp_window_scale_ignored_due_to_missing_syn_or_synack_packet, 
                            tvb, offset + 14, 2, tcph->th_win,
                            "Window size: %d (scale factor UNKNOWN in opposite flow thus UNSUPPORTED in this connection)", tcph->th_win);
                    } else if (tcpd->rev->win_scale==UNSUPPORTED) {
                        wini = proto_tree_add_uint_format(tcp_tree, hf_tcp_window_size_scaling_unsupported, 
                            tvb, offset + 14, 2, tcph->th_win,
                            "Window size: %d (scale factor UNSUPPORTED in opposite flow thus UNSUPPORTED in this connection)", tcph->th_win);
                    } else if (tcpd->fwd->win_scale==UNSUPPORTED) {
                        wini = proto_tree_add_uint_format(tcp_tree, hf_tcp_window_size_scaling_unsupported, 
                            tvb, offset + 14, 2, tcph->th_win,
                            "Window size: %d (scale factor UNSUPPORTED in this flow thus UNSUPPORTED in this connection)", tcph->th_win);
                    } 
                }
            }
        }
    }
    if (tcp_analyze_seq) {                
        if (!tcpd->ta_recv)
            tcp_analyze_get_ta_recv_struct(pinfo->fd->num, TRUE, tcpd);
        ta_recv = tcpd->ta_recv;
        if (ta_recv) {
            /*
              Print receiver-related flags such as ACK of unseen packet, Duplicate ack, Out-of-order ACK,
              and partner can exit recovery.
            */
            if (ta_recv->flags < TCP_ZERO_WINDOW) 
                tcp_analyze_seq_print_ta_recv_flags_ack(pinfo, tvb, acki, ack_tree, tcpd);
            if (ta_recv->flags >= TCP_ZERO_WINDOW)
                /*
                   Window: update, zero size, exceeded, full, probe, and ACK of probe
                */
                tcp_analyze_seq_print_ta_recv_flags_window(pinfo, tvb, wini, window_tree, tcpd);
        }
    }

    if(tcph->th_flags & (TH_FIN | TH_RST )
    || (ta_send && ta_send->flags & TCP_REUSED_PORTS) ) {
        /*
          Release all of the nonpersistent struct lists for this flow. 
          Don't release the lists in the rev flow yet in case this conv remains in a half open state.
        */
        release_all_non_persistent_lists(tcpd);
    }

    /* Supply the sequence number of the first byte and of the first byte after the segment. */
    tcpinfo.seq = tcph->th_seq;
    tcpinfo.nxtseq = nxtseq;
    tcpinfo.lastackseq = tcph->th_ack;

    /* Assume we'll pass un-reassembled data to subdissectors. */
    tcpinfo.is_reassembled = FALSE;
    pinfo->private_data = &tcpinfo;

    /*
       Assume, initially, that we can't desegment.
    */
    pinfo->can_desegment = 0;
    th_sum = tvb_get_ntohs(tvb, offset + 16);
    if (!pinfo->fragmented && tvb_bytes_exist(tvb, 0, reported_len)) {
        /*
           The packet isn't part of an un-reassembled fragmented datagram
           and isn't truncated. This means we have all the data, and thus
           can checksum it and, unless it's being returned in an error
           packet, are willing to allow subdissectors to request reassembly
           on it.
        */

        if (tcp_check_checksum) {
            /*
              We haven't turned checksum checking off; checksum it.
              Set up the fields of the pseudo-header.
            */
            cksum_vec[0].ptr = (guint8 *)pinfo->src.data;
            cksum_vec[0].len = pinfo->src.len;
            cksum_vec[1].ptr = (const guint8 *)pinfo->dst.data;
            cksum_vec[1].len = pinfo->dst.len;
            cksum_vec[2].ptr = (const guint8 *)phdr;

            switch (pinfo->src.type) {
            case AT_IPv4:
                phdr[0] = g_htonl((IP_PROTO_TCP<<16) + reported_len);
                cksum_vec[2].len = 4;
                break;

            case AT_IPv6:
                phdr[0] = g_htonl(reported_len);
                phdr[1] = g_htonl(IP_PROTO_TCP);
                cksum_vec[2].len = 8;
                break;

            default:
                /* TCP runs only atop IPv4 and IPv6. */
                DISSECTOR_ASSERT_NOT_REACHED();
                break;
            }
            cksum_vec[3].ptr = tvb_get_ptr(tvb, offset, reported_len);
            cksum_vec[3].len = reported_len;
            computed_cksum = in_cksum(cksum_vec, 4);
            if (computed_cksum == 0 && th_sum == 0xffff) {
                if (tree) {
                    chki = proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
                                                      offset + 16, 2, th_sum,
                                                      "Checksum: 0x%04x [should be 0x0000 (see RFC 1624)]", th_sum);

                    checksum_tree = proto_item_add_subtree(chki, ett_tcp_checksum);
                    chki2 = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_good, tvb,
                                                  offset + 16, 2, FALSE);
                    PROTO_ITEM_SET_GENERATED(chki2);
                    chki2 = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_bad, tvb,
                                                  offset + 16, 2, FALSE);
                    PROTO_ITEM_SET_GENERATED(chki2);
                    expert_add_info_format(pinfo, chki2, PI_CHECKSUM, PI_WARN, "TCP Checksum 0xffff instead of 0x0000 (see RFC 1624)");
                }
                col_append_str(pinfo->cinfo, COL_INFO, " [TCP CHECKSUM 0xFFFF]");

                /* Checksum is treated as valid on most systems, so we're willing to desegment it. */
                desegment_ok = TRUE;
            } else if (computed_cksum == 0) {
                if (tree) {
                    chki = proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
                              offset + 16, 2, th_sum, "Checksum: 0x%04x [correct]", th_sum);

                    checksum_tree = proto_item_add_subtree(chki, ett_tcp_checksum);
                    chki2 = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_good, tvb,
                                                  offset + 16, 2, TRUE);
                    PROTO_ITEM_SET_GENERATED(chki2);
                    chki2 = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_bad, tvb,
                                                  offset + 16, 2, FALSE);
                    PROTO_ITEM_SET_GENERATED(chki2);
                }
                /* Checksum is valid, so we're willing to desegment it. */
                desegment_ok = TRUE;
            } else if (th_sum == 0) {
                if (tree) {
                    /* checksum is probably fine but checksum offload is used */
                    chki = proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
                              offset + 16, 2, th_sum, "Checksum: 0x%04x [Checksum Offloaded]", th_sum);
                    checksum_tree = proto_item_add_subtree(chki, ett_tcp_checksum);
                    chki2 = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_good, tvb,
                                                  offset + 16, 2, FALSE);
                    PROTO_ITEM_SET_GENERATED(chki2);
                    chki2 = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_bad, tvb,
                                                  offset + 16, 2, FALSE);
                    PROTO_ITEM_SET_GENERATED(chki2);
                }
                /* Checksum is (probably) valid, so we're willing to desegment it. */
                desegment_ok = TRUE;
            } else {
                if (tree) {
                    chki = proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
                              offset + 16, 2, th_sum,
                              "Checksum: 0x%04x [incorrect, should be 0x%04x (could be caused by \"TCP checksum offload\")]", th_sum,
                              in_cksum_shouldbe(th_sum, computed_cksum));
                    checksum_tree = proto_item_add_subtree(chki, ett_tcp_checksum);
                    chki2 = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_good, tvb,
                                                  offset + 16, 2, FALSE);
                    PROTO_ITEM_SET_GENERATED(chki2);
                    chki2 = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_bad, tvb,
                                                  offset + 16, 2, TRUE);
                    PROTO_ITEM_SET_GENERATED(chki2);
                    expert_add_info_format(pinfo, chki2, PI_CHECKSUM, PI_ERROR, "Bad checksum");
                }
                col_append_str(pinfo->cinfo, COL_INFO, " [TCP CHECKSUM INCORRECT]");
             
                /* Checksum is invalid, so we're not willing to desegment it. */
                desegment_ok = FALSE;
                pinfo->noreassembly_reason = " [Incorrect TCP checksum]";
            }
        } else {
           if (tree) {
               chki = proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
                        offset + 16, 2, th_sum, "Checksum: 0x%04x [validation disabled]", th_sum);
                checksum_tree = proto_item_add_subtree(chki, ett_tcp_checksum);
                chki2 = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_good, tvb,
                                              offset + 16, 2, FALSE);
                PROTO_ITEM_SET_GENERATED(chki2);
                chki2 = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_bad, tvb,
                                              offset + 16, 2, FALSE);
                PROTO_ITEM_SET_GENERATED(chki2);
           }
           /* We didn't check the checksum, and don't care if it's valid,
              so we're willing to desegment it. */
           desegment_ok = TRUE;
        }
    } else {
        if (tree) {
            /* We don't have all the packet data, so we can't checksum it... */
            chki = proto_tree_add_uint_format(tcp_tree, hf_tcp_checksum, tvb,
                      offset + 16, 2, th_sum, "Checksum: 0x%04x [unchecked, not all data available]", th_sum);
            checksum_tree = proto_item_add_subtree(chki, ett_tcp_checksum);
            chki2 = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_good, tvb,
                                          offset + 16, 2, FALSE);
            PROTO_ITEM_SET_GENERATED(chki2);
            chki2 = proto_tree_add_boolean(checksum_tree, hf_tcp_checksum_bad, tvb,
                                          offset + 16, 2, FALSE);
            PROTO_ITEM_SET_GENERATED(chki2);
        }
        /* ...and aren't willing to desegment it. */
        desegment_ok = FALSE;
    }

    if (desegment_ok) {
        /* We're willing to desegment this. Is desegmentation enabled? */
        if (tcp_desegment) {
            /* Yes - is this segment being returned in an error packet? */
            if (!pinfo->in_error_pkt) {
                /*
                   No - indicate that we will desegment.
                   We do NOT want to desegment segments returned in error
                   packets, as they're not part of a TCP connection.
                */
                pinfo->can_desegment = 2;
            }
        }
    }

    /* If zero the Urgent pointer is not displayed; however, it is exported for the benefit of
       protocols such as rlogin. */ 
    if (tcph->th_flags & TH_URG) {
        th_urp = tvb_get_ntohs(tvb, offset + 18);
        tcpinfo.urgent = TRUE;
        tcpinfo.urgent_pointer = th_urp;
        col_append_fstr(pinfo->cinfo, COL_INFO, "Urg=%u ", th_urp);
        if (tcp_tree)
            proto_tree_add_uint(tcp_tree, hf_tcp_urgent_pointer, tvb, offset + 18, 2, th_urp);
    } else {
        tcpinfo.urgent = FALSE;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "]");
    proto_item_append_text(ti, "]");  

    /*
      If some or all of the TCP options were sliced off, options dissection was not performed above but
      now that we've dissected as much as possible, we need to raise an exception and stop the 
      dissection.
    */
    tvb_ensure_bytes_exist(tvb, offset + 20, optlen);

    /* Skip over the TCP header (and options) */
    offset += tcph->th_hlen;
    /*
      Check the packet length to see if there's more data (it could be an ACK-only packet)
    */
    length_remaining = tvb_length_remaining(tvb, offset);

    if (tcph->th_seglen > 0) {
        if ( data_out_file ) {
            reassemble_tcp( conv->index,                          /* conversation index */
                            tcph->th_seq,                         /* sequence number */
                            tcph->th_ack,                         /* acknowledgement number */
                            tcph->th_seglen,                      /* data length */
                            (gchar*)tvb_get_ptr(tvb, offset, length_remaining), /* data */
                            length_remaining,                     /* captured data length */
                            (tcph->th_flags & TH_SYN),            /* is syn set? */
                            &pinfo->net_src,
                            &pinfo->net_dst,
                            pinfo->srcport,
                            pinfo->destport);
        }
    }

    /* Display the Relative and Delta times for this frame in this stream */
    if (tree && tcp_calculate_ts) {
        tcp_print_delta_time_info(pinfo, tvb, tcp_tree, tcpd, tcppd);
    }

    if(tree
    && tcp_analyze_seq) {        
        /*
           Provide a right-click target for tcp.analysis.flags in the tcp tree
        */
        tcp_analyze_get_saved_sackl_struct(pinfo->fd->num, FALSE, 0, tcpd);
        
        if ((ta_send && ta_send->flags) 
        || (ta_recv && ta_recv->flags) 
        || (rxmtinfo && rxmtinfo->flags)
        || tcpd->saved_sackb_l) { 
            item = proto_tree_add_item(tcp_tree, hf_tcp_analysis_flags, tvb, 0, 0, FALSE);
            PROTO_ITEM_SET_GENERATED(item);
        }
    }

    tap_queue_packet(tcp_tap, pinfo, tcph);
    /*
      A FIN packet might complete reassembly so we need to explicitly check for this here.
    */
    if(tcph->th_seglen > 0 
    && (tcph->th_flags & TH_FIN)
    && (tcpd->fwd->flags & TCP_FLOW_REASSEMBLE_UNTIL_FIN)) {
        struct tcp_multisegment_pdu *msp;

        /* Find the most previous PDU starting before this sequence number */
        msp=se_tree_lookup32_le(tcpd->fwd->multisegment_pdus, tcph->th_seq-1);
        if (msp) {
            fragment_data *ipfd_head;

            ipfd_head = fragment_add(tvb, offset, pinfo, msp->first_frame,
                                     tcp_fragment_table,
                                     tcph->th_seq - msp->seq,
                                     tcph->th_seglen,
                                     FALSE );
            if (ipfd_head) {
                tvbuff_t *next_tvb;
                /*
                   Create a new TVB structure for desegmented data datalen-1 to strip the dummy FIN byte off.
                */
                next_tvb = tvb_new_child_real_data(tvb, ipfd_head->data, ipfd_head->datalen, ipfd_head->datalen);

                /* Add desegmented data to the data source list */
                add_new_data_source(pinfo, next_tvb, "Reassembled TCP");

                /* Call the payload dissector
                   but make sure we don't offer desegmentation any more
                */
                pinfo->can_desegment = 0;

                process_tcp_payload(next_tvb, 0, pinfo, tree, tcp_tree, tcph->th_sport, tcph->th_dport,
                    tcph->th_seq, nxtseq, tcph->th_ack, tcph->th_win, FALSE, tcpd);

                print_tcp_fragment_tree(ipfd_head, tree, tcp_tree, pinfo, next_tvb);

                return;
            }
        }
    }

    if (tcpd->fwd->command || tcpd->rev->command) {
        ti = proto_tree_add_text(tcp_tree, tvb, offset, 0, "Process Information");
        PROTO_ITEM_SET_GENERATED(ti);
        process_tree = proto_item_add_subtree(ti, ett_tcp_process_info);
        if (tcpd->fwd->command) {
            proto_tree_add_uint_format_value(process_tree, hf_tcp_proc_dst_uid, tvb, 0, 0,
                                             tcpd->fwd->process_uid, "%u", tcpd->fwd->process_uid);
            proto_tree_add_uint_format_value(process_tree, hf_tcp_proc_dst_pid, tvb, 0, 0,
                                             tcpd->fwd->process_pid, "%u", tcpd->fwd->process_pid);
            proto_tree_add_string_format_value(process_tree, hf_tcp_proc_dst_uname, tvb, 0, 0,
                                               tcpd->fwd->username, "%s", tcpd->fwd->username);
            proto_tree_add_string_format_value(process_tree, hf_tcp_proc_dst_cmd, tvb, 0, 0,
                                               tcpd->fwd->command, "%s", tcpd->fwd->command);
        }
        if (tcpd->rev->command) {
            proto_tree_add_uint_format_value(process_tree, hf_tcp_proc_src_uid, tvb, 0, 0,
                                             tcpd->rev->process_uid, "%u", tcpd->rev->process_uid);
            proto_tree_add_uint_format_value(process_tree, hf_tcp_proc_src_pid, tvb, 0, 0,
                                             tcpd->rev->process_pid, "%u", tcpd->rev->process_pid);
            proto_tree_add_string_format_value(process_tree, hf_tcp_proc_src_uname, tvb, 0, 0,
                                               tcpd->rev->username, "%s", tcpd->rev->username);
            proto_tree_add_string_format_value(process_tree, hf_tcp_proc_src_cmd, tvb, 0, 0,
                                               tcpd->rev->command, "%s", tcpd->rev->command);
        }
    }

    /* TCP Payload (segment) length */
    item = proto_tree_add_uint(tcp_tree, hf_tcp_len, tvb, tcph->th_hlen, tcph->th_seglen, tcph->th_seglen);
    PROTO_ITEM_SET_GENERATED(item);
               
    if(length_remaining
    && (tcph->th_flags & TH_RST) == 0) 
        dissect_tcp_payload(tvb, pinfo, offset, tcph->th_seq, nxtseq, tcph->th_ack, tcph->th_win,
                                tcph->th_sport, tcph->th_dport, tree, tcp_tree, tcpd);
}

void
proto_register_tcp(void)
{
    static hf_register_info hf[] = {

        /* TCP port-related fields */
        { &hf_tcp_srcport,
          { "Source Port", "tcp.srcport", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_dstport,
          { "Destination Port", "tcp.dstport", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_port,
          { "Source or Destination Port", "tcp.port", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_analysis_reused_ports,
          { "TCP Port numbers reused", "tcp.analysis.reused_ports", FT_NONE, BASE_NONE, NULL, 0x0,
            "A new tcp session has started with previously used port numbers", HFILL }},


        /* TCP stream and payload length fields */
        { &hf_tcp_stream,
          { "Stream index", "tcp.stream", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_len,
          { "TCP segment length", "tcp.len", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},


        /* Sequence number-related fields not related to packet loss */
        { &hf_tcp_seq,
          { "Sequence number", "tcp.seq", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_analysis_flags,
          { "TCP Analysis Flags",      "tcp.analysis.flags", FT_NONE, BASE_NONE, NULL, 0x0,
            "This frame has one or more TCP analysis flags set", HFILL }},

        { &hf_tcp_analysis_bytes_in_flight,
          { "Bytes in flight",           "tcp.analysis.bif", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The number of bytes that are considered to have been on the wire (network) as opposed"
            " to unACKed for this flow.", HFILL}},

        { &hf_tcp_analysis_unacked_bytes,
          { "UnACKed bytes",           "tcp.analysis.unacked", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The number of bytes transmitted on this flow that have not been ACKed or SACKed.", HFILL}},

        { &hf_tcp_analysis_keep_alive,
          { "Keep Alive",     "tcp.analysis.keep_alive", FT_NONE, BASE_NONE, NULL, 0x0,
            "This is a keep-alive segment", HFILL }},

        { &hf_tcp_analysis_duplicate_frame,
          { "Duplicate frame", "tcp.analysis.dup_frame", FT_NONE, BASE_NONE, NULL, 0x0,
            "This frame appears to have been duplicated by the network", HFILL }},

        { &hf_tcp_analysis_duplicate_of,
          { "Duplicate of", "tcp.analysis.dup_frame_of", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This frame appears to be a duplicate of the indicated frame", HFILL }},

        { &hf_tcp_analysis_mss,
          { "Based on MSS", "tcp.analysis.mss", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The negotiated or estimated MSS value minus 12 for timestamps if present", HFILL}},


        /* Sequence number-related fields concerning to packet loss */
        { &hf_tcp_analysis_packet_lost,
          { "Packet lost", "tcp.analysis.packet_lost", FT_NONE, BASE_NONE, NULL, 0x0,
            "This packet was lost", HFILL }},

        { &hf_tcp_analysis_prev_packet_lost,
          { "Previous Segment Lost", "tcp.analysis.prev_seg_lost", FT_NONE, BASE_NONE, NULL, 0x0,
            "The previous packet was lost", HFILL }},

        { &hf_tcp_analysis_prev_packet_out_of_order,
          { "Previous Segment Out-of-Order", "tcp.analysis.prev_seg_ooo", FT_NONE, BASE_NONE, NULL, 0x0,
            "The previous packet was delivered out-of-order", HFILL }},

        { &hf_tcp_analysis_prev_packet_unseen,
          { "Previous Segment Missing", "tcp.analysis.prev_seg_unseen", FT_NONE, BASE_NONE, NULL, 0x0,
            "One or more packets prior to this one are missing from the capture but NOT actually lost", HFILL }},
            
        { &hf_tcp_analysis_gap_size,
          { "Gap size", "tcp.analysis.prev_seg_gap", FT_UINT32, BASE_DEC, NULL, 0x0,
          "The number of bytes from the highest nextseq seen in this flow and this frame's seq#", HFILL}},  

        { &hf_tcp_analysis_retransmission,
          { "Retransmission",          "tcp.analysis.retransmission", FT_NONE, BASE_NONE, NULL, 0x0,
            "This segment is a suspected TCP retransmission", HFILL }},

        { &hf_tcp_analysis_fast_retransmission,
          { "Fast Retransmission",     "tcp.analysis.retransmission_fast", FT_NONE, BASE_NONE, NULL, 0x0,
            "Suspected TCP fast retransmission triggered by multiple duplicate ACKs", HFILL }},

        { &hf_tcp_analysis_fack_retransmission,
          { "FACK Retransmission",     "tcp.analysis.retransmission_fack", FT_NONE, BASE_NONE, NULL, 0x0,
            "Suspected retransmission triggered by FACK: (snd.fack - snd.una) > (3 * MSS)", HFILL }},

        { &hf_tcp_analysis_sack_retransmission,
          { "SACK Retransmission",     "tcp.analysis.retransmission_sack", FT_NONE, BASE_NONE, NULL, 0x0,
            "A suspected retransmission while in TCP Recovery based on by SACK information", HFILL }},

        { &hf_tcp_analysis_newreno_retransmission,
          { "NewReno Retransmission",   "tcp.analysis.retransmission_newreno", FT_NONE, BASE_NONE, NULL, 0x0,
            "Suspected retransmission while in TCP Recovery triggered by a partial ACK", HFILL }},

        { &hf_tcp_analysis_rto_retransmission,
          { "RTO Retransmission",       "tcp.analysis.retransmission_rto", FT_NONE, BASE_NONE, NULL, 0x0,
            "Suspected retransmission that appears to have been triggered by the expiry of the sender's retransmission timer", HFILL }},

        { &hf_tcp_analysis_unwarranted_retransmission,
          { "Unwarranted Retransmission", "tcp.analysis.retransmission_unwarranted", FT_NONE, BASE_NONE, NULL, 0x0,
            "This entire segment appears to have already been ACKed or SACKed", HFILL }},

        { &hf_tcp_analysis_unwarranted_rxmt_and_new_data,
          { "Unwarranted Retransmission plus new data", "tcp.analysis.retransmission_unwarranted", FT_NONE, BASE_NONE, NULL, 0x0,
            "The first part of the segment was ACKed or SACKed but new data was tacked on", HFILL }},

        { &hf_tcp_analysis_recovery_target,
          { "Target recovery seq#",      "tcp.analysis.rec_target", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Highest seq# sent when this flow entered TCP recovery and which must be ACKed before recovery can be exited", HFILL}},

        { &hf_tcp_analysis_frame_rec_entered,
          { "Recovery entered in frame",  "tcp.analysis.frame_rec_entered", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The frame number at which TCP recovery was entered", HFILL}},

        { &hf_tcp_analysis_first_rxmt,
          { "First retransmission in this recovery event","tcp.analysis.first_rxmt", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "True if this is the first retransmission in this TCP recovery event", HFILL}},

        { &hf_tcp_analysis_orig_frame,
          { "Original frame",              "tcp.analysis.orig_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Frame number of the original frame", HFILL }},

        { &hf_tcp_analysis_orig_frame_prior_to,
          { "Original frame sent prior to", "tcp.analysis.orig_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Frame number of the frame following the gap within which the original frame was sent and then lost", HFILL }},

        { &hf_tcp_analysis_unacked_of_orig,
          { "UnACKed bytes of original frame", "tcp.analysis.orig_unacked", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total number of unACKed/unSACKed bytes after the original frame was transmitted.", HFILL}},

        { &hf_tcp_analysis_unacked_of_orig_in_first_rxmt,
          { "FCPA: Avg unACKed when orig frame of 1st rxmt in each event was sent",
            "tcp.analysis.avg_ua_of_orig_in_first_rxmt", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Fixed Congestion point analysis: Avg unACKed bytes when the orig frame of 1st rxmt in each recovery event was sent", HFILL }},           

        { &hf_tcp_analysis_time_from_orig,
          { "Time from original frame",  "tcp.analysis.time_from_orig", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "Time from the original frame or frame following the 'hole' to the retransmitted frame", HFILL}},

        { &hf_tcp_analysis_new_data_sent_in_rec,
          { "New data sent while in recovery length", "tcp.analysis.new_data_sent_in_rec", FT_UINT32, BASE_DEC, NULL, 0x0,
            "This packet contains new data (data beyond rec_target) of this length.", HFILL}},      

        { &hf_tcp_analysis_rxmt_in_frame,
          { "Retransmitted in frame", "tcp.analysis.retransmitted_at_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This segment appears to have been lost and retransmitted at the indicated frame number.", HFILL }},

        { &hf_tcp_analysis_rxmt_ending_in_frame,
          { "Retransmitted ending in frame", "tcp.analysis.retransmitted_in_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This segment appears to have been lost and retransmitted at the indicated frame number.", HFILL }},

        { &hf_tcp_analysis_prev_seg_rxmt_at_frame,
          { "Missing segments prior to this were retransmitted ending at frame", "tcp.analysis.lost_segment_rxmt_at_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Previous segment(s) were lost and retransmitted ending at the indicated frame number.", HFILL }},

        { &hf_tcp_analysis_prev_packet_ooo_at_frame,
          { "Segment(s) prior to this were delivered out-of-order ending at frame", 
            "tcp.analysis.ooo_at_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "One or more frames sent prior to this arrived out-of-order ending at the indicated frame number", HFILL }},

        { &hf_tcp_analysis_ack_of_out_of_order_segment,
          { "ACK of segment(s) delivered out-of-order ending at frame", 
            "tcp.analysis.ack_of_ooo_at", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "ACK of segment(s) in frames that arrived out-of-order ending at the indicated frame number", HFILL }},

        { &hf_tcp_analysis_out_of_order,
          { "Out Of Order", "tcp.analysis.out_of_order", FT_NONE, BASE_NONE, NULL, 0x0,
            "A suspected out-of-order packet", HFILL }},

        { &hf_tcp_analysis_belongs_before_frame,
          { "Actually sent prior to frame", "tcp.analysis.ooo_sent_before_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This frame appears to have been reordered by the network and actually sent prior to the indicated frame", HFILL }},            

        { &hf_tcp_analysis_ooo_belongs_after_frame,
          { "Actually sent after frame", "tcp.analysis.ooo_sent_after_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This ACK-only packet appears to have been reordered by the network and actually sent after the indicated frame", HFILL }}, 

        { &hf_tcp_analysis_seq_number_space_alert,
          { "Sequence number space alert", "tcp.analysis.number_space_alert", FT_NONE, BASE_NONE, NULL, 0x0,
            "The sequence number differs a great deal from the highest nextseq seen in this flow", HFILL }},


        /* Next expected sequence number field */
        { &hf_tcp_nxtseq,
          { "Next sequence number", "tcp.nxtseq", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},


        /* ACKnowledgement headers not related to packet loss */
        { &hf_tcp_ack,
          { "Acknowledgement number", "tcp.ack", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_analysis_acks_frame,
          { "ACK of sequence# in frame", "tcp.analysis.acks_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The sequence number being ACKed and the frame in which it resides", HFILL}},

        { &hf_tcp_analysis_ack_rtt,
          { "The RTT to ACK that sequence number", "tcp.analysis.ack_rtt", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
          "The (roundtrip) time it took to ACK this sequence number", HFILL}},

        { &hf_tcp_analysis_unacked_in_rev_flow,
          { "Unacked bytes in reverse flow", "tcp.analysis.unacked_in_rev", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The number of bytes that have not yet been acknowledged in the reverse flow", HFILL}},

        { &hf_tcp_analysis_keep_alive_ack,
          { "Keep Alive ACK",     "tcp.analysis.keep_alive_ack", FT_NONE, BASE_NONE, NULL, 0x0,
            "ACK of a keep-alive segment", HFILL }},


        /* ACKnowledgement headers concerning packet loss */
        { &hf_tcp_analysis_can_exit_recovery,
          { "Partner can exit recovery", "tcp.analysis.can_exit_recovery", FT_NONE, BASE_NONE, NULL, 0x0,
            "This ACK allows the partner (reverse flow) to exit TCP recovery", HFILL }},

        { &hf_tcp_analysis_time_in_rec,
          { "Time in recovery", "tcp.analysis.time_partner_in_rec", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "Time that our partner spent in this recovery event", HFILL}},

        { &hf_tcp_analysis_duplicate_ack,
          { "Duplicate ACK", "tcp.analysis.duplicate_ack", FT_NONE, BASE_NONE, NULL, 0x0,
            "A duplicate ACK", HFILL }},

        { &hf_tcp_analysis_duplicate_ack_num,
          { "Duplicate ACK #", "tcp.analysis.duplicate_ack_num", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Duplicate ACK number #", HFILL }},

        { &hf_tcp_analysis_duplicate_ack_frame,
          { "Duplicate of the ACK in frame", "tcp.analysis.duplicate_ack_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "A duplicate of the ACK in frame #", HFILL }},

        { &hf_tcp_analysis_gratuitous_ack,
          { "Gratuitous ACK", "tcp.analysis.gratuitous_ack", FT_NONE, BASE_NONE, NULL, 0x0,
            "Since there is no outstanding data in the reverse flow, this ACK is needless", HFILL }},

        { &hf_tcp_analysis_ack_unseen_segment,
          { "ACK of unseen Segment", "tcp.analysis.ack_unseen_segment", FT_NONE, BASE_NONE, NULL, 0x0,
            "This frame ACKs a segment that is missing from the capture file", HFILL }},

        { &hf_tcp_analysis_sack_unseen_segment,
          { "SACK of unseen segment", "tcp.analysis.sack_unseen_segment", FT_NONE, BASE_NONE, NULL, 0x0,
            "This frame SACKs a segment that is missing from the capture file", HFILL }},

        /* TCP header length */
        { &hf_tcp_hdr_len,
          { "Header Length",      "tcp.hdr_len", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        /* TCP flags-related fields */
        { &hf_tcp_flags,
          { "Flags",          "tcp.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_flags_res,
          { "Reserved",            "tcp.flags.res", FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_RES,
            "Three reserved bits (must be zero)", HFILL }},

        { &hf_tcp_flags_ns,
          { "Nonce", "tcp.flags.ns", 
            FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_NS, 
            "ECN concealment protection (RFC 3540)", HFILL }},

        { &hf_tcp_flags_cwr,
          { "Congestion Window Reduced (CWR)", "tcp.flags.cwr", 
            FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_CWR, NULL, HFILL }},

        { &hf_tcp_flags_ecn,
          { "ECN-Echo", "tcp.flags.ecn", 
            FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_ECN, NULL, HFILL }},

        { &hf_tcp_flags_urg,
          { "Urgent", "tcp.flags.urg",
            FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_URG, NULL, HFILL }},

        { &hf_tcp_flags_ack,
          { "Acknowledgement", "tcp.flags.ack",
            FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_ACK, NULL, HFILL }},

        { &hf_tcp_flags_push,
          { "Push", "tcp.flags.push",
            FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_PUSH, NULL, HFILL }},

        { &hf_tcp_flags_reset,
          { "Reset", "tcp.flags.reset", 
            FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_RST, NULL, HFILL }},

        { &hf_tcp_flags_syn,
          { "Syn", "tcp.flags.syn",
            FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_SYN, NULL, HFILL }},

        { &hf_tcp_flags_fin,
          { "Fin", "tcp.flags.fin",
            FT_BOOLEAN, 12, TFS(&tfs_set_notset), TH_FIN, NULL, HFILL }},

        { &hf_tcp_urgent_pointer,
          { "Urgent pointer", "tcp.urgent_pointer",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},


        /* TCP window-related fields  */
         /* 32 bits to accomodate very large scaled window sizes) */
        { &hf_tcp_window_size_scaled,
          { "Scaled window size", "tcp.window_size", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The scaled window size (window size value * window scale factor) for this flow", HFILL }},

        { &hf_tcp_window_size_value,
          { "Window size value", "tcp.window_size_value", FT_UINT16, BASE_DEC, NULL, 0x0,
            "The raw (unscaled) window size value in the TCP header", HFILL }},

        { &hf_tcp_window_scalefactor,
          { "Window size scaling factor", "tcp.window_size_scalefactor", FT_INT32, BASE_DEC, NULL, 0x0,
            "The window scale factor (2**<window_scale>) for this flow", HFILL }},

        { &hf_tcp_window_size_scale_unknown,
          { "Window size (scale unknown)", "tcp.window_size", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The (raw) window size value from the TCP header (window scale is unknown)", HFILL }},

        { &hf_tcp_window_scale_ignored_due_to_missing_syn_or_synack_packet,
          { "Window size (scale ignored to to missing WSF in SYN or SYN-SCK", "tcp.window_size", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The (raw) window size value from the TCP header (window scale is unknown)", HFILL }},

        { &hf_tcp_window_size_scaling_unsupported,
          { "Window size (scaling unsupported)", "tcp.window_size", FT_UINT32, BASE_DEC, NULL, 0x0,
          "The (raw) window size value in the TCP header (window scaling is not supported)", HFILL }},

        { &hf_tcp_analysis_window_update,
          { "Window update", "tcp.analysis.window_update", FT_NONE, BASE_NONE, NULL, 0x0,
            "This frame is a tcp window update", HFILL }},

        { &hf_tcp_analysis_window_full,
          { "Window full", "tcp.analysis.window_full", FT_NONE, BASE_NONE, NULL, 0x0,
            "This segment has caused the receiver's window to become 100% full", HFILL }},

        { &hf_tcp_analysis_zero_window_probe,
          { "Zero Window Probe", "tcp.analysis.zero_window_probe", FT_NONE, BASE_NONE, NULL, 0x0,
            "A Zero-window-probe", HFILL }},

        { &hf_tcp_analysis_zero_window_probe_ack,
          { "Zero Window Probe Ack", "tcp.analysis.zero_window_probe_ack", FT_NONE, BASE_NONE, NULL, 0x0,
            "An ACK of a zero-window-probe", HFILL }},

        { &hf_tcp_analysis_zero_window,
          { "Zero Window", "tcp.analysis.zero_window", FT_NONE, BASE_NONE, NULL, 0x0,
            "A zero-window", HFILL }},

        { &hf_tcp_analysis_window_exceeded,
          { "Window size exceeded", "tcp.analysis.window_exceeded", FT_NONE, BASE_NONE, NULL, 0x0,
            "All or a portion of this segment may have exceeded the receiver's window size", HFILL }},


        /* TCP checksum-related fields */
        { &hf_tcp_checksum,
          { "Checksum", "tcp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
            "Details at: http://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html", HFILL }},

        { &hf_tcp_checksum_good,
          { "Good Checksum", "tcp.checksum_good", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "True: checksum matches packet content; False: doesn't match content or not checked", HFILL }},

        { &hf_tcp_checksum_bad,
          { "Bad Checksum", "tcp.checksum_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "True: checksum doesn't match packet content; False: matches content or not checked", HFILL }},


        /* TCP options-related fields */
        { &hf_tcp_options,
          { "TCP Options","tcp.options", FT_BOOLEAN, 
            BASE_DEC, NULL, 0x0, "The TCP options field", HFILL }},

        { &hf_tcp_options_len,
          { "Options length", "tcp.options_len", FT_UINT8,
            BASE_DEC, NULL, 0x0, "Total length of the TCP option fields", HFILL }},

        { &hf_tcp_option_kind,
          { "Kind", "tcp.option_kind", FT_UINT8,
            BASE_DEC, VALS(tcp_option_kind_vs), 0x0, "This TCP option's kind", HFILL }},

        { &hf_tcp_option_len,
          { "Length", "tcp.option_len", FT_UINT8,
            BASE_DEC, NULL, 0x0, 
            "Length of this TCP option in bytes including the kind and length fields", HFILL }},

        { &hf_tcp_option_mss,
          { "TCP MSS Option", "tcp.options.mss", FT_BOOLEAN,
            BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_mss_val,
          { "TCP MSS Option Value", "tcp.options.mss_val", FT_UINT16,
            BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_wscale_shift,
          { "Shift count", "tcp.options.wscale.shift", FT_UINT8,
            BASE_DEC, NULL, 0x0, "Logarithmically encoded power of 2 scale factor", HFILL}},

        { &hf_tcp_option_wscale_multiplier,
          { "Multiplier", "tcp.options.wscale.multiplier",  FT_UINT8,
            BASE_DEC, NULL, 0x0, 
            "Multiply segment window size by this for scaled window size", HFILL}},

        { &hf_tcp_option_sack_perm,
          { "TCP SACK Permitted Option", "tcp.options.sack_perm", FT_BOOLEAN,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_sack,
          { "SACK", "tcp.options.sack", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
            "Each sequence number pair in parentheses has been Selectively ACKed", HFILL}},

        { &hf_tcp_option_sack_triggered_by_ack,
          { "Triggered by an ACK update", "tcp.options.sack_trig_ack", FT_BYTES, BASE_NONE, NULL, 0x0, 
            "This packet was triggered by a update of the acknowledgement number. SACK info may not have changed", HFILL}},

        { &hf_tcp_option_sack_triggered_by_dsack,
          { "Triggered by a DSACK block", "tcp.options.sack_trig_dsack", FT_BYTES, BASE_NONE, NULL, 0x0, 
            "The data receiver has indicated that duplicate data has been received", HFILL}},

        { &hf_tcp_option_sack_triggered_by_new_block,
          { "Triggered by a new SACK block", "tcp.options.sack_trig_newblock", FT_BYTES, BASE_NONE, NULL, 0x0, 
            "A segment has been received (shown in the first SACK block) which has produced a gap in the byte stream.", HFILL}},
            
        { &hf_tcp_option_sack_triggered_by_block_update,
          { "Triggered by an ACK update", "tcp.options.sack_trig_block_update", FT_BYTES, BASE_NONE, NULL, 0x0, 
            "An existing SACK block has been updated", HFILL}},
            
        { &hf_tcp_option_sack_triggered_by_data,
          { "Triggered by new data", "tcp.options.sack_trig_data", FT_NONE, BASE_NONE, NULL, 0x0, 
            "The data receiver had new data to send. The SACK info in this packet may not have changed.", HFILL}},
            
        { &hf_tcp_option_sack_triggered_by_unknown,
          { "Triggered for unknown reasons", "tcp.options.sack_trig_unknown", FT_BYTES, BASE_NONE, NULL, 0x0, 
            "It is not clear why this SACK info was sent. This packet may have been duplicated by the network.", HFILL}},
                      
        { &hf_tcp_option_included_sackblks,
          { "Included SACK blocks", "tcp.options.sack", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
             "Ordered list of SACK blocks that are included in this packet", HFILL}},

        { &hf_tcp_option_sack_sle,
          {"TCP SACK Left Edge", "tcp.options.sack_le", FT_UINT32,
           BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_sack_sre,
          {"TCP SACK Right Edge", "tcp.options.sack_re", FT_UINT32,
           BASE_DEC, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_sack_invalid_block,
          { "Invalid SACK blocks", "tcp.options.sack_invalid", FT_NONE, BASE_NONE, NULL, 0x0,
             "This can be caused by a firewall or proxy device that does not properly support SACK.", HFILL}},

        { &hf_tcp_option_active_sackblks,
          { "Active SACK blocks and gaps", "tcp.options.sack", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
             "Ordered list of active SACK blocks some of which might not be included in this packet", HFILL}},

        { &hf_tcp_option_sack_block,
          { "SACK block", "tcp.options.sack_block", FT_BYTES, BASE_NONE, NULL, 0x0, 
            "Active SACK block", HFILL}},

        { &hf_tcp_option_sack_total_blocks,
          { "Total blocks", "tcp.options.sack_total_blocks", FT_UINT16,
            BASE_DEC, NULL, 0x0, "Total number of active (unACKed) SACK blocks", HFILL}},

        { &hf_tcp_option_sack_total_gaps,
          { "Total Gaps", "tcp.options.sack_total_gaps", FT_UINT32,
            BASE_DEC, NULL, 0x0, "Total gaps (unACKed bytes) in the reverse flow", HFILL}},
       
        { &hf_tcp_option_sack_ack_to_fack,
          { "ACK to FACK", "tcp.options.sack_ack_to_fack", FT_UINT32,
            BASE_DEC, NULL, 0x0, 
            "The number of bytes from the ACK to the highest SACKed seq (snd.fack)", HFILL}},

        { &hf_tcp_option_echo,
          { "TCP Echo Option", "tcp.options.echo", FT_BOOLEAN,
            BASE_NONE, NULL, 0x0, "TCP Sack Echo", HFILL}},

        { &hf_tcp_option_echo_reply,
          { "TCP Echo Reply Option", "tcp.options.echo_reply", FT_BOOLEAN,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_timestamps,
          { "Timestamps (TSval and TSecr) values","tcp.options.timestamps", FT_BOOLEAN,
            BASE_DEC, NULL, 0x0, "TSval and TSecr pair", HFILL }},

        { &hf_tcp_option_timestamp_tsval,
          { "Timestamp value", "tcp.options.timestamp.tsval", FT_UINT32,
            BASE_DEC, NULL, 0x0, "Value of sending host's timestamp clock", HFILL}},

        { &hf_tcp_option_timestamp_tsecr,
          { "Timestamp echo reply", "tcp.options.timestamp.tsecr", FT_UINT32,
            BASE_DEC, NULL, 0x0, "Echoed timestamp from remote host", HFILL}},


        { &hf_tcp_option_cc,
          { "TCP CC Option", "tcp.options.cc", FT_BOOLEAN, 
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_ccnew,
          { "TCP CC New Option", "tcp.options.ccnew", FT_BOOLEAN,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_ccecho,
          { "TCP CC Echo Option", "tcp.options.ccecho", FT_BOOLEAN,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_md5,
          { "TCP MD5 Option", "tcp.options.md5", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_qs,
          { "TCP QS Option", "tcp.options.qs", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_scps,
          { "TCP SCPS Capabilities Option", "tcp.options.scps",
            FT_BOOLEAN, BASE_NONE, NULL,  0x0,
            NULL, HFILL}},

        { &hf_tcp_option_scps_vector,
          { "TCP SCPS Capabilities Vector", "tcp.options.scps.vector",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_option_scps_binding,
          { "TCP SCPS Extended Binding Spacce",
            "tcp.options.scps.binding",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "TCP SCPS Extended Binding Space", HFILL}},

        { &hf_tcp_option_snack,
          { "TCP Selective Negative Acknowledgement Option",
            "tcp.options.snack",
            FT_BOOLEAN, BASE_NONE, NULL,  0x0,
            NULL, HFILL}},

        { &hf_tcp_option_snack_offset,
          { "TCP SNACK Offset", "tcp.options.snack.offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_option_snack_size,
          { "TCP SNACK Size", "tcp.options.snack.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_option_snack_le,
          { "TCP SNACK Left Edge", "tcp.options.snack.le",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_option_snack_re,
          { "TCP SNACK Right Edge", "tcp.options.snack.re",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_scpsoption_flags_bets,
          { "Partial Reliability Capable (BETS)",
            "tcp.options.scpsflags.bets", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x80, NULL, HFILL }},

        { &hf_tcp_scpsoption_flags_snack1,
          { "Short Form SNACK Capable (SNACK1)",
            "tcp.options.scpsflags.snack1", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x40, NULL, HFILL }},

        { &hf_tcp_scpsoption_flags_snack2,
          { "Long Form SNACK Capable (SNACK2)",
            "tcp.options.scpsflags.snack2", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x20, NULL, HFILL }},

        { &hf_tcp_scpsoption_flags_compress,
          { "Lossless Header Compression (COMP)",
            "tcp.options.scpsflags.compress", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x10, NULL, HFILL }},

        { &hf_tcp_scpsoption_flags_nlts,
          { "Network Layer Timestamp (NLTS)",
            "tcp.options.scpsflags.nlts", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x8, NULL, HFILL }},

        { &hf_tcp_scpsoption_flags_resv1,
          { "Reserved Bit 1",
            "tcp.options.scpsflags.reserved1", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x4, NULL, HFILL }},

        { &hf_tcp_scpsoption_flags_resv2,
          { "Reserved Bit 2",
            "tcp.options.scpsflags.reserved2", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x2, NULL, HFILL }},

        { &hf_tcp_scpsoption_flags_resv3,
          { "Reserved Bit 3",
            "tcp.options.scpsflags.reserved3", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x1, NULL, HFILL }},

        { &hf_tcp_option_mood,
          { "TCP Mood Option", "tcp.options.mood", FT_BOOLEAN,
            BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_mood_val,
          { "TCP Mood Option Value", "tcp.options.mood_val", FT_STRING,
            BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_tcp_option_user_to,
          { "TCP User Timeout", "tcp.options.user_to", FT_BOOLEAN,
            BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_user_to_granularity,
          { "Granularity", "tcp.options.user_to_granularity", FT_BOOLEAN,
            16, TFS(&tcp_option_user_to_granularity), 0x8000, "TCP User Timeout Granularity", HFILL}},

        { &hf_tcp_option_user_to_val,
          { "User Timeout", "tcp.options.user_to_val", FT_UINT16,
            BASE_DEC, NULL, 0x7FFF, "TCP User Timeout Value", HFILL}},

        { &hf_tcp_option_rvbd_probe,
          { "Riverbed Probe", "tcp.options.rvbd.probe", FT_BOOLEAN,
            BASE_NONE, NULL, 0x0, "RVBD TCP Probe Option", HFILL }},

        { &hf_tcp_option_rvbd_probe_type1,
          { "Type", "tcp.options.rvbd.probe.type1",
            FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_type2,
          { "Type", "tcp.options.rvbd.probe.type2",
            FT_UINT8, BASE_DEC, NULL, 0xFE, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_version1,
          { "Version", "tcp.options.rvbd.probe.version",
            FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_version2,
          { "Version", "tcp.options.rvbd.probe.version_raw",
            FT_UINT8, BASE_DEC, NULL, 0x01, "Version 2 Raw Value", HFILL }},

        { &hf_tcp_option_rvbd_probe_optlen,
          { "Length", "tcp.options.rvbd.probe.len",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_prober,
          { "CSH IP", "tcp.options.rvbd.probe.prober",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_proxy,
          { "SSH IP", "tcp.options.rvbd.probe.proxy.ip",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_proxy_port,
          { "SSH Port", "tcp.options.rvbd.probe.proxy.port",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_appli_ver,
          { "Application Version", "tcp.options.rvbd.probe.appli_ver",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_client,
          { "Client IP", "tcp.options.rvbd.probe.client.ip",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_storeid,
          { "CFE Store ID", "tcp.options.rvbd.probe.storeid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_flags,
          { "Probe Flags", "tcp.options.rvbd.probe.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_flag_not_cfe,
          { "Not CFE", "tcp.options.rvbd.probe.flags.notcfe",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), RVBD_FLAGS_PROBE_NCFE,
            NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_flag_last_notify,
          { "Last Notify", "tcp.options.rvbd.probe.flags.last",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), RVBD_FLAGS_PROBE_LAST,
            NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_flag_probe_cache,
          { "Disable Probe Cache on CSH", "tcp.options.rvbd.probe.flags.probe",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), RVBD_FLAGS_PROBE,
            NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_flag_sslcert,
          { "SSL Enabled", "tcp.options.rvbd.probe.flags.ssl",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), RVBD_FLAGS_PROBE_SSLCERT,
            NULL, HFILL }},

        { &hf_tcp_option_rvbd_probe_flag_server_connected,
          { "SSH outer to server established", "tcp.options.rvbd.probe.flags.server",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), RVBD_FLAGS_PROBE_SERVER,
            NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy,
          { "Riverbed Transparency", "tcp.options.rvbd.trpy",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "RVBD TCP Transparency Option", HFILL }},

        { &hf_tcp_option_rvbd_trpy_flags,
          { "Transparency Options", "tcp.options.rvbd.trpy.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy_flag_fw_rst_probe,
          { "Enable FW traversal feature", "tcp.options.rvbd.trpy.flags.fw_rst_probe",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset),
            RVBD_FLAGS_TRPY_FW_RST_PROBE,
            "Reset state created by probe on the nexthop firewall",
            HFILL }},

        { &hf_tcp_option_rvbd_trpy_flag_fw_rst_inner,
          { "Enable Inner FW feature on All FWs", "tcp.options.rvbd.trpy.flags.fw_rst_inner",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset),
            RVBD_FLAGS_TRPY_FW_RST_INNER,
            "Reset state created by transparent inner on all firewalls"
            " before passing connection through",
            HFILL }},

        { &hf_tcp_option_rvbd_trpy_flag_fw_rst,
          { "Enable Transparency FW feature on All FWs", "tcp.options.rvbd.trpy.flags.fw_rst",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset),
            RVBD_FLAGS_TRPY_FW_RST,
            "Reset state created by probe on all firewalls before "
            "establishing transparent inner connection", HFILL }},

        { &hf_tcp_option_rvbd_trpy_flag_chksum,
          { "Reserved", "tcp.options.rvbd.trpy.flags.chksum",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset),
            RVBD_FLAGS_TRPY_CHKSUM, NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy_flag_oob,
          { "Out of band connection", "tcp.options.rvbd.trpy.flags.oob",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset),
            RVBD_FLAGS_TRPY_OOB, NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy_flag_mode,
          { "Transparency Mode", "tcp.options.rvbd.trpy.flags.mode",
            FT_BOOLEAN, 16, TFS(&trpy_mode_str),
            RVBD_FLAGS_TRPY_MODE, NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy_src,
          { "CSH IP Addr", "tcp.options.rvbd.trpy.src.ip",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy_dst,
          { "SSH IP Addr", "tcp.options.rvbd.trpy.dst.ip",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy_src_port,
          { "CSH Inner Port", "tcp.options.rvbd.trpy.src.port",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy_dst_port,
          { "SSH Inner Port", "tcp.options.rvbd.trpy.dst.port",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_tcp_option_rvbd_trpy_client_port,
          { "Out of band connection Client Port", "tcp.options.rvbd.trpy.client.port",
            FT_UINT16, BASE_DEC, NULL , 0x0, NULL, HFILL }},


        /* Delta time ("Timestamps")-related fields */
        { &hf_tcp_ts_relative,
          { "Time since first frame in this TCP stream", "tcp.time_relative",
             FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
             "Time relative to first frame in this TCP stream", HFILL}},

        { &hf_tcp_ts_delta,
          { "Time since previous frame in this TCP stream", "tcp.time_delta", 
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "Time delta from previous frame in this TCP stream", HFILL}},

        //{ &hf_tcp_est_rtt,
        //  { "Estimated RTT", "tcp.est_rtt", 
        //    FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        //    "RTT estimate based on 3-way handshake and avg. time to ACK retransmissions", HFILL}},

        /* TCP reassembly and PDU-related fields */
        { &hf_tcp_segments,
          { "Reassembled TCP Segments", "tcp.segments", FT_NONE, BASE_NONE, NULL, 0x0,
            "TCP Segments", HFILL }},

        { &hf_tcp_reassembled_in,
          { "Reassembled PDU in frame", "tcp.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "The PDU that doesn't end in this segment is reassembled in this frame", HFILL }},

        { &hf_tcp_reassembled_length,
          { "Reassembled TCP length", "tcp.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL }},

        { &hf_tcp_pdu_time,
          { "Time until the last segment of this PDU", "tcp.pdu.time", 
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "How long time has passed until the last frame of this PDU", HFILL}},

        { &hf_tcp_pdu_size,
          { "PDU Size", "tcp.pdu.size", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The size of this PDU", HFILL}},

        { &hf_tcp_pdu_last_frame,
          { "Last frame of this PDU", "tcp.pdu.last_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This is the last frame of the PDU starting in this segment", HFILL }},

        { &hf_tcp_continuation_of,
          { "Continuation of the PDU in frame", "tcp.continuation_to",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          "Continuation of the PDU in frame #", HFILL }},

        { &hf_tcp_segment_count,
          { "Segment count", "tcp.segment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_segment,
          { "TCP Segment", "tcp.segment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_tcp_segment_overlap,
          { "Segment overlap",    "tcp.segment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Segment overlaps with other segments", HFILL }},

        { &hf_tcp_segment_overlap_conflict,
          { "Conflicting data in segment overlap", "tcp.segment.overlap.conflict",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Overlapping segments contained conflicting data", HFILL }},

        { &hf_tcp_segment_multiple_tails,
          { "Multiple tail segments found",   "tcp.segment.multipletails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when reassembling the pdu", HFILL }},

        { &hf_tcp_segment_too_long_fragment,
          { "Segment too long",   "tcp.segment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Segment contained data past end of the pdu", HFILL }},

        { &hf_tcp_segment_error,
          { "Reassembly error", "tcp.segment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Reassembly error due to illegal segments", HFILL }},


        /* Process-releated fields */
        { &hf_tcp_proc_src_uid,
          { "Source process user ID", "tcp.proc.srcuid", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_proc_src_pid,
          { "Source process ID", "tcp.proc.srcpid", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_proc_src_uname,
          { "Source process user name", "tcp.proc.srcuname", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_proc_src_cmd,
          { "Source process name", "tcp.proc.srccmd", FT_STRING, BASE_NONE, NULL, 0x0,
            "Source process command name", HFILL}},

        { &hf_tcp_proc_dst_uid,
          { "Destination process user ID", "tcp.proc.dstuid", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_proc_dst_pid,
          { "Destination process ID", "tcp.proc.dstpid", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_proc_dst_uname,
          { "Destination process user name", "tcp.proc.dstuname", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}},

        { &hf_tcp_proc_dst_cmd,
          { "Destination process name", "tcp.proc.dstcmd", FT_STRING, BASE_NONE, NULL, 0x0,
            "Destination process command name", HFILL}}
    };

    static gint *ett[] = {
        &ett_tcp,
        &ett_tcp_sequence_analysis,
        &ett_tcp_ack_analysis,
        &ett_tcp_flags,
        &ett_tcp_window_size_scale,
        &ett_tcp_checksum,
        &ett_tcp_options,
        &ett_tcp_option_window_scale,
        &ett_tcp_option_sack,
        &ett_tcp_option_included_sackblks,
        &ett_tcp_option_active_sackblks,
        &ett_tcp_option_timestamps,
        &ett_tcp_option_scps,
        &ett_tcp_option_scps_extended,
        &ett_tcp_option_user_to,
        &ett_tcp_delta_times,
        &ett_tcp_segments,
        &ett_tcp_segment ,
        &ett_tcp_process_info,
        &ett_tcp_opt_rvbd_probe,
        &ett_tcp_opt_rvbd_probe_flags,
        &ett_tcp_opt_rvbd_trpy,
        &ett_tcp_opt_rvbd_trpy_flags
    };
    module_t *tcp_module;

    proto_tcp = proto_register_protocol("Transmission Control Protocol",
        "TCP", "tcp");
    proto_register_field_array(proto_tcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* subdissector code */
    subdissector_table = register_dissector_table("tcp.port",
        "TCP port", FT_UINT16, BASE_DEC);
    register_heur_dissector_list("tcp", &heur_subdissector_list);

    /* Register configuration preferences */
    tcp_module = prefs_register_protocol(proto_tcp, NULL);
    prefs_register_bool_preference(tcp_module, "try_heuristic_first",
        "Try heuristic sub-dissectors first",
        "Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to a specific port",
        &try_heuristic_first);
    prefs_register_bool_preference(tcp_module, "desegment_tcp_streams",
        "Allow subdissector to reassemble TCP streams",
        "Whether subdissector can request TCP streams to be reassembled",
        &tcp_desegment);
    prefs_register_bool_preference(tcp_module, "check_checksum",
        "Validate the TCP checksum if possible",
        "Whether to validate the TCP checksum",
        &tcp_check_checksum);

    //prefs_register_enum_preference(tcp_module, "manually_set_wsf",
    //    "Scaling factor (WSF) to apply to windows advertised by the opposite flow "
    //    "FOR THIS FLOW ONLY when the WSF is UNKNOWN.",
    //    "If the WSF is UNKNOWN in the opposite flow, it must also be set for that flow.",
    //    &manually_set_wsf_pref, window_scaling_vals, FALSE);

    /* Presumably a retired, unconditional version of what has been added back with the preference above... */
    prefs_register_obsolete_preference(tcp_module, "window_scaling");
    
    prefs_register_bool_preference(tcp_module, "calculate_timestamps",
        "Calculate conversation timestamps",
        "Calculate timestamps relative to the first frame and the previous frame of a given TCP connection",
        &tcp_calculate_ts);
    prefs_register_bool_preference(tcp_module, "display_ports_in_packet_list",
        "Display the port number pair in the Packet List",
        "Whether the TCP port number pair (e.g., \"445 > 1906\") should be shown in the Packet List",
        &display_ports_in_packet_list);
    prefs_register_bool_preference(tcp_module, "display_len_in_packet_list",
        "Display the segment length in the Packet List",
        "Whether to display the length of the TCP data in this packet in Packet List",
        &display_len_in_packet_list);
    prefs_register_bool_preference(tcp_module, "display_timestamps_in_summary",
        "Display TCP timestamp (TSval/TSecr) values in the Packet List and Options header",
        "Display TS Value and TS Echo Reply in the Info column and the TCP Options header in Packet Details",
        &tcp_display_timestamps_in_summary);
    prefs_register_bool_preference(tcp_module, "summary_in_tcp_tree_header",
        "Display TCP summary info in TCP tree header",
        "Whether TCP summary info should be appended to the TCP tree header in Packet Details",
        &summary_in_tcp_tree_header);    
    prefs_register_bool_preference(tcp_module, "only_display_ack_flag_in_packet_list_when_needed",
        "Display the ACK flag in the Packet List only when needed",
        "Only display the ACK flag Packet List if the SYN or FIN flags are set, or for an ACK of a SYN-ACK or FIN",
        &only_display_ack_flag_in_packet_list_when_needed);

    prefs_register_bool_preference(tcp_module, "analyze_sequence_numbers",
        "Analyze TCP sequence numbers",
        "Analyze TCP sequence numbers in order to detect such things as retransmissions and unseen segments",
        &tcp_analyze_seq);

    prefs_register_static_text_preference(tcp_module, "analysis_prefs", 
        "********************** The following require \"Analyze TCP sequence numbers\" to be checked *********************************************"
        " ", ""); 

    prefs_register_bool_preference(tcp_module, "relative_sequence_numbers",
        "Relative sequence numbers",
        "Make the TCP dissector use relative sequence numbers instead of absolute ones. "
        "To use this option you must also enable \"Analyze TCP sequence numbers\". ",
        &tcp_relative_seq);

    prefs_register_bool_preference(tcp_module, "track_bytes_in_flight",
        "Track number of unACKed bytes and bytes-in-flight",
        "Track the number of un-ACKed bytes and bytes in flight per packet. Each can be plotted in IO Graphs."
        "To use this option you must also enable \"Analyze TCP sequence numbers\". ",
        &tcp_track_unacked_and_bif);
    prefs_register_uint_preference(tcp_module, "rto_period", "Set the retransmssion timeout period to (milliseconds)",
        "The retransmission timeout interval to apply when testing for RTO retransmissions.",
        10, &tcp_rto_period);
    prefs_register_enum_preference(tcp_module, "side_cap_taken",
        "Side on which the capture was taken:",
        "Was the capture taken on the sender or should this be auto-detected?",
        &sender_side_cap,
        tcp_side_cap_taken,
        TRUE);

    register_init_routine(tcp_fragment_init);
}

void
proto_reg_handoff_tcp(void)
{
    dissector_handle_t tcp_handle;

    tcp_handle = create_dissector_handle(dissect_tcp, proto_tcp);
    dissector_add_uint("ip.proto", IP_PROTO_TCP, tcp_handle);
    data_handle = find_dissector("data");
    tcp_tap = register_tap("tcp");
}

/*
   Editor modelines
 *
   Local Variables:
   c-basic-offset: 4
   tab-width: 8
   indent-tabs-mode: nil
   End:
 *
   ex: set shiftwidth=4 tabstop=8 expandtab
   :indentSize=4:tabSize=8:noTabs=true:
 */
