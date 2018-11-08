/* packet-tcp.h
 *
 * $Id: packet-tcp.h 35425 2011-01-08 15:51:38Z sake $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_TCP_H__
#define __PACKET_TCP_H__

#ifndef __CONVERSATION_H__
#include <epan/conversation.h>
#endif

/* TCP flags */
#define TH_FIN   0x01
#define TH_SYN   0x02
#define TH_RST   0x04
#define TH_PUSH  0x08
#define TH_ACK   0x10
#define TH_URG   0x20
#define TH_ECN   0x40
#define TH_CWR   0x80
#define TH_NS    0x100
#define TH_RES   0xE00 /* 3 reserved bits */

/* Sequence number comparison functions that mitigate number wrapping.
*/
#define GT_SEQ(x, y) ((gint32)((y)-(x)) <  0)
#define GE_SEQ(x, y) ((gint32)((y)-(x)) <= 0)
#define LT_SEQ(x, y) ((gint32)((x)-(y)) <  0)
#define LE_SEQ(x, y) ((gint32)((x)-(y)) <= 0)
#define EQ_SEQ(x, y) (x==y)  /* (XXX: Should this be deleted since it provides no benefit?) */

/* IP ID comparison functions that mitigate number wrapping. Compare x to y and return TRUE if the 
*  difference between them is less than z. 
*/
#define GT_ID(x, y, z) ((gint16)((y)-(x)) <  0 ? ABS((gint16)((y)-(x))-1) < z : FALSE)
#define GE_ID(x, y, z) ((gint16)((y)-(x)) <= 0 ? ABS((gint16)((y)-(x))-1) < z : FALSE)
#define LT_ID(x, y, z) ((gint16)((x)-(y)) <  0 ? ABS((gint16)((x)-(y))-1) < z : FALSE)
#define LE_ID(x, y, z) ((gint16)((x)-(y)) <= 0 ? ABS((gint16)((x)-(y))-1) < z : FALSE)


/* the tcp header structure, passed to tap listeners */
typedef struct tcpheader {
    guint32 th_seq;
    guint32 th_ack;
    guint32 th_seglen;
    guint32 th_win;          /* make it 32 bits so we can handle some scaling */
    guint16 th_sport;
    guint16 th_dport;
    guint8  th_hlen;
    guint16 th_flags;
    address ip_src;
    address ip_dst;
} tcp_info_t;

/*
* Private data passed from the TCP dissector to subdissectors. Passed to the
* subdissectors in pinfo->private_data*/
struct tcpinfo {
    guint32 seq;             /* Sequence number of first byte in the data */
    guint32 nxtseq;          /* Sequence number of first byte after data */
    guint32 win;             /* Window size */
    guint32 lastackseq;      /* Sequence number of last ack */
    gboolean is_reassembled; /* This is reassembled data. */
    gboolean urgent;         /* TRUE if "urgent_pointer" is valid */
    guint16  urgent_pointer; /* Urgent pointer value for the current packet. */
    emem_strbuf_t *tcp_flags;
};


/******************************* Definitions of structs used in SLAB Lists ***********************************
*
* UnACKed segments 
  The current list of unACKed segments, "ua_segs_l" list consists of these (ua_segment_t) "ua_seg" structs.*/
typedef struct _ua_segment_t {
    struct _ua_segment_t *next;
    guint32  frame;
    nstime_t ts;
    guint16  ip_id;        /* Used to detect duplicate frames */
    guint32  seq;
    guint32  nextseq;
    guint32  ack;          /* Used to detect duplicate frames */
    guint16  flags;        /* Used to detect duplicate frames */
    guint32  win;          /* Used to detect duplicate frames */
    guint32  unacked;
    gboolean rxmted;       /* TRUE if this segment has been retransmitted (used for RE-retransmission detection) */
} ua_segment_t;

/* UnACKed retransmissions sent while in TCP recovery. The ua_rxmts_in_rec_l list consists of these ("ua_rxmts")
   structs. */
typedef struct _ua_rxmts_in_rec {
    struct _ua_rxmts_in_rec *next;
    guint32 frame;
    guint32 seq;
    guint32 nextseq;
    guint16 seglen;
} ua_rxmts_in_rec_t;

/* 
 The struct 'prev_seg_unseen_t' is used to store info about 'Previous packet unseen' and 'TCP ACK of unseen segment
 packets. The prev_seg_miss_l list consists of these "psu" structs and is essentially a list of gaps that is used
 for determining if a segment that arrives whose range falls fully or partially within one of these gaps is a
 retransmission or was delivered out-of-order. There are three ways that psu entries are generated:

  1. Frame arrives with seq > tcpd->fwd->nextseq (the highest nextseq seen thus far in the fwd flow)
     Set: ta_send->flags |= TCP_PREV_PACKET_UNSEEN
     Set: psu->trigger    = PSU_TRIGGERED_BY_SEQ 
          psu->ack_only   = FALSE
          psu->lbound     = tcpd->fwd->nextseq
          psu->ubound     = seq
          psu->seq        = 0 (not used because ubound = seq)
          psu->ack        = ack
          psu->nextseq    = nextseq
          psu->ip_id      = pinfo->ip_id (0 if tcpd->fwd->invalid)
          psu->unacked    = total number of unACKed/unSACKed bytes including this segment

  2. Frame arrives with ack > tcpd->rev->nextseq ((the highest nextseq seen thus far in the *rev flow)
     Set: ta_recv->flags |= TCP_ACK_OF_UNSEEN_SEGMENT
     Set: psu->trigger    = PSU_TRIGGERED_BY_ACK
          psu->ack_only   = TRUE or FALSE
          psu->lbound     = tcpd->rev->nextseq
          psu->ubound     = ack
          psu->seq        = seq (used as a sanity check for detecting frame reordering)
          psu->ack        = (not used because ubound = ack)  
          psu->nextseq      (not used)
          psu->ip_id      = pinfo->ip_id  (0 if tcpd->rev->invalid)
          psu->unacked    = 0 (not used) 

 3. Frame arrives with one or more SACK blocks
     Set: ta_recv->flags |= TCP_ACK_OF_UNSEEN_SEGMENT
     Set: psu->trigger    = PSU_TRIGGERED_BY_ACK
          psu->ack_only   = FALSE
          psu->lbound     = ack if block 1, sre of the previous block for blocks 2-n
          psu->ubound     = sle
          psu->seq          (not used)
          psu->ack          (not used)
          psu->nextseq      (not used)
          psu->ip_id      = pinfo->ip_id  (0 if tcpd->rev->invalid)
          psu->unacked      (not used) 

 The rules for detecting retransmissions and reordered packets based on the psu info:

   Case A:  A packet arrives with nextseq < tcpd->fwd->nextseq, and falls within the gap of a PSU_TRIGGERED_BY_SEQ psu.
    
   Case B:  A packet arrives with seq < tcpd->fwd->nextseq, and falls within the gap of a PSU_TRIGGERED_BY_ACK psu.

            In some cases the ACK-only packet refered to in this psu is marked out-of-order instead of marking segments
            that fall below this ACk as out-of-order.  

   Case C:  A packet arrives with seq < tcpd->fwd->nextseq, and falls within the gap of a PSU_TRIGGERED_BY_SACK_GAP psu.

            Scenarios:

            Type-1. A gap was found before seq in the fwd flow:
                    Determine if this is a retransmission or was delivered out-of-order and      
                    label it accordingly.

            Type-2. A gap was found before an ack from the rev flow:
                    Determine which of the following has occurred:
                    a. The data-carrying frame was delivered out-of-order and was actually sent
                       prior to the ACK-only frame. Label the data-carrying frame as
                       out-of-order.
                    b. The data-carrying frame was delivered *in-order* but the ACK-only frame
                       was delivered *out-of-order*: Rather than labeling the data-carrying frame
                       as a retransmission, change the flag in the ACK-only frame from
                       TCP_ACK_OF_UNSEEN_SEGMENT to TCP_ACK_ONLY_OUT_OF_ORDER and store the
                       frame# of this frame in the other frame's ta_recv->ooo_belongs_after.
                    c. The ACK of a segment is packet is present in the capture but an RTO occurs
                       because the ACK was lost or arrived after the sender's retransmission timer
                       expired (perhaps because the senders timer is too short).
                       Label the segment as an RTO and set ta_recv->ack_lost. The message "ACK
                       appears to have been lost" ll be displayed in the sequence tree.

            Type-3. A frame arrives that falls within the gap prior to the SACK block:
                    label it as a retransmission.  

 Accurate detection of each of these scenarios allows for an entire block of frames including ACK-only packets
 to be correctly labeled as out-of-order even when an ACK acknowledges a seq# in a frame that was itself
 reordered. 

 The "psu" entries in the prev_seg_miss_l list consist of prev_seg_unseen_t structs that define the boundaries
 of the gaps preceeding segments in the fwd flow and gaps prior to ACKs in the opposite flow.
 
 A "dummy" psu entry is created for out-of-order frames with seq numbers less than the first frame in that flow
 added to the tcpd->prev_seg_miss_l list; however, gaps prior to SACK blocks (sackb's) are *not* included in
 that list but are instead detected by examining entrie in sackb_l, the list of active SACK blocks.
*/
typedef struct _prev_seg_unseen_t {
    struct _prev_seg_unseen_t *next;
    guint32 frame;          /* Frame number of the frame flagged as "Previous segment unseen" */
    nstime_t ts;
    guint8 trigger;         /* Indicates whether this psu entry was triggered by a seq# in the fwd flow
                               or an ACK in the rev flow. */
    gboolean 
        ack_only_no_sack;   /* The frame contained neither sack blocks nor data */
    guint32 lbound;         /* Gap's lower boundary: If ack_of_miss, tcpd->REV->nextseq; if the dummy entry;
                               otherwise, tcpd->FWD->nextseq */
    guint32 ubound;         /* Gap's upper boundary: if ack_of_miss, ack; if ACK-only ooo, nextseq of ACKed
                               frame; if the dummy entry, 0; otherwise, seq */
    guint32 seq;            /* This var and the next 4 are used to detect if this psu frame was out-of-order */
    guint32 nextseq;
    guint32 ack;            /* If the dummy entry, tcpd->REV->ack, if ACK-only ooo, tcpd->FWD->ack; otherwise. */
    guint16 ip_id;
    guint16 ip_id_high_rev; /* The highest ip_id value seen in the rev flow when this psu was processed */
    guint32 unacked;        /* The number of unACKed bytes when the frame was processed */
} prev_seg_unseen_t;

/*
 The (sackb_in_this_frame_t) sackb_fr[] array is comprised of these sackb_in_this_frame_t structs which
 reside in the current frame. Info in each (sackb_in_this_frame_t) struct is copied to a (sackb_t) sackb.
 Info in each active sackb is copied to a (saved_sackb_t) saved_sackb_l struct and each saved_sackb_l is
 stored in a (saved_sackb_l_t) saved_sackb_l as a member of the saved_sackb_l->arr array which is the 
 list of active (unACKed) SACK blocks (saved_sackb blocks) when this frame was received.
*/
typedef struct sackb_in_this_frame_t {
    int       offset;
    guint32   sle;
    guint32   sre;
    guint8   *p_sackb_bytes;
    gboolean  dsack_blk;
    gboolean  sack_of_unseen;
} sackb_in_this_frame_t;

/*
 The sackb_l list is comprised of active (sackb_t) block entries. In the first pass
 tcp_analyze_sequence_number() uses this list to determine if a segment is a retransmission or
 out-of-order. Each sackb struct is stored in the saved_sackb_l persistent list for display in
 the tree after the first pass. 
 */
typedef struct _sackb_t {
    struct _sackb_t *next;
    guint32 frame;            /* frame# that contained this sackb */
    int        offset;        /* The tvb offset of the SACK block if this sackb is included in this packet */
    guint32    seq;           /* The left-hand boundary of this sackb */
    guint32    nextseq;       /* The right-hand boundary of this sackb */
    guint32    ack;           /* Useful for detecting frame reordering and zero if the block is still
                                  active but not included in this packet. */
    guint8   *p_sackb_bytes;  /* Pointer to the 8 bytes for this block copied from tvb and saved in
                                 saved_sackb_l because the block was still active (unACKed) but was not
                                 included in the SACK options. If the user filters on this block the,
                                 8 bytes will be copied from this location rather than from the tvb. */
    gboolean  sack_of_unseen; /* TRUE if the segment referred to by this sackb was not seen when this
                                 sackb arrived */
    gboolean  invalid;        /* TRUE if the SACK block is more than one max window size less than the ACK or
                                 more than one max window size greater than the highest nextseq seen in the rev
                                 flow. Such bogus blocks are typically the result of proxy devices that do not
                                 properly handle SACK. */
} sackb_t;

/***************************** End of definitions used in SLAB lists ******************************************/


/**************************** Definitions of structs used in PERSISTENT Lists *********************************

 These are essentially snapshots of values when a given frame was first dissected and are typically used for
 populating the tree with TCP analysis info. The variables have been separated into seperate lists by category
 in order to conserve memory rather than one persistent list of giant structs.

***************************** SENDER-related structs used in PERSISTENT per-packet lists ********************************

 Struct that keeps per-packet data. One exists for every TCP frame in the capture if 'tcp_calculate_ts or
 'tcp_track_unacked_and_bif' is set.
 The 'pinfo->fd->pfd list' consists of these ("tcppd") structs. */
typedef struct tcp_per_packet_data_t {
    nstime_t ts_del;                /* Time_delta from the last seen frame in this TCP conversation */
    guint32   bif;                  /* Number of bytes in this flow considered to be still "on the wire" */
    guint32   unacked;              /* Total number of unACKed/unSACKed bytes including those in this packet */
    guint32   highest_ack_rev;      /* The highest ACK in the reverse flow */
    gboolean  display_ack;          /* TRUE if the previous packet in the reverse flow was a SYN-ACK or a FIN */
} tcp_per_packet_data_t;

/* TCP sender-related info for NON-retransmitted frames and frames that were lost and later retransmitted.
   The "ta_send_table" consists of these "ta_send" structs indexed by frame number. */
typedef struct ta_send_t {
    guint32   flags;                /* Flags such as TCP_PREV_PACKET_LOST, TCP_OUT_OF_ORDER, and TCP_ZERO_WINDOW_PROBE */
    guint32   this_frame;           /* The frame# is stored in ta_send_table but this is useful for debugging */
    guint32   rxmt_at_frame;        /* If this segment was lost; this segment, its final portion, or one of the segments
                                       of a lost LSO segment was retranmsitted at this frame number. If instead frames
                                       prior to this one were lost, this is the frame# of the last of those retransmissions. */
    guint32   orig_frame;           /* If this frame was delivered out-of-order, this is the frame following the
                                       gap within which this frame was actually sent. If this is a "Previous segment
                                       out-of-order" frame, this is the frame# of the last of those reordered frames. */
    nstime_t  frame_dt;             /* If this is a duplicated frame, the delta time between this frame and the original.
                                       If this is an out-of-order frame, the delta time between this frame and the frame
                                        following the gap into which this segment falls */
    gboolean  seg_falls_in_gap;     /* TRUE if the nextseq in this frame falls in the gap prior to a
                                       TCP_PREV_PACKET_<LOST or OUT_OF_ORDER> frame */
    guint32   gap_size;             /* If TCP_PREV_PACKET_<LOST|OUT_OF_ORDER|UNSEEN> flag, the number of bytes between the
                                       highest seq# sent in this flow and this frame's seq#. */
    guint32   new_data_sent_in_rec; /* If this flow is in recovery and this is new rather than rexmited data, the number
                                       of bytes sent (seglen) in this frame */
    guint32   lastwindow_from_rev;  /* Last (scaled if known) window size received from the rev flow */
} ta_send_t;

/* Info about retransmitted segments  
   The rxmtinfo_table consists of these "rxmtinfo" structs and indexed by frame number. */
typedef struct tcp_rxmtinfo_t {
    guint32   flags;               /* Flags such as TCP_FAST_RETRANSMISSION */
    guint32   orig_frame;          /* Frame number of the originally transmitted segment or the prev_seg_lost
                                      Frame number that follows the gap within which the original frame was transmitted. */
    nstime_t  orig_frame_dt;       /* Delta time between this retransmission and original */
    guint32   unacked_of_orig;     /* The number of outstanding bytes when the original frame of the *first* retransmission */
                                   /* in the recovery event was transmitted. */
    gboolean  is_first_rxmt;       /* The first retransmission of a TCP recovery event. Prevents STDEV from being 
                                      recalculated on subsequent rexmits of a given event. */
    nstime_t  first_rxmt_ts;       /* If is_first_rxmt, the timestamp of that frame (for calc of ta_recv->time_in_rec_dt) */
    guint32   rec_target;          /* Seq# that must be ACKed before *this* flow can exit TCP Recovery */
    guint32   frame_rec_entered;   /* Frame number that this flow entered recovery */
    guint32   remaining;           /* Number of bytes remaining before the target is reached */

    gboolean  new_data_appended;   /* TRUE if new data was appended to this retransmission */
    gboolean  ack_lost;            /* TRUE if the ACK of the original segment appears to have been lost and resulted
                                      in this RTO */
    gboolean    re_retransmission; /* TRUE if this is a retransmission of an earlier retransmission */
} tcp_rxmtinfo_t;

/* The first_rxmtl list ("first_rxmtl") consists of these first_rxmt_t structs. */
typedef struct first_rxmt_t {
    struct first_rxmt_t *next;
    guint32 unacked_of_orig;       /* Bytes that were in_flight when the original segment was sent */
} first_rxmt_t;

/* One instance of this structure is created for each PDU that spans multiple TCP segments.
   The tcp_multisegment_pdus list is made up of these ("msp") structs and indexed by *sequence* number.
*/
struct tcp_multisegment_pdu {
    guint32  seq;
    guint32  nxtpdu;
    guint32  first_frame;
    guint32  last_frame;
    nstime_t last_frame_time;
    guint32  flags;
#define MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT 0x00000001
};

/*
 ****************************** RECEIVER-related structs used in PERSISTENT per-packet lists ****************************** 
 
 The 'ta_recv_table' consists of these ("ta_recv") structs indexed by frame number.
*/
typedef struct ta_recv_t {
    guint32        flags;               /* Receiver-related TCP analysis flags such as TCP_ACK_OF_UNSEEN_PACKET,
                                           TCP_ZERO_WINDOW, and TCP_PARTNER_CAN_EXIT_RECOVERY */
    guint8         triggered_by;        /* If this frame has one or more SACK blocks, this triggered it to be sent */
    guint32        frame_acked;         /* Frame containing the ACKed seq# */
    nstime_t       delta_ts;            /* Delta time between the ACK and frame containing the ACKed seq# */
    nstime_t       ooo_ack_dt;          /* Delta time between this TCP_ACK_ONLY_OUT_OF_ORDER frame and the 
                                           'ooo_belongs_after' frame */
    guint16        dupack_num;          /* dup-ack counter */
    guint32        dup_of_ack_in_frame; /* duplicate of the ack in frame# */
    guint32        ooo_belongs_after;   /* If TCP_ACK_ONLY_OUT_OF_ORDER, the frame# after which this frame belongs */
    guint32        frame_rec_entered;   /* Frame number at which *our partner* entered recovery */
    nstime_t       time_in_rec_dt;      /* If TCP_PARTNER_CAN_EXIT_RECOVERY, time that our partner spent in recovery */
    guint32        unacked_in_rev;      /* The number of unACKed bytes in the rev flow (=0 if error in preceding packet) */
} ta_recv_t;

/*
 Info in (sackb_t) sackb structs is copied to (saved_sackb_t) ssackb structs which comprise the
 tcpd->saved_sackb_l->arr list: the list of active SACK blocks when this frame was received. Note, active
 (unACKed) SACK blocks that were previously received aren't included in subsequent frames unless they have changed.
*/
typedef struct saved_sackb_t {
    int            offset;              /* Offset of sle */
    guint32        seq;                 /* The left and right edges of the of this SACK block. */
    guint32        nextseq;
    guint8        *p_sackb_bytes;       /* Pointer to the location where the 8 tvb bytes (sle and sre) were saved. */
    gboolean       dsack_blk;
    gboolean       sack_of_unseen;
    gboolean       invalid;             /* TRUE if a SACK block is more than one max window size less than the ACK or more
                                           than one max window size greater than the highest nextseq seen in the rev flow. */
} saved_sackb_t;

/* (saved_sackb_l_t) saved_sackb_l->arr is comprised of (saved_sackb_t) ssackb structs that were active (unACKed) when a
  frame containing SACK options was dissected. After the first pass this list is displayed in the "Options" subtree tree.
*/
typedef struct saved_sackb_l_t {
    guint16        num_active_blks;     /* The number of active (unACKed) SACK blocks in arr[] */
    saved_sackb_t *arr;                 /* List of (saved_sackb_t) SACK blocks that were active (unACKed) when this frame
                                           was processed */
    guint32        rev_nextseq;         /* The highest seq# transmitted in the rev flow when this SACK info was processed */
    gboolean       invalid_blks;        /* TRUE if a SACK block is more than one max window size less than the ACK or more
                                           than one max window size greater than the highest nextseq seen in the rev flow. */
    gboolean       rev_in_recovery;     /* TRUE: if the reverse flow is in recovery */
} saved_sackb_l_t;

/******************************* End of definitions used in PERSISTENT lists **********************************/

typedef struct _tcp_flow_t {
    
    /* Items in the following group are useful both during and after the first pass.
    */
    guint32          base_seq;              /* Lowest seq# seen in this flow or referenced in an ACK or DSACK block in the rev flow */
    guint32          base_seq_old;          /* If ports reused, and the packet is from the prior connection, base_seq is set to this. */
    guint32          firstxmitseq;          /* Lowest seq# sent and seen (not just referened) in this flow. */
    guint16          s_mss;                 /* SMSS: the largest segment size that the sender is allowed to transmit per RFC 5681
                                               Section 2. */
    guint32          max_seglen_rxmt;       /* Used to estimate MSS when tcpd->mss_opt_seen==FALSE: The max seglen of 
                                               retransmissions in this flow that are from 512 (or 500) to 8960 (or 8948) bytes */

    gint16           win_scale;             /* win_scale = -2 means that window scale factor (WSF) is UNKNNOWN in this flow which means it 
                                               it is UNSUPPORTED (win_scale = -1) in *both* flows per RFC 1323. */
    guint32          max_size_unacked;      /* The largest number of unACKed bytes seen by this flow.  
                                               If tcpd->wsf_announced==FALSE and the user has NOT manually set the WSF for this flow, this is
                                               also used to estimate the max window size in this flow. */
    guint32          max_size_window;       /* The maximum window size advertised in the this flow. 
                                               If the WSF is UNKNOWN in the REVERSE flow and the user has not manually set the WSF via 
                                               preference in the REVERSE flow, set the REVERSE flow's max_size_window to the the larger
                                               of tcpd->rev->max_size_window and this flow's max_size_unacked value. */

    guint32          max_size_acked;        /* Used for SNACK analysis */
    gint16           scps_capable;          /* flow advertised scps capabilities */

    emem_tree_t     *multisegment_pdus;     /* Tree indexed by *sequence* number that keeps track of all of the PDUs spanning
                                               multiple segments for this flow */
                                            /* The following five variables are used for the FCPA */
    struct
       first_rxmt_t *first_rxmtl;           /* The list of the num bytes that were in_flight when the original segment of the first
                                               retransmitted segment in each TCP recovery event was sent. */
    int              num_first_rxmts;       /* The number of entries in the first_rxmtl list */
    guint32          first_rxmt_avg;        /* Average of the first_rxmtl->unacked_of_orig values */
    double           first_rxmt_stdev;      /* The standard deviation based on the values in the first_rxmtl list */
    guint16          total_rexmits;         /* The total number of retransmissions in this flow. Used to calc retransmission ratio. 
                                               NOTE: There must be a counter for both the number of segments and retransmissions. 
                                               In addition, LSOs must be divided by MSS or the ratio will be inaccurate. */
    gboolean         fcpa_stats_calculated; /* Prevents the relcalculation of the FCPA stats if the capture is reloaded.


    /* The following items are used during the first pass when tcp_analyze_sequence_number() is called. They are NOT useful for
       populating the tree or for performimg analyses after the initial dissection because they contain values relative to the
       last frame in the conversation. However, some info indexed by frame number is stored in persistent lists such as ta_send,
       ta_recv, and saved_sackb_l.
    */
    gboolean         reused_port_conv;      /* Prevents seq# from previous conv to be displayed in RST packets when ports were
                                               reused. */
    guint32          seq;
    guint32          last_seq;              /* Last seq# seen in this flow: (for detecting duplicated frames) */
    guint32          nextseq;               /* Highest nextseq seen so far in this flow */
    guint32          seglen;                /* Length of this segment */
    guint32          last_seglen;

    ua_segment_t    *ua_segs_l;             /* Current List of unACKed (ua_seg) segments in this flow. */
    guint32          highest_ack;           /* The highest ACK number sent so far on *this* flow. In most implementations when an 
                                               ACK is received that is lower than the highest ACK seen on that flow, the packet is
                                               discarded; therefore, Wireshark should disregard those ACKs as well. */
    guint32          prior_highest_ack;     /* The highest ACK seen on *this* flow prior to the ACK in this frame */
    gboolean         valid_unacked;         /* If the previous seg is unseen/lost/ooo, disable BIF and unACKed until the next ACK */
    nstime_t         lastacktime;           /* Timestamp of the last *valid* ACK received on this flow. */
    guint16          dupacknum;             /* The number of dup-acks sent on this flow */
    guint16          dupacks_in_rec;        /* The number of dup-acks received during this recovery event */
    guint32          lastnondupack_frame;   /* Frame number of last non-dupack sent on this flow*/
    gboolean         partial_ack;           /* For detection of retransmissions triggered by NewReno */

    guint32          frame_rec_entered;     /* Frame number when this flow entered recovery. */
    guint32          rec_target;            /* The highest nextseq sent by this flow when the first retransmission of a recovery event 
                                               is sent. This sequence number must be ACKed before this flow can exit TCP Recovery.
                                               If not in recovery, it equals zero. When the 3rd dup-ack is received it is presumed that
                                               this flow has entered recovery and rec_target is set to the highest nextseq sent in this
                                               flow. If a segment is retransmitted, rec_target is set to the highest nextseq at that
                                               point in time. When the rec_target is ACKed, it is set to zero to indicate that this flow
                                               is no longer in recovery. */
    ua_rxmts_in_rec_t
                    *ua_rxmts_in_rec_l;     /* Current list of unACKed rexmits sent in this flow while in TCP recovery */
    guint32          ua_rxmt_bytes_in_rec;  /* The number of unACKed bytes in rexmits within a recovery event. This is used for calc of
                                                BIF if SACK is supported in this connection. */
    guint32          all_rxmt_bytes_in_rec; /* The sum of ALL retransmitted bytes including unwarrented rexmits within a particular
                                               recovery event including those that have been ACKed or SACKed. This is used for the calc
                                               of BIF when SACK is not supported in this connection. */
    guint16          tot_rxmts_this_event;  /* The total number of rexmits in this TCP recovery event */
    guint32          nextseq_upon_exit;     /* The seq number of the first data segment following exit from recovery (tcpd->rev->nextseq).
                                               If new data was transmitted (by tyhe flow in recovery) during a recovery event, unacked 
                                               data will remain. The next recovery event will not be included in the congestion point
                                               calculations until and unless that data has been acknowledged. This policy is based on 
                                               the fact that if unacked bytes remain from that last event, the number of outstanding
                                               bytes of the original packet that was later retrnamsitted is fairly meaningless and can
                                               skew the results of fixed congestion point analysis (FCPA). */
    gboolean         unwarranted_rxmt;      /* TRUE if this retransmitted segment has already been ACKed  */

    prev_seg_unseen_t
                    *prev_seg_miss_l;       /* Current list of unACKed "previous segment lost" frames and info */
    prev_seg_unseen_t
                    *last_ack_only_ooo;     /* If an ACK-only is ooo and a gap remains between the ACK and the nextseq of the frame
                                               it belongs after, store the pointer to the ACK-only frame's psu. If segments arrive
                                               fall within that gap, ooo_belongs_after in the ACK-only frame's ta_recv struct will
                                               be updated. */

    sackb_t         *sackb_l;               /* Current list of active (unACKed) (sackb) SACK blocks in this flow. */
    guint16          num_ssackb;            /* Current number of SACK blocks saved in sackl */
    guint32          totalsacked;           /* Current sum of the bytes in sackb_l, the active SACK block list, that have been SACKed */
    guint32          sackl_rev_nextseq;     /* nextseq in the rev flow when sackb_l was last processed (for rev flow's bytes_in_flight) */
    guint32          snd_fack;              /* Forward-most seq# plus one that *this* flow has SACKed */
    gboolean         dsack;                 /* This flag is used to prevent "Gratuitous ACK" labels on DSACK packets */

    guint32          lastwindow;            /* The last window size advertized in this flow (tcp.window_size_value) */
    guint16          last_tcpflags;         /* The last TCP flags seen in this flow */
    guint32          lastsegmentflags;      /* This is an OR of the ta_send, ta_recv, and rxmtinfo flags in the last packet */

    gboolean         ip_id_valid;           /* Valid as long as ip_id is within 5000 of ip_id_highest */
    guint16          ip_id_prev;            /* The previous frame's IP ID in this flow (for duplicate frame detection) */
    guint16          ip_id_highest;         /* Highest IP ID value seen in this flow */

    guint32          prev_frame;            /* The frame number of the previous frame *in this flow* (for duplicate frame detection) */

    guint32          process_uid;           /* UID of local process currently discovered via IPFIX */
    guint32          process_pid;           /* PID of local process currently discovered via IPFIX */
    gchar           *username;              /* Username of the local process */
    gchar           *command;               /* Local process name + path + args */
    guint32          flags;                 /* At present the only flag stored here is TCP_FLOW_REASSEMBLE_UNTIL_FIN. If a PDU might
                                               be fully reassembled with the data in a FIN packet, the dissector sets this flag. 
                                               WARNING: This feature has not been fully implemented in this version so it is 
                                               hard-coded to 0x0001 for now. */

#define TCP_FLOW_REASSEMBLE_UNTIL_FIN  0x0001
} tcp_flow_t;

/*
  tcpd is a tcp_analysis struct. There is one tcpd per *conversation*. tcpd->fwd/rev (flow1/flow2) contain info for each direction of 
  traffic in a given conversation.
 */
struct tcp_analysis {
    /* These two structs are managed based on comparing the source and destination addresses and, if they're equal, comparing
       the source and destination ports.

       If the source is greater than the destination, then stuff
       sent from src is in ual1.
 
       If the source is less than the destination, then stuff
       sent from src is in ual2.

       XXX - if the addresses and ports are equal, we don't guarantee
       the behavior.
    */
    tcp_flow_t   flow1;
    tcp_flow_t   flow2;

    /* These pointers are set by get_tcp_conversation_data(). "fwd" points in
       the same direction as the current packet and "rev" in the reverse direction.
    */
    tcp_flow_t  *fwd;
    tcp_flow_t  *rev;

    /* These pointers are NULL or point to the struct for this packet if it has "interesting" properties.
       tcp_analyze_get_<name>_struct() is called to retrieve the struct by frame number from the
       appropriate table and sets the associated pointer to that struct.
    */
    ta_send_t   *ta_send;         /* Sender oriented info unrelated to retransmissions */
    ta_recv_t   *ta_recv;         /* Receiver-oriented info */
    saved_sackb_l_t 
                *saved_sackb_l;   /* Array of active (unACKed) SACK blocks */
    tcp_rxmtinfo_t
                *rxmtinfo;        /* Retransmission-related info */

    /* These point to lists consisting of the above structs keyed by frame number.
    */
    emem_tree_t *ta_send_table;
    emem_tree_t *ta_recv_table;
    emem_tree_t *saved_sackl_table;
    emem_tree_t *rxmtinfo_table;

    /* Remember the timestamp of the first frame seen in this tcp conversation for the calculation of
       the time relative to the start of this conversation. */
    nstime_t     ts_first;
    /* Remember the timestamp of the frame that was last seen in this tcp conversation for the calculation
       of delta time from the previous frame in this conversation. */
    nstime_t     ts_prev;

    gboolean     syn_ack_sent;
    gboolean     fin_sent;
    gboolean     mss_opt_seen;      /* TRUE if the MSS option was seen in a SYN packet in either flow */
    guint8       ts_optlen;         /* The length of the timestamp option (0 or 12) */
    gboolean     sack_supported;    /* TRUE if SACK was negotiated or SACK blocks have been seen in this
                                       connection */
    gboolean     syn_seen;          /* Used to determine if window scaling has been fully declared in the SYN and SYN-ACK.*/
    gboolean     syn_ack_seen;      /* Used to determine if window scaling has been fully declared in the SYN and SYN-ACK.*/
    gboolean     wsf_announced;     /* TRUE if (a.) the SYN and SYN-ACK are included in this connection, (b.) neither
                                       WSF has been truncated, and (3.) both flows have supplied a WSF
                                       (even a WSF of 0) or either has omitted a WSF signaling that scaling
                                       is UNSUPPORTED on this *connection*.  */ 
                                    //////* If TRUE and the user manually sets the WSF for either flow, it is ignored.
    gboolean     nplists_released;  /* TRUE if all nonpersistent lists have already been released in both flows */
} tcp_analysis;


/* The following should be added to the Wireshark manual:

   ======================================
   Fixed Congestion Point Analysis (FCPA)
   ======================================
   The number of bytes that were in flight when the original segment of the first retransmitted segment of a
   given TCP recovery event was transmitted: This is used for fixed congestion point analysis. 

   Fixed Congestion Point Analysis: The average number of unACKed (outstanding) bytes when the original frame of
   first retransmission of a recovery event (tcp.analysis.orig_unacked) along with the STDEV of those values can
   be used to determine the likelihood that fixed congestion point existed in the network path during the capture
   period. If the STDEV is low enough to suggest that a fixed congestion point existed and there are a sufficient
   number of samples, the user might consider setting the receiving host's max TCP window size to the average
   unACKed bytes minus the STDEV in order to reduce or eliminate packet loss. The selected max window size along
   with average RTT can be used to calculate the maximum throughput allowed by these values:

       (Max throughput (B/s) := Max TCP window size / RTT)

   The avg unACKed bytes and the STDEV are recalculated for the first retransmission in a recovery event. In 
   Wireshark these values are displayed in any retransmission header of a given flow. These values are calulated 
   in the same manner in tshark. The "running" values are not displayed in the tree; however, the user can 
   tcp.analysis.orig_unacked can be plotted in IO Graphs. The final plotted values are equivalent to the 
   corresponding values in Wireshark. Until a separate Wireshark window and tshark output table is developed
   to display the values for each connection and the final roll-up they are displayed in the 'Sequence number'
   subtree of every retransmission of a given flow including those not used in the calculations (i.e. retransmissions
   2 thru n of a TCP Recovery event.
 
   The congestion point in the network for any particular instance of congestion is the amount of data that has been
   sent on a TCP connection beyond the current acknowledgment before any traffic would be discarded in the network.
   Thus, the congestion point is approximately the amount of traffic outstanding in the network when the first frame
   of a flight of transmitted frames is retransmitted. (This is an approximate amount, because some traffic could
   have been delivered through the network while the acknowledgment of the data had not been received yet by the data
   sender.)  
   
   Provided that the Standard Deviation (STDEV) is sufficiently small, an FCPA can be useful in mitigating packet
   loss by implicitly suggesting a receiver window size that is most likely to reduce or eliminate the number of
   retransmissions by setting the average unACKed bytes of origiinal frame minus the STDEV. The resulting value 
   should be configured if the throughput allowed by window size / rtt allows for an acceptable level of throughput.  
   
   The maximum possible throughput is the smaller of (1) the bandwidth of the slowest link divided by the average
   RTT and (2) the receiver's maximum TCP window size divided by the average RTT. If (2) is greater than the bandwidth
   of the slowest link, calculate the Bandwidth Delay Product (BDP): the product of the average RTT and the average
   available bandwidth of the slowest link between the connection partners. In such cases reducing the receiver's
   window size to the BDP, may significantly reduce packet loss or possibly eliminate it.   

   NOTE: An FCPA will only be conducted for the flow that was captured on or near the data sender. If packet loss
         occurred in both directions and an FCPA is desired for the opposite flow, a capture must also be taken on
         or ner the the connection partner during a period when a typical volume of data is transmitted in both
         directions. That is why concurrent captures should be obtained during a representative (usual) period when
         I/O is taking place in both directions. 

   Required Criteria for Calculating the Fixed Congestion Point Analysis (FCPA) Statisics in the First Pass
   ========================================================================================================
   The following criteria must be met for a retransmission to be included in the 'first_rxmtl' list which in turn
   is used to conduct an FCPA. 

     1. It is the first retransmission of a Recovery event 
     2. If new data was transmitted during the previous event and the 'nextseq_upon_exit' of that event has
        been ACKed. This makes the FCPA more accurate.  
     3. Preference 'sender_side_cap' has either been set to CAP_TAKEN_ON_THE_SENDER or the the default value
        of AUTO_DETECT_SIDE_CAP_TAKEN 
     4. The 'tcp_track_unacked_and_bif' preference is set
     5. There were unACKed bytes when the original frame was transmitted (sanity check)

   Criteria used for Auto-detection in the Second Pass        
   ===================================================
     1. If a segment is present in the capture and later retransmitted, the original segment is labeled TCP_PACKET_LOST 
        "[TCP Packet lost]”) and indicates that the capture *must* have been taken on or near the data sender, even if
        only one packet is so labelled. Whenever this flag is set, the 'num_packet_lost' is incremented. 

        If the original segment was actually sent but for some reason was not stored in the capture file, the following
        packet in that flow is labelled TCP_PREV_PACKET_UNSEEN and subsequent packets are labelled
        TCP_ACK_OF_UNSEEN_SEGMENT or TCP_SACK_OF_UNSEEN_SEGMENT unless of course they are also missing from the
        capture. Since these labels can result fron missing frames, they provide little help in detecting on which side
        the capture was taken.

        Variables: num_packet_lost, num_ooo_segs, and num_ack_only_ooo [XXX: If needed, variables num_lso_pdus and 
                   num_lro_pdus will be utilized as well. 

     2. If packets are received out-of-order, they are flagged as "TCP_OUT_OF_ORDER", "TCP_PREV_PACKET_OUT_OF_ORDER",
        or TCP_ACK_ONLY_OUT_OF_ORDER. These flags indicate that capture was very likely to have been taken on the
        *RECEIVER* because in the vast majority of cases, packets are reordered by the network rather than the data 
        transmitter.  

        Variables: int num_ooo_segs, num_prev_packet_ooo, num_ack_only_ooo;

     3. If the 3-way TCP connection establishment sequence is present in the capture and a segment exceeds the
        negotiated MSS or if not present exceeds the estimated MSS, it is either an LSO or LRO PDU. LSOs are only
        present in sender-side captures and LROs only in receiver-side captures. If the entire large segment is
        ACKed all at once, it is an LRO; otherwise it is an LSO.  

        Variables: int num_lso_pdus, num_lro_pdus  

     4. [XXX: Not yet implemented] If the capture has a sufficient number of samples ("degrees of freedom") to
        reliably calculate the average time to ACK a segment, the larger of those values will likely belong to the
        data receiver. This method is effective even if the time granularity of the host/server on which the capture
        was taken exceeds the average ack_rtt. Note: This method requires that packets with ack_rtt of zero be
        included in the calculation. 

     5. [XXX: Not yet implemented] If the source *MAC* address does not have the OUI of a router manufacturer such
        as Cisco or Cisco's HSRP protocol (RFC 2281) but the destination MAC address does, the capture was very
        likely to have been taken on the sender. See the 'manuf' file for the list of known OUIs. 

   If the above indices contradict one another or there is insufficient evidence (degrees of freedom) to produce
   a reliable result, 'sender_side_cap' is set to 0 (unknown), an FCPA is not performed, and the user is informed
   that   the option manually set this preference if they have this information. 
*/

extern void
tcp_dissect_pdus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
         gboolean proto_desegment, guint fixed_len,
         guint (*get_pdu_len)(packet_info *, tvbuff_t *, int),
         dissector_t dissect_pdu);

extern struct tcp_multisegment_pdu *
pdu_store_sequencenumber_of_next_pdu(packet_info *pinfo, guint32 seq, guint32 nxtpdu, emem_tree_t *multisegment_pdus);

extern void dissect_tcp_payload(tvbuff_t *tvb, packet_info *pinfo, int offset,
                                guint32 seq, guint32 nxtseq, guint32 ack, guint32 win, 
                                guint32 sport, guint32 dport, 
                                proto_tree *tree, proto_tree *tcp_tree,
                                struct tcp_analysis *tcpd);

extern struct tcp_analysis *get_tcp_conversation_data(conversation_t *conv,
                                packet_info *pinfo);

extern gboolean decode_tcp_ports(tvbuff_t *, int, packet_info *, proto_tree *, int, int, struct tcp_analysis *);

/* Associate process information with a given flow

   @param frame_num The frame number
   @param local_addr The local IPv4 or IPv6 address of the process
   @param remote_addr The remote IPv4 or IPv6 address of the process
   @param local_port The local TCP port of the process
   @param remote_port The remote TCP port of the process
   @param uid The numeric user ID of the process
   @param pid The numeric PID of the process
   @param username Ephemeral string containing the full or partial process name
   @param command Ephemeral string containing the full or partial process name
 */
extern void add_tcp_process_info(guint32 frame_num, address *local_addr, address *remote_addr, guint16 local_port,
                                 guint16 remote_port, guint32 uid, guint32 pid, gchar *username, gchar *command);

#endif