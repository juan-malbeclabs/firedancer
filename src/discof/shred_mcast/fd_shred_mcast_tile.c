#define _GNU_SOURCE
#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_disco.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../ballet/shred/fd_shred.h"

#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "generated/fd_shred_mcast_tile_seccomp.h"

/* Number of recent slots to track for deduplication */
#define FD_SHRED_MCAST_DEDUP_SLOT_CNT (8UL)

/* Max shred index per slot per type (data or code).  Shred indices are
   bounded to FD_SHRED_BLK_MAX (32767).  We track one bit per index. */
#define FD_SHRED_MCAST_MAX_SHREDS_PER_HALF (32768UL)
#define FD_SHRED_MCAST_SEEN_BYTES          (FD_SHRED_MCAST_MAX_SHREDS_PER_HALF / 8UL) /* 4096 */

/* Number of datagrams to receive in a single recvmmsg call */
#define FD_SHRED_MCAST_RX_BURST (64UL)

typedef struct {
  /* Per-slot deduplication bitsets.  Indexed by slot % DEDUP_SLOT_CNT.
     data_seen[i] tracks which data shreds have been forwarded for
     slot dedup[i].slot, and code_seen[i] does the same for coding
     shreds.  A slot value of ULONG_MAX means the entry is unused. */
  struct {
    ulong slot;
    uchar data_seen[ FD_SHRED_MCAST_SEEN_BYTES ];
    uchar code_seen[ FD_SHRED_MCAST_SEEN_BYTES ];
  } dedup[ FD_SHRED_MCAST_DEDUP_SLOT_CNT ];

  /* Input link workspaces — one entry per upstream shred_mcast link */
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
  } in[ FD_TOPO_MAX_TILE_IN_LINKS ];

  /* Multicast RX socket (joined to the source multicast group) */
  int mcast_rx_sock;

  /* Multicast TX socket (for forwarding to the destination group) */
  int mcast_tx_sock;

  /* Destination address for TX sendto() */
  struct sockaddr_in mcast_dst_addr;

  /* Work buffer for a fragment received from the shred tile link */
  uchar pkt_buf[ FD_SHRED_MAX_SZ ];
  ulong pkt_sz;
  int   skip_frag;

  /* Counters */
  struct {
    ulong rx_turbine;
    ulong rx_mcast;
    ulong tx_mcast;
    ulong dedup_skipped;
    ulong parse_failed;
  } metrics;
} fd_shred_mcast_ctx_t;

/* Returns 1 if this (slot, is_code, global_idx) has already been seen
   and forwarded.  Returns 0 and marks it as seen if it is new.
   global_idx = fec_set_idx + shred_idx_within_fec_set. */
static inline int
dedup_check_and_set( fd_shred_mcast_ctx_t * ctx,
                     ulong                  slot,
                     int                    is_code,
                     ulong                  global_idx ) {
  ulong ring_idx = slot % FD_SHRED_MCAST_DEDUP_SLOT_CNT;

  if( FD_UNLIKELY( ctx->dedup[ ring_idx ].slot != slot ) ) {
    /* This ring slot belongs to a different (older) slot — evict it. */
    ctx->dedup[ ring_idx ].slot = slot;
    fd_memset( ctx->dedup[ ring_idx ].data_seen, 0, FD_SHRED_MCAST_SEEN_BYTES );
    fd_memset( ctx->dedup[ ring_idx ].code_seen, 0, FD_SHRED_MCAST_SEEN_BYTES );
  }

  if( FD_UNLIKELY( global_idx >= FD_SHRED_MCAST_MAX_SHREDS_PER_HALF ) ) {
    /* Index out of bitset range — let it pass through (conservative). */
    return 0;
  }

  uchar * seen = is_code ? ctx->dedup[ ring_idx ].code_seen
                         : ctx->dedup[ ring_idx ].data_seen;
  ulong word = global_idx >> 3;
  uchar bit  = (uchar)(1U << (global_idx & 7U));

  if( FD_UNLIKELY( seen[ word ] & bit ) ) return 1; /* already seen */
  seen[ word ] |= bit;
  return 0;
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_shred_mcast_ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_shred_mcast_ctx_t ), sizeof( fd_shred_mcast_ctx_t ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo  FD_PARAM_UNUSED,
                           fd_topo_tile_t const * tile,
                           ulong                  out_cnt,
                           struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_shred_mcast_tile(
      out_cnt, out,
      (uint)fd_log_private_logfile_fd(),
      (uint)tile->shred_mcast.mcast_rx_sock,
      (uint)tile->shred_mcast.mcast_tx_sock );
  return sock_filter_policy_fd_shred_mcast_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo       FD_PARAM_UNUSED,
                       fd_topo_tile_t const * tile,
                       ulong                  out_fds_cnt FD_PARAM_UNUSED,
                       int *                  out_fds ) {
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1 != fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  out_fds[ out_cnt++ ] = tile->shred_mcast.mcast_rx_sock;
  out_fds[ out_cnt++ ] = tile->shred_mcast.mcast_tx_sock;
  return out_cnt;
}

static void
privileged_init( fd_topo_t *      topo  FD_PARAM_UNUSED,
                  fd_topo_tile_t * tile ) {

  /* --- RX socket: join source multicast group --- */
  int rx_sock = socket( AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP );
  if( FD_UNLIKELY( rx_sock < 0 ) )
    FD_LOG_ERR(( "shred_mcast: socket(RX) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  int reuse = 1;
  if( FD_UNLIKELY( setsockopt( rx_sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse) ) ) )
    FD_LOG_ERR(( "shred_mcast: setsockopt(SO_REUSEPORT) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  int rcvbuf = 1<<20; /* 1 MiB */
  (void)setsockopt( rx_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf) );

  struct sockaddr_in bind_addr = {
    .sin_family      = AF_INET,
    .sin_addr.s_addr = INADDR_ANY,
    .sin_port        = fd_ushort_bswap( tile->shred_mcast.mcast_src_port ),
  };
  if( FD_UNLIKELY( bind( rx_sock, fd_type_pun_const( &bind_addr ), sizeof(bind_addr) ) ) )
    FD_LOG_ERR(( "shred_mcast: bind(RX) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  struct ip_mreq mreq = {
    .imr_multiaddr.s_addr = tile->shred_mcast.mcast_src_ip,
    .imr_interface.s_addr = INADDR_ANY,
  };
  if( FD_UNLIKELY( setsockopt( rx_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq) ) ) )
    FD_LOG_ERR(( "shred_mcast: IP_ADD_MEMBERSHIP failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  FD_LOG_NOTICE(( "shred_mcast: joined multicast group %u.%u.%u.%u:%u (rx_sock=%d)",
                  (tile->shred_mcast.mcast_src_ip      ) & 0xFF,
                  (tile->shred_mcast.mcast_src_ip >>  8) & 0xFF,
                  (tile->shred_mcast.mcast_src_ip >> 16) & 0xFF,
                  (tile->shred_mcast.mcast_src_ip >> 24) & 0xFF,
                  tile->shred_mcast.mcast_src_port, rx_sock ));

  /* --- TX socket: for sending to destination multicast group --- */
  int tx_sock = socket( AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP );
  if( FD_UNLIKELY( tx_sock < 0 ) )
    FD_LOG_ERR(( "shred_mcast: socket(TX) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  uchar ttl = tile->shred_mcast.mcast_ttl ? tile->shred_mcast.mcast_ttl : 1;
  if( FD_UNLIKELY( setsockopt( tx_sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl) ) ) )
    FD_LOG_ERR(( "shred_mcast: setsockopt(IP_MULTICAST_TTL) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  FD_LOG_NOTICE(( "shred_mcast: TX socket ready, dst %u.%u.%u.%u:%u (tx_sock=%d, ttl=%u)",
                  (tile->shred_mcast.mcast_dst_ip      ) & 0xFF,
                  (tile->shred_mcast.mcast_dst_ip >>  8) & 0xFF,
                  (tile->shred_mcast.mcast_dst_ip >> 16) & 0xFF,
                  (tile->shred_mcast.mcast_dst_ip >> 24) & 0xFF,
                  tile->shred_mcast.mcast_dst_port, tx_sock, ttl ));

  tile->shred_mcast.mcast_rx_sock = rx_sock;
  tile->shred_mcast.mcast_tx_sock = tx_sock;
}

static void
unprivileged_init( fd_topo_t *      topo,
                    fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_shred_mcast_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_shred_mcast_ctx_t), sizeof(fd_shred_mcast_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  fd_memset( ctx, 0, sizeof(*ctx) );

  /* Mark all dedup slots as unused */
  for( ulong i=0UL; i<FD_SHRED_MCAST_DEDUP_SLOT_CNT; i++ )
    ctx->dedup[ i ].slot = ULONG_MAX;

  /* Set up input link workspaces */
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];
    ctx->in[ i ].mem    = wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  /* Copy socket FDs and destination address from tile config */
  ctx->mcast_rx_sock = tile->shred_mcast.mcast_rx_sock;
  ctx->mcast_tx_sock = tile->shred_mcast.mcast_tx_sock;

  ctx->mcast_dst_addr.sin_family      = AF_INET;
  ctx->mcast_dst_addr.sin_addr.s_addr = tile->shred_mcast.mcast_dst_ip;
  ctx->mcast_dst_addr.sin_port        = fd_ushort_bswap( tile->shred_mcast.mcast_dst_port );

  FD_LOG_NOTICE(( "shred_mcast: tile initialized, in_cnt=%lu rx_sock=%d tx_sock=%d",
                  tile->in_cnt, ctx->mcast_rx_sock, ctx->mcast_tx_sock ));
}

/* before_credit: poll the multicast RX socket for incoming shreds from
   the external multicast feed.  Uses MSG_DONTWAIT to avoid blocking.
   For each new shred, deduplicates and forwards to the TX socket. */
static void
before_credit( fd_shred_mcast_ctx_t * ctx,
               fd_stem_context_t *    stem FD_PARAM_UNUSED,
               int *                  charge_busy ) {
  /* Declare static arrays to avoid large stack frames */
  static struct mmsghdr msgs[ FD_SHRED_MCAST_RX_BURST ];
  static struct iovec   iovs[ FD_SHRED_MCAST_RX_BURST ];
  static uchar          bufs[ FD_SHRED_MCAST_RX_BURST ][ FD_SHRED_MAX_SZ ];

  for( ulong i=0UL; i<FD_SHRED_MCAST_RX_BURST; i++ ) {
    iovs[ i ].iov_base              = bufs[ i ];
    iovs[ i ].iov_len               = FD_SHRED_MAX_SZ;
    msgs[ i ].msg_hdr.msg_iov       = &iovs[ i ];
    msgs[ i ].msg_hdr.msg_iovlen    = 1;
    msgs[ i ].msg_hdr.msg_name      = NULL;
    msgs[ i ].msg_hdr.msg_namelen   = 0;
    msgs[ i ].msg_hdr.msg_control   = NULL;
    msgs[ i ].msg_hdr.msg_controllen= 0;
  }

  int cnt = recvmmsg( ctx->mcast_rx_sock, msgs, FD_SHRED_MCAST_RX_BURST, MSG_DONTWAIT, NULL );
  if( FD_LIKELY( cnt <= 0 ) ) return;

  *charge_busy = 1;

  for( int i=0; i<cnt; i++ ) {
    uchar const * raw    = bufs[ i ];
    ulong         raw_sz = msgs[ i ].msg_len;

    fd_shred_t const * shred = fd_shred_parse( raw, raw_sz );
    if( FD_UNLIKELY( !shred ) ) { ctx->metrics.parse_failed++; continue; }

    int   is_code  = fd_shred_is_code( fd_shred_type( shred->variant ) );
    ulong global_i = (ulong)shred->fec_set_idx + (ulong)shred->idx;

    if( dedup_check_and_set( ctx, shred->slot, is_code, global_i ) ) {
      ctx->metrics.dedup_skipped++;
      continue;
    }

    if( FD_UNLIKELY( sendto( ctx->mcast_tx_sock, raw, raw_sz, 0,
                              fd_type_pun_const( &ctx->mcast_dst_addr ),
                              sizeof(ctx->mcast_dst_addr) ) < 0 ) ) continue;

    ctx->metrics.rx_mcast++;
    ctx->metrics.tx_mcast++;
  }
}

/* during_frag: copy raw shred bytes from the dcache into a local buffer.
   The sig carries slot/fec_set_idx/is_code/shred_idx encoded by the
   shred tile via fd_disco_shred_out_shred_sig(). */
static inline void
during_frag( fd_shred_mcast_ctx_t * ctx,
              ulong                  in_idx,
              ulong                  seq    FD_PARAM_UNUSED,
              ulong                  sig    FD_PARAM_UNUSED,
              ulong                  chunk,
              ulong                  sz,
              ulong                  ctl    FD_PARAM_UNUSED ) {
  ctx->skip_frag = 0;
  if( FD_UNLIKELY( sz > FD_SHRED_MAX_SZ ) ) { ctx->skip_frag = 1; return; }
  uchar const * src = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
  fd_memcpy( ctx->pkt_buf, src, sz );
  ctx->pkt_sz = sz;
}

/* after_frag: parse the shred, deduplicate, and forward to multicast TX. */
static inline void
after_frag( fd_shred_mcast_ctx_t * ctx,
             ulong                  in_idx  FD_PARAM_UNUSED,
             ulong                  seq     FD_PARAM_UNUSED,
             ulong                  sig     FD_PARAM_UNUSED,
             ulong                  sz      FD_PARAM_UNUSED,
             ulong                  tsorig  FD_PARAM_UNUSED,
             ulong                  tspub   FD_PARAM_UNUSED,
             fd_stem_context_t *    stem    FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( ctx->skip_frag ) ) return;

  fd_shred_t const * shred = fd_shred_parse( ctx->pkt_buf, ctx->pkt_sz );
  if( FD_UNLIKELY( !shred ) ) { ctx->metrics.parse_failed++; return; }

  int   is_code  = fd_shred_is_code( fd_shred_type( shred->variant ) );
  ulong global_i = (ulong)shred->fec_set_idx + (ulong)shred->idx;

  if( dedup_check_and_set( ctx, shred->slot, is_code, global_i ) ) {
    ctx->metrics.dedup_skipped++;
    return;
  }

  if( FD_UNLIKELY( sendto( ctx->mcast_tx_sock, ctx->pkt_buf, ctx->pkt_sz, 0,
                            fd_type_pun_const( &ctx->mcast_dst_addr ),
                            sizeof(ctx->mcast_dst_addr) ) < 0 ) ) return;

  ctx->metrics.rx_turbine++;
  ctx->metrics.tx_mcast++;
}

static void
metrics_write( fd_shred_mcast_ctx_t * ctx ) {
  FD_MCNT_SET( SHRED_MCAST, RX_TURBINE_SHREDS, ctx->metrics.rx_turbine  );
  FD_MCNT_SET( SHRED_MCAST, RX_MCAST_SHREDS,   ctx->metrics.rx_mcast    );
  FD_MCNT_SET( SHRED_MCAST, TX_MCAST_SHREDS,   ctx->metrics.tx_mcast    );
  FD_MCNT_SET( SHRED_MCAST, DEDUP_SKIPPED,      ctx->metrics.dedup_skipped );
  FD_MCNT_SET( SHRED_MCAST, PARSE_FAILED,       ctx->metrics.parse_failed  );
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE   fd_shred_mcast_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN  alignof(fd_shred_mcast_ctx_t)
#define STEM_CALLBACK_BEFORE_CREDIT  before_credit
#define STEM_CALLBACK_DURING_FRAG    during_frag
#define STEM_CALLBACK_AFTER_FRAG     after_frag
#define STEM_CALLBACK_METRICS_WRITE  metrics_write

/* Sink tile with no outputs — use a relaxed lazy timeout */
#define STEM_LAZY (128L*3000L)

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_shred_mcast = {
  .name                     = "shred_mcast",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
