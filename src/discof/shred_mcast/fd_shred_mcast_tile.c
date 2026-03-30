#define _GNU_SOURCE
#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_disco.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../util/hist/fd_histf.h"
#include "../../tango/tempo/fd_tempo.h"

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

/* Race tracking: which source delivered each shred first?
   Sources: 0..FD_SHRED_MCAST_SRC_MAX-1 = mcast sockets; FD_SHRED_MCAST_SRC_MAX = turbine. */
#define FD_SHRED_RACE_SRC_CNT     (FD_SHRED_MCAST_SRC_MAX + 1UL)
#define FD_SHRED_RACE_SRC_TURBINE (FD_SHRED_MCAST_SRC_MAX)

/* Per-slot hash table of race entries.  4096 buckets covers a typical
   slot (~1000–5000 shreds) with very low collision probability. */
#define FD_SHRED_RACE_TBL_SZ   (4096UL)
#define FD_SHRED_RACE_TBL_MASK (FD_SHRED_RACE_TBL_SZ - 1UL)
#define FD_SHRED_RACE_KEY_EMPTY (0xFFFFFFFFU)  /* sentinel for unused entry */

typedef struct {
  uint   full_key;     /* (is_code<<16)|global_idx; FD_SHRED_RACE_KEY_EMPTY = unused */
  uchar  src_first;    /* source index of first arrival */
  uchar  _pad;
  ushort sources_seen; /* bitmask: bit s set iff source s has delivered this shred */
  ulong  ts_first;     /* fd_tickcount() of first arrival */
} fd_shred_race_entry_t;  /* 16 bytes */

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

  /* Input link workspaces — one entry per upstream shred_mcast link (shred → shred_mcast) */
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
  } in[ FD_TOPO_MAX_TILE_IN_LINKS ];

  /* Output link workspaces — one entry per downstream mcast_shred link (shred_mcast → shred) */
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
    ulong       out_idx; /* index in tile->out_link_id[] for fd_stem_publish */
  } out[ FD_TOPO_MAX_TILE_IN_LINKS ];
  ulong shred_tile_cnt;

  /* Multicast RX sockets — one per source group (may have different ports) */
  int                mcast_rx_socks[ FD_SHRED_MCAST_SRC_MAX ];
  ulong              mcast_rx_cnt;

  /* Multicast TX socket — single socket, sendto() repeated per destination */
  int                mcast_tx_sock;
  struct sockaddr_in mcast_dst_addrs[ FD_SHRED_MCAST_DST_MAX ];
  ulong              mcast_dst_cnt;

  /* Work buffer for a fragment received from the shred tile link */
  uchar pkt_buf[ FD_SHRED_MAX_SZ ];
  ulong pkt_sz;
  int   skip_frag;

  /* Counters */
  struct {
    ulong rx_turbine;
    ulong rx_mcast;
    ulong tx_mcast;
    ulong tx_mcast_bytes;
    ulong tx_relay_bytes;
    ulong dedup_skipped;
    ulong parse_failed;
    ulong rx_src_shreds[ FD_SHRED_MCAST_SRC_MAX ];
    ulong rx_src_bytes [ FD_SHRED_MCAST_SRC_MAX ];
    ulong rx_src_dedup [ FD_SHRED_MCAST_SRC_MAX ];
  } metrics;

  /* tick → nanosecond conversion factor (populated in unprivileged_init) */
  double tick_per_ns;

  /* Race tracking: per-slot hash table (indexed by slot % DEDUP_SLOT_CNT).
     Tracks which source delivered each shred first, and the delay for
     subsequent sources.  Evicted when the ring slot is reused for a new slot. */
  struct {
    ulong                 slot;
    fd_shred_race_entry_t tbl[ FD_SHRED_RACE_TBL_SZ ];
  } race[ FD_SHRED_MCAST_DEDUP_SLOT_CNT ];

  /* Race placement counters and delay histograms.
     Source index: 0..FD_SHRED_MCAST_SRC_MAX-1 = mcast; FD_SHRED_MCAST_SRC_MAX = turbine. */
  struct {
    ulong      first [ FD_SHRED_RACE_SRC_CNT ];
    ulong      second[ FD_SHRED_RACE_SRC_CNT ];
    ulong      third [ FD_SHRED_RACE_SRC_CNT ];
    ulong      solo  [ FD_SHRED_RACE_SRC_CNT ];
    fd_histf_t delay [ FD_SHRED_RACE_SRC_CNT ];
  } race_metrics;
} fd_shred_mcast_ctx_t;

/* Finalize race stats for the given ring slot before eviction.
   Scans the table for entries seen by only one source and increments
   the "solo" counter for that source.  Must be called before the table
   is cleared for a new slot. */
static void
race_finalize_slot( fd_shred_mcast_ctx_t * ctx,
                    ulong                  ring_idx ) {
  if( FD_UNLIKELY( ctx->race[ ring_idx ].slot==ULONG_MAX ) ) return;
  fd_shred_race_entry_t const * tbl = ctx->race[ ring_idx ].tbl;
  for( ulong i=0UL; i<FD_SHRED_RACE_TBL_SZ; i++ ) {
    if( FD_LIKELY( tbl[i].full_key==FD_SHRED_RACE_KEY_EMPTY ) ) continue;
    /* popcount(sources_seen)==1 means only one source delivered this shred */
    if( FD_UNLIKELY( __builtin_popcount( (uint)tbl[i].sources_seen )==1 ) )
      ctx->race_metrics.solo[ tbl[i].src_first ]++;
  }
}

/* Record the arrival of a shred from the given source.  Updates race
   placement counters (first/second/third) and the delay histogram.
   Must be called BEFORE dedup_check_and_set so we observe every source. */
static inline void
race_track_shred( fd_shred_mcast_ctx_t * ctx,
                  ulong                  slot,
                  int                    is_code,
                  ulong                  global_idx,
                  ulong                  source,   /* 0..FD_SHRED_RACE_SRC_CNT-1 */
                  long                   ts ) {    /* fd_tickcount() at arrival */
  ulong ring_idx = slot % FD_SHRED_MCAST_DEDUP_SLOT_CNT;

  if( FD_UNLIKELY( ctx->race[ ring_idx ].slot!=slot ) ) {
    race_finalize_slot( ctx, ring_idx );
    ctx->race[ ring_idx ].slot = slot;
    /* FD_SHRED_RACE_KEY_EMPTY (0xFFFFFFFF) is the fill byte for the full_key
       field at offset 0 of each 16-byte entry, so a 0xFF memset works. */
    fd_memset( ctx->race[ ring_idx ].tbl, 0xFF,
               FD_SHRED_RACE_TBL_SZ * sizeof(fd_shred_race_entry_t) );
  }

  if( FD_UNLIKELY( global_idx>=FD_SHRED_MCAST_MAX_SHREDS_PER_HALF ) ) return;

  uint  full_key = (uint)global_idx | ((uint)is_code << 16);
  ulong tbl_idx  = global_idx & FD_SHRED_RACE_TBL_MASK;
  fd_shred_race_entry_t * e = &ctx->race[ ring_idx ].tbl[ tbl_idx ];

  if( e->full_key!=full_key ) {
    /* Empty slot or hash collision — (re-)initialize for this shred. */
    e->full_key     = full_key;
    e->src_first    = (uchar)source;
    e->sources_seen = (ushort)(1U << source);
    e->ts_first     = (ulong)ts;
    ctx->race_metrics.first[ source ]++;
    return;
  }

  ushort src_bit = (ushort)(1U << source);
  if( e->sources_seen & src_bit ) return;  /* already recorded from this source */

  uint prev_cnt = (uint)__builtin_popcount( (uint)e->sources_seen );
  e->sources_seen = (ushort)(e->sources_seen | src_bit);

  if( prev_cnt==1U ) ctx->race_metrics.second[ source ]++;
  else               ctx->race_metrics.third [ source ]++;

  long delay_ticks = ts - (long)e->ts_first;
  if( FD_LIKELY( delay_ticks>0L ) ) {
    ulong delay_ns = (ulong)( (double)delay_ticks / ctx->tick_per_ns );
    fd_histf_sample( &ctx->race_metrics.delay[ source ], delay_ns );
  }
}

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
  /* Pass all 8 RX socket slots; unused slots hold -1 (==UINT_MAX as uint,
     which never matches a real fd in the BPF filter). */
  populate_sock_filter_policy_fd_shred_mcast_tile(
      out_cnt, out,
      (uint)fd_log_private_logfile_fd(),
      (uint)tile->shred_mcast.mcast_rx_socks[0],
      (uint)tile->shred_mcast.mcast_rx_socks[1],
      (uint)tile->shred_mcast.mcast_rx_socks[2],
      (uint)tile->shred_mcast.mcast_rx_socks[3],
      (uint)tile->shred_mcast.mcast_rx_socks[4],
      (uint)tile->shred_mcast.mcast_rx_socks[5],
      (uint)tile->shred_mcast.mcast_rx_socks[6],
      (uint)tile->shred_mcast.mcast_rx_socks[7],
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
  for( ulong i=0UL; i<FD_SHRED_MCAST_SRC_MAX; i++ )
    if( FD_LIKELY( tile->shred_mcast.mcast_rx_socks[ i ] != -1 ) )
      out_fds[ out_cnt++ ] = tile->shred_mcast.mcast_rx_socks[ i ];
  out_fds[ out_cnt++ ] = tile->shred_mcast.mcast_tx_sock;
  return out_cnt;
}

static void
privileged_init( fd_topo_t *      topo  FD_PARAM_UNUSED,
                  fd_topo_tile_t * tile ) {

  /* Initialize all RX socket slots to -1 (unused) */
  for( ulong i=0UL; i<FD_SHRED_MCAST_SRC_MAX; i++ )
    tile->shred_mcast.mcast_rx_socks[ i ] = -1;

  /* --- RX sockets: one per source group (may have different ports) --- */
  ulong src_cnt = tile->shred_mcast.mcast_src_cnt;
  for( ulong i=0UL; i<src_cnt; i++ ) {
    int rx_sock = socket( AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP );
    if( FD_UNLIKELY( rx_sock < 0 ) )
      FD_LOG_ERR(( "shred_mcast: socket(RX[%lu]) failed (%d-%s)", i, errno, fd_io_strerror( errno ) ));

    int reuse = 1;
    if( FD_UNLIKELY( setsockopt( rx_sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse) ) ) )
      FD_LOG_ERR(( "shred_mcast: setsockopt(SO_REUSEPORT,[%lu]) failed (%d-%s)", i, errno, fd_io_strerror( errno ) ));

    int rcvbuf = 1<<20; /* 1 MiB */
    (void)setsockopt( rx_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf) );

    struct sockaddr_in bind_addr = {
      .sin_family      = AF_INET,
      .sin_addr.s_addr = INADDR_ANY,
      .sin_port        = fd_ushort_bswap( tile->shred_mcast.mcast_src_ports[ i ] ),
    };
    if( FD_UNLIKELY( bind( rx_sock, fd_type_pun_const( &bind_addr ), sizeof(bind_addr) ) ) )
      FD_LOG_ERR(( "shred_mcast: bind(RX[%lu]) failed (%d-%s)", i, errno, fd_io_strerror( errno ) ));

    struct ip_mreq mreq = {
      .imr_multiaddr.s_addr = tile->shred_mcast.mcast_src_ips[ i ],
      .imr_interface.s_addr = INADDR_ANY,
    };
    if( FD_UNLIKELY( setsockopt( rx_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq) ) ) )
      FD_LOG_ERR(( "shred_mcast: IP_ADD_MEMBERSHIP[%lu] failed (%d-%s)", i, errno, fd_io_strerror( errno ) ));

    uint ip = tile->shred_mcast.mcast_src_ips[ i ];
    FD_LOG_NOTICE(( "shred_mcast: joined multicast group %u.%u.%u.%u:%u (rx_sock=%d)",
                    (ip      ) & 0xFF, (ip >>  8) & 0xFF,
                    (ip >> 16) & 0xFF, (ip >> 24) & 0xFF,
                    tile->shred_mcast.mcast_src_ports[ i ], rx_sock ));

    tile->shred_mcast.mcast_rx_socks[ i ] = rx_sock;
  }

  /* --- TX socket: single socket, sendto() repeated per destination --- */
  int tx_sock = socket( AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP );
  if( FD_UNLIKELY( tx_sock < 0 ) )
    FD_LOG_ERR(( "shred_mcast: socket(TX) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  uchar ttl = tile->shred_mcast.mcast_ttl ? tile->shred_mcast.mcast_ttl : 1;
  if( FD_UNLIKELY( setsockopt( tx_sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl) ) ) )
    FD_LOG_ERR(( "shred_mcast: setsockopt(IP_MULTICAST_TTL) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  FD_LOG_NOTICE(( "shred_mcast: TX socket ready tx_sock=%d ttl=%u dst_cnt=%lu",
                  tx_sock, ttl, tile->shred_mcast.mcast_dst_cnt ));

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

  /* Initialize race tracking tables */
  ctx->tick_per_ns = fd_tempo_tick_per_ns( NULL );
  for( ulong i=0UL; i<FD_SHRED_MCAST_DEDUP_SLOT_CNT; i++ ) {
    ctx->race[ i ].slot = ULONG_MAX;
    fd_memset( ctx->race[ i ].tbl, 0xFF,
               FD_SHRED_RACE_TBL_SZ * sizeof(fd_shred_race_entry_t) );
  }

  /* Initialize race delay histograms */
  for( ulong s=0UL; s<FD_SHRED_RACE_SRC_CNT; s++ ) {
    fd_histf_join( fd_histf_new( &ctx->race_metrics.delay[ s ],
                                 FD_MHIST_MIN( SHRED_MCAST, RACE_MCAST_SRC0_DELAY_NANOS ),
                                 FD_MHIST_MAX( SHRED_MCAST, RACE_MCAST_SRC0_DELAY_NANOS ) ) );
  }

  /* Set up input link workspaces (shred → shred_mcast) */
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];
    ctx->in[ i ].mem    = wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  /* Set up output link workspaces (shred_mcast → shred, one per shred tile) */
  ctx->shred_tile_cnt = 0UL;
  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->out_link_id[ i ] ];
    if( strcmp( link->name, "mcast_shred" ) ) continue;
    ulong j = ctx->shred_tile_cnt++;
    fd_topo_wksp_t * wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];
    ctx->out[ j ].mem     = wksp->wksp;
    ctx->out[ j ].chunk0  = fd_dcache_compact_chunk0( ctx->out[ j ].mem, link->dcache );
    ctx->out[ j ].wmark   = fd_dcache_compact_wmark ( ctx->out[ j ].mem, link->dcache, link->mtu );
    ctx->out[ j ].chunk   = ctx->out[ j ].chunk0;
    ctx->out[ j ].out_idx = i;
  }

  /* Copy socket FDs and destination addresses from tile config */
  ctx->mcast_rx_cnt = tile->shred_mcast.mcast_src_cnt;
  for( ulong i=0UL; i<FD_SHRED_MCAST_SRC_MAX; i++ )
    ctx->mcast_rx_socks[ i ] = tile->shred_mcast.mcast_rx_socks[ i ];
  ctx->mcast_tx_sock = tile->shred_mcast.mcast_tx_sock;

  ctx->mcast_dst_cnt = tile->shred_mcast.mcast_dst_cnt;
  for( ulong i=0UL; i<tile->shred_mcast.mcast_dst_cnt; i++ ) {
    ctx->mcast_dst_addrs[ i ].sin_family      = AF_INET;
    ctx->mcast_dst_addrs[ i ].sin_addr.s_addr = tile->shred_mcast.mcast_dst_ips[ i ];
    ctx->mcast_dst_addrs[ i ].sin_port        = fd_ushort_bswap( tile->shred_mcast.mcast_dst_ports[ i ] );
  }

  FD_LOG_NOTICE(( "shred_mcast: tile initialized, in_cnt=%lu src_cnt=%lu dst_cnt=%lu tx_sock=%d",
                  tile->in_cnt, ctx->mcast_rx_cnt, ctx->mcast_dst_cnt, ctx->mcast_tx_sock ));
}

/* before_credit: poll the multicast RX socket for incoming shreds from
   the external multicast feed.  Uses MSG_DONTWAIT to avoid blocking.
   For each new shred, deduplicates and forwards to the TX socket. */
static void
before_credit( fd_shred_mcast_ctx_t * ctx,
               fd_stem_context_t *    stem,
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

  for( ulong s=0UL; s<ctx->mcast_rx_cnt; s++ ) {
    int rx_sock = ctx->mcast_rx_socks[ s ];
    if( FD_UNLIKELY( rx_sock < 0 ) ) continue;

    int cnt = recvmmsg( rx_sock, msgs, FD_SHRED_MCAST_RX_BURST, MSG_DONTWAIT, NULL );
    if( FD_LIKELY( cnt <= 0 ) ) continue;

    *charge_busy = 1;

    for( int i=0; i<cnt; i++ ) {
      uchar const * raw    = bufs[ i ];
      ulong         raw_sz = msgs[ i ].msg_len;

      fd_shred_t const * shred = fd_shred_parse( raw, raw_sz );
      if( FD_UNLIKELY( !shred ) ) { ctx->metrics.parse_failed++; continue; }

      int   is_code  = fd_shred_is_code( fd_shred_type( shred->variant ) );
      ulong global_i = (ulong)shred->fec_set_idx + (ulong)shred->idx;

      race_track_shred( ctx, shred->slot, is_code, global_i, s, fd_tickcount() );

      if( dedup_check_and_set( ctx, shred->slot, is_code, global_i ) ) {
        ctx->metrics.dedup_skipped++;
        ctx->metrics.rx_src_dedup[ s ]++;
        continue;
      }

      for( ulong d=0UL; d<ctx->mcast_dst_cnt; d++ ) {
        (void)sendto( ctx->mcast_tx_sock, raw, raw_sz, 0,
                      fd_type_pun_const( &ctx->mcast_dst_addrs[ d ] ),
                      sizeof(ctx->mcast_dst_addrs[ d ]) );
      }

      ctx->metrics.rx_mcast++;
      ctx->metrics.tx_mcast       += ctx->mcast_dst_cnt;
      ctx->metrics.tx_relay_bytes += ctx->mcast_dst_cnt * raw_sz;
      ctx->metrics.rx_src_shreds[ s ]++;
      ctx->metrics.rx_src_bytes [ s ] += raw_sz;

      /* Forward to the appropriate shred tile via stem (round-robin by sig) */
      if( FD_LIKELY( ctx->shred_tile_cnt > 0UL ) ) {
        ulong shred_sig = fd_ulong_load_8( shred->signature );
        ulong tile_idx  = shred_sig % ctx->shred_tile_cnt;
        uchar * dst = fd_chunk_to_laddr( ctx->out[ tile_idx ].mem, ctx->out[ tile_idx ].chunk );
        fd_memcpy( dst, raw, raw_sz );
        ulong out_sig = fd_disco_shred_out_shred_sig( 0, shred->slot, shred->fec_set_idx,
                                                       is_code, shred->idx );
        ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
        fd_stem_publish( stem, ctx->out[ tile_idx ].out_idx, out_sig,
                         ctx->out[ tile_idx ].chunk, raw_sz, 0UL, tspub, tspub );
        ctx->out[ tile_idx ].chunk = fd_dcache_compact_next( ctx->out[ tile_idx ].chunk, raw_sz,
                                                              ctx->out[ tile_idx ].chunk0,
                                                              ctx->out[ tile_idx ].wmark );
      }
    }
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

  race_track_shred( ctx, shred->slot, is_code, global_i, FD_SHRED_RACE_SRC_TURBINE, fd_tickcount() );

  if( dedup_check_and_set( ctx, shred->slot, is_code, global_i ) ) {
    ctx->metrics.dedup_skipped++;
    return;
  }

  for( ulong d=0UL; d<ctx->mcast_dst_cnt; d++ ) {
    (void)sendto( ctx->mcast_tx_sock, ctx->pkt_buf, ctx->pkt_sz, 0,
                  fd_type_pun_const( &ctx->mcast_dst_addrs[ d ] ),
                  sizeof(ctx->mcast_dst_addrs[ d ]) );
  }

  ctx->metrics.rx_turbine++;
  ctx->metrics.tx_mcast       += ctx->mcast_dst_cnt;
  ctx->metrics.tx_mcast_bytes += ctx->mcast_dst_cnt * ctx->pkt_sz;
}

static void
metrics_write( fd_shred_mcast_ctx_t * ctx ) {
  FD_MCNT_SET( SHRED_MCAST, RX_TURBINE_SHREDS, ctx->metrics.rx_turbine    );
  FD_MCNT_SET( SHRED_MCAST, RX_MCAST_SHREDS,   ctx->metrics.rx_mcast      );
  FD_MCNT_SET( SHRED_MCAST, TX_MCAST_SHREDS,   ctx->metrics.tx_mcast       );
  FD_MCNT_SET( SHRED_MCAST, TX_MCAST_BYTES,    ctx->metrics.tx_mcast_bytes  );
  FD_MCNT_SET( SHRED_MCAST, TX_RELAY_BYTES,    ctx->metrics.tx_relay_bytes  );
  FD_MCNT_SET( SHRED_MCAST, DEDUP_SKIPPED,     ctx->metrics.dedup_skipped   );
  FD_MCNT_SET( SHRED_MCAST, PARSE_FAILED,      ctx->metrics.parse_failed  );
  for( ulong i=0UL; i<FD_SHRED_MCAST_SRC_MAX; i++ ) {
    fd_metrics_tl[ FD_METRICS_COUNTER_SHRED_MCAST_RX_MCAST_SRC0_SHREDS_OFF + 2UL*i     ] = ctx->metrics.rx_src_shreds[ i ];
    fd_metrics_tl[ FD_METRICS_COUNTER_SHRED_MCAST_RX_MCAST_SRC0_SHREDS_OFF + 2UL*i+1UL ] = ctx->metrics.rx_src_bytes [ i ];
  }
  for( ulong i=0UL; i<FD_SHRED_MCAST_SRC_MAX; i++ ) {
    fd_metrics_tl[ FD_METRICS_COUNTER_SHRED_MCAST_RX_MCAST_SRC0_DEDUP_OFF + i ] = ctx->metrics.rx_src_dedup[ i ];
  }

  /* Race placement counters: stride 4 per source (first, second, third, solo).
     Source indices 0..FD_SHRED_MCAST_SRC_MAX-1 = mcast; FD_SHRED_MCAST_SRC_MAX = turbine. */
  for( ulong s=0UL; s<FD_SHRED_RACE_SRC_CNT; s++ ) {
    ulong base = FD_METRICS_COUNTER_SHRED_MCAST_RACE_MCAST_SRC0_FIRST_OFF + 4UL*s;
    fd_metrics_tl[ base + 0UL ] = ctx->race_metrics.first [ s ];
    fd_metrics_tl[ base + 1UL ] = ctx->race_metrics.second[ s ];
    fd_metrics_tl[ base + 2UL ] = ctx->race_metrics.third [ s ];
    fd_metrics_tl[ base + 3UL ] = ctx->race_metrics.solo  [ s ];
  }

  /* Race delay histograms: stride (FD_HISTF_BUCKET_CNT+1) per source. */
  for( ulong s=0UL; s<FD_SHRED_RACE_SRC_CNT; s++ ) {
    ulong hist_base = FD_METRICS_HISTOGRAM_SHRED_MCAST_RACE_MCAST_SRC0_DELAY_NANOS_OFF
                    + s * (FD_HISTF_BUCKET_CNT + 1UL);
    fd_histf_t const * h = &ctx->race_metrics.delay[ s ];
    for( ulong b=0UL; b<FD_HISTF_BUCKET_CNT; b++ )
      fd_metrics_tl[ hist_base + b ] = h->counts[ b ];
    fd_metrics_tl[ hist_base + FD_HISTF_BUCKET_CNT ] = h->sum;
  }
}

#define STEM_BURST (FD_SHRED_MCAST_RX_BURST)

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
  .name                     = "smcast",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
