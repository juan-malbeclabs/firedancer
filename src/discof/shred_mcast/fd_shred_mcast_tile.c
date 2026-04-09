#define _GNU_SOURCE
#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_disco.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/shred/fd_stake_ci.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/sha512/fd_sha512.h"
#include "../../ballet/reedsol/fd_reedsol.h"
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

/* Shreds per FEC set.  Mirrors the private define in fd_fec_resolver.c. */
#define FD_SHRED_MCAST_FEC_SHRED_CNT (32UL)

/* Number of FEC sets per slot half (fec_set_idx is a multiple of FD_SHRED_MCAST_FEC_SHRED_CNT=32,
   max shred idx is 32767, so max fec_idx = 32767/32 = 1023, → 1024 FEC sets).
   One bit per FEC set → 128 bytes for the bitset. */
#define FD_SHRED_MCAST_SEEN_FEC_SETS  (1024UL)
#define FD_SHRED_MCAST_SEEN_FEC_BYTES (FD_SHRED_MCAST_SEEN_FEC_SETS / 8UL) /* 128 */

/* Input link kinds */
#define IN_KIND_SHRED (0)
#define IN_KIND_STAKE (1)
#define IN_KIND_EPOCH (2) /* Firedancer: replay_epoch instead of stake_out */

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
     shreds.  A slot value of ULONG_MAX means the entry is unused.
     fec_ok/fec_bad track per-FEC-set signature verification results
     so we only call ed25519_verify once per FEC set (index = fec_set_idx/32). */
  struct {
    ulong slot;
    uchar data_seen[ FD_SHRED_MCAST_SEEN_BYTES     ];
    uchar code_seen[ FD_SHRED_MCAST_SEEN_BYTES     ];
    uchar fec_ok   [ FD_SHRED_MCAST_SEEN_FEC_BYTES ]; /* sig verified OK */
    uchar fec_bad  [ FD_SHRED_MCAST_SEEN_FEC_BYTES ]; /* sig verified BAD */
  } dedup[ FD_SHRED_MCAST_DEDUP_SLOT_CNT ];

  /* Input link kinds (IN_KIND_SHRED or IN_KIND_STAKE) */
  int in_kind[ FD_TOPO_MAX_TILE_IN_LINKS ];

  /* Input link workspaces — one entry per upstream link */
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
    ulong sig_failed;
    ulong rx_src_shreds      [ FD_SHRED_MCAST_SRC_MAX ];
    ulong rx_src_bytes       [ FD_SHRED_MCAST_SRC_MAX ];
    ulong rx_src_dedup       [ FD_SHRED_MCAST_SRC_MAX ];
    ulong rx_src_parse_failed[ FD_SHRED_MCAST_SRC_MAX ];
    ulong rx_src_sender_ip   [ FD_SHRED_MCAST_SRC_MAX ]; /* champion sender IPv4 per socket (network byte order) */
  } metrics;

  /* Sticky sender IP tracking: champion = sender IP with the most cumulative
     packets per mcast socket.  Only displaced when a challenger accumulates
     more packets than the current champion. */
  uint  rx_src_champion_ip  [ FD_SHRED_MCAST_SRC_MAX ];
  ulong rx_src_champion_cnt [ FD_SHRED_MCAST_SRC_MAX ];
  uint  rx_src_challenger_ip [ FD_SHRED_MCAST_SRC_MAX ];
  ulong rx_src_challenger_cnt[ FD_SHRED_MCAST_SRC_MAX ];

  /* tick → nanosecond conversion factor (populated in unprivileged_init) */
  double tick_per_ns;

  /* Race tracking: per-slot hash table (indexed by slot % DEDUP_SLOT_CNT).
     Tracks which source delivered each shred first, and the delay for
     subsequent sources.  Evicted when the ring slot is reused for a new slot. */
  struct {
    ulong                 slot;
    fd_shred_race_entry_t tbl[ FD_SHRED_RACE_TBL_SZ ];
  } race[ FD_SHRED_MCAST_DEDUP_SLOT_CNT ];

  /* Race placement counters and delay histograms (split by placement).
     Source index: 0..FD_SHRED_MCAST_SRC_MAX-1 = mcast; FD_SHRED_MCAST_SRC_MAX = turbine. */
  struct {
    ulong      first       [ FD_SHRED_RACE_SRC_CNT ];
    ulong      second      [ FD_SHRED_RACE_SRC_CNT ];
    ulong      third       [ FD_SHRED_RACE_SRC_CNT ];
    ulong      solo        [ FD_SHRED_RACE_SRC_CNT ];
    fd_histf_t delay_second[ FD_SHRED_RACE_SRC_CNT ];  /* delay vs first, when arriving 2nd */
    fd_histf_t delay_third [ FD_SHRED_RACE_SRC_CNT ];  /* delay vs first, when arriving 3rd+ */
  } race_metrics;

  /* Signature verification support.
     stake_ci provides leader schedule lookups (updated via replay_stake link).
     sha512 and bmtree_mem are scratch workspaces for ed25519 + Merkle root computation.
     require_leader_sig: when 1, only enforce strict sig verification after the first
     stake update is received (has_received_stake==1).  Set in shred_relay mode.
     has_received_stake: set to 1 after the first stake update is finalized.
     stake_epoch / stake_start_slot / stake_slot_cnt: epoch info from the most recent
     stake update (used for GUI display).  Only valid when has_received_stake==1. */
  fd_stake_ci_t * stake_ci;
  fd_sha512_t   * sha512;
  void          * bmtree_mem;
  int             require_leader_sig;
  int             has_received_stake;
  ulong           stake_epoch;
  ulong           stake_start_slot;
  ulong           stake_slot_cnt;
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
   Must be called BEFORE dedup_check_and_set so we observe every source.
   Only shreds seen by TWO OR MORE sources contribute to first/second/third
   counters — solo deliveries are not counted (no race occurred). */
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
    /* Empty slot or hash collision — (re-)initialize for this shred.
       Do NOT increment first[] yet: we only count contested shreds
       (2+ sources), so we wait until a second source arrives. */
    e->full_key     = full_key;
    e->src_first    = (uchar)source;
    e->sources_seen = (ushort)(1U << source);
    e->ts_first     = (ulong)ts;
    return;
  }

  ushort src_bit = (ushort)(1U << source);
  if( e->sources_seen & src_bit ) return;  /* already recorded from this source */

  uint prev_cnt = (uint)__builtin_popcount( (uint)e->sources_seen );
  e->sources_seen = (ushort)(e->sources_seen | src_bit);

  if( prev_cnt==1U ) {
    /* Second source: now we know this is a contested shred.
       Retroactively credit the first source, then credit this one. */
    ctx->race_metrics.first [ e->src_first ]++;
    ctx->race_metrics.second[ source ]++;
  } else {
    ctx->race_metrics.third[ source ]++;
  }

  long delay_ticks = ts - (long)e->ts_first;
  if( FD_LIKELY( delay_ticks>0L ) ) {
    ulong delay_ns = (ulong)( (double)delay_ticks / ctx->tick_per_ns );
    if( prev_cnt==1U ) fd_histf_sample( &ctx->race_metrics.delay_second[ source ], delay_ns );
    else               fd_histf_sample( &ctx->race_metrics.delay_third [ source ], delay_ns );
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
    fd_memset( ctx->dedup[ ring_idx ].data_seen, 0, FD_SHRED_MCAST_SEEN_BYTES     );
    fd_memset( ctx->dedup[ ring_idx ].code_seen, 0, FD_SHRED_MCAST_SEEN_BYTES     );
    fd_memset( ctx->dedup[ ring_idx ].fec_ok,    0, FD_SHRED_MCAST_SEEN_FEC_BYTES );
    fd_memset( ctx->dedup[ ring_idx ].fec_bad,   0, FD_SHRED_MCAST_SEEN_FEC_BYTES );
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
  l = FD_LAYOUT_APPEND( l, alignof( fd_shred_mcast_ctx_t ),   sizeof( fd_shred_mcast_ctx_t )                          );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(),                fd_stake_ci_footprint()                                 );
  l = FD_LAYOUT_APPEND( l, alignof( fd_sha512_t ),             sizeof( fd_sha512_t )                                   );
  l = FD_LAYOUT_APPEND( l, fd_bmtree_commit_align(),           fd_bmtree_commit_footprint( FD_SHRED_MERKLE_LAYER_CNT ) );
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
  fd_shred_mcast_ctx_t * ctx       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_shred_mcast_ctx_t),   sizeof(fd_shred_mcast_ctx_t)                          );
  void                 * _stake_ci = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(),               fd_stake_ci_footprint()                                );
  void                 * _sha512   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sha512_t),              sizeof(fd_sha512_t)                                    );
  void                 * _bmtree   = FD_SCRATCH_ALLOC_APPEND( l, fd_bmtree_commit_align(),          fd_bmtree_commit_footprint( FD_SHRED_MERKLE_LAYER_CNT ) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  fd_memset( ctx, 0, sizeof(*ctx) );

  /* Initialize stake_ci with a null identity (smcast only needs leader schedule, not sdest routing) */
  fd_pubkey_t null_identity[1];
  fd_memset( null_identity, 0, sizeof(fd_pubkey_t) );
  ctx->stake_ci          = fd_stake_ci_join( fd_stake_ci_new( _stake_ci, null_identity ) );
  ctx->sha512            = fd_sha512_join( fd_sha512_new( _sha512 ) );
  ctx->bmtree_mem        = _bmtree;
  ctx->require_leader_sig = tile->shred_mcast.require_leader_sig;

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

  /* Initialize race delay histograms (split: second and third placement) */
  for( ulong s=0UL; s<FD_SHRED_RACE_SRC_CNT; s++ ) {
    fd_histf_join( fd_histf_new( &ctx->race_metrics.delay_second[ s ],
                                 FD_MHIST_MIN( SHRED_MCAST, RACE_MCAST_SRC0_DELAY_SECOND_NANOS ),
                                 FD_MHIST_MAX( SHRED_MCAST, RACE_MCAST_SRC0_DELAY_SECOND_NANOS ) ) );
    fd_histf_join( fd_histf_new( &ctx->race_metrics.delay_third[ s ],
                                 FD_MHIST_MIN( SHRED_MCAST, RACE_MCAST_SRC0_DELAY_THIRD_NANOS ),
                                 FD_MHIST_MAX( SHRED_MCAST, RACE_MCAST_SRC0_DELAY_THIRD_NANOS ) ) );
  }

  /* Set up input link workspaces */
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    if( !strcmp( link->name, "replay_epoch" ) )           ctx->in_kind[ i ] = IN_KIND_EPOCH;
    else if( !strcmp( link->name, "replay_stake" ) ||
             !strcmp( link->name, "stake_out"    ) )      ctx->in_kind[ i ] = IN_KIND_STAKE;
    else                                                  ctx->in_kind[ i ] = IN_KIND_SHRED;
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

/* fec_sigcheck: verify the leader Ed25519 signature for a shred received
   from an external multicast source.  Only called for the first shred of
   each FEC set (subsequent shreds reuse the cached fec_ok/fec_bad result).

   Returns 1 if the signature is valid.
   Returns 0 if the signature is provably invalid, OR if epoch data is
   unavailable AND strict verification is active (require_leader_sig==1 AND
   has_received_stake==1).  Before the first stake update is received, shreds
   pass through regardless of require_leader_sig (startup warmup, Option B). */
static inline int
fec_sigcheck( fd_shred_mcast_ctx_t * ctx,
              fd_shred_t const     * shred ) {
  /* Strict mode = require_leader_sig set AND we've already loaded epoch data once */
  int strict = ctx->require_leader_sig & ctx->has_received_stake;
  fd_epoch_leaders_t const * lsched = fd_stake_ci_get_lsched_for_slot( ctx->stake_ci, shred->slot );
  if( FD_UNLIKELY( !lsched ) ) return !strict;
  fd_pubkey_t const * leader = fd_epoch_leaders_get( lsched, shred->slot );
  if( FD_UNLIKELY( !leader ) ) return !strict;

  uchar shred_type = fd_shred_type( shred->variant );
  /* Reject legacy shreds: they have no Merkle proof */
  if( FD_UNLIKELY( (shred_type==FD_SHRED_TYPE_LEGACY_DATA) |
                   (shred_type==FD_SHRED_TYPE_LEGACY_CODE) ) ) return 0;
  ulong tree_depth = fd_shred_merkle_cnt( shred->variant );
  if( FD_UNLIKELY( tree_depth!=6UL ) ) return 0; /* all live shreds use depth 6 */

  int   is_data     = fd_shred_is_data( shred_type );
  ulong in_type_idx = fd_ulong_if( is_data, shred->idx - shred->fec_set_idx, shred->code.idx );
  if( FD_UNLIKELY( in_type_idx >= fd_ulong_if( is_data, FD_REEDSOL_DATA_SHREDS_MAX, FD_REEDSOL_PARITY_SHREDS_MAX ) ) ) return 0;
  ulong shred_idx = fd_ulong_if( is_data, in_type_idx, in_type_idx + shred->code.data_cnt );

  /* Compute Merkle-protected sizes (mirrors fd_fec_resolver.c) */
  ulong rsp = 1115UL + FD_SHRED_DATA_HEADER_SZ - FD_SHRED_SIGNATURE_SZ
            - FD_SHRED_MERKLE_NODE_SZ * tree_depth
            - FD_SHRED_MERKLE_ROOT_SZ * fd_shred_is_chained ( shred_type )
            - FD_SHRED_SIGNATURE_SZ   * fd_shred_is_resigned( shred_type );
  ulong merkle_protected_sz = fd_ulong_if( is_data,
      rsp + FD_SHRED_MERKLE_ROOT_SZ * fd_shred_is_chained( shred_type ),
      rsp + FD_SHRED_MERKLE_ROOT_SZ * fd_shred_is_chained( shred_type ) + FD_SHRED_CODE_HEADER_SZ - FD_ED25519_SIG_SZ );

  fd_bmtree_node_t leaf[1];
  fd_bmtree_hash_leaf( leaf, (uchar const *)shred + sizeof(fd_ed25519_sig_t),
                       merkle_protected_sz, FD_BMTREE_LONG_PREFIX_SZ );

  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( ctx->bmtree_mem,
      FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ, FD_SHRED_MERKLE_LAYER_CNT );
  fd_bmtree_node_t          root[1];
  fd_shred_merkle_t const * proof = fd_shred_merkle_nodes( shred );
  if( FD_UNLIKELY( !fd_bmtree_commitp_insert_with_proof( tree, shred_idx, leaf,
                                                          (uchar const *)proof, tree_depth, root ) ) ) return 0;

  return fd_ed25519_verify( root->hash, 32UL, shred->signature, leader->uc, ctx->sha512 ) == FD_ED25519_SUCCESS;
}

/* before_credit: poll the multicast RX socket for incoming shreds from
   the external multicast feed.  Uses MSG_DONTWAIT to avoid blocking.
   For each new shred, deduplicates, signature-verifies, and forwards. */
static void
before_credit( fd_shred_mcast_ctx_t * ctx,
               fd_stem_context_t *    stem,
               int *                  charge_busy ) {
  /* Declare static arrays to avoid large stack frames */
  static struct mmsghdr    msgs     [ FD_SHRED_MCAST_RX_BURST ];
  static struct iovec      iovs     [ FD_SHRED_MCAST_RX_BURST ];
  static uchar             bufs     [ FD_SHRED_MCAST_RX_BURST ][ FD_SHRED_MAX_SZ ];
  static struct sockaddr_in src_addrs[ FD_SHRED_MCAST_RX_BURST ];

  for( ulong i=0UL; i<FD_SHRED_MCAST_RX_BURST; i++ ) {
    iovs[ i ].iov_base              = bufs[ i ];
    iovs[ i ].iov_len               = FD_SHRED_MAX_SZ;
    msgs[ i ].msg_hdr.msg_iov       = &iovs[ i ];
    msgs[ i ].msg_hdr.msg_iovlen    = 1;
    msgs[ i ].msg_hdr.msg_name      = &src_addrs[ i ];
    msgs[ i ].msg_hdr.msg_namelen   = sizeof(struct sockaddr_in);
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

      /* Sticky sender IP tracking: maintain champion (most cumulative packets)
         per mcast socket.  A challenger only displaces the champion once it
         has accumulated strictly more packets. */
      uint sender_ip = src_addrs[ i ].sin_addr.s_addr;
      if( FD_LIKELY( sender_ip != 0U ) ) {
        if( FD_LIKELY( sender_ip == ctx->rx_src_champion_ip[ s ] ) || ctx->rx_src_champion_ip[ s ] == 0U ) {
          ctx->rx_src_champion_ip[ s ] = sender_ip;
          ctx->rx_src_champion_cnt[ s ]++;
        } else if( sender_ip == ctx->rx_src_challenger_ip[ s ] ) {
          ctx->rx_src_challenger_cnt[ s ]++;
          if( ctx->rx_src_challenger_cnt[ s ] > ctx->rx_src_champion_cnt[ s ] ) {
            ctx->rx_src_champion_ip[ s ]   = ctx->rx_src_challenger_ip[ s ];
            ctx->rx_src_champion_cnt[ s ]  = ctx->rx_src_challenger_cnt[ s ];
            ctx->rx_src_challenger_ip[ s ]  = 0U;
            ctx->rx_src_challenger_cnt[ s ] = 0UL;
          }
        } else {
          /* New IP — becomes challenger, displacing previous challenger */
          ctx->rx_src_challenger_ip[ s ]  = sender_ip;
          ctx->rx_src_challenger_cnt[ s ] = 1UL;
        }
        ctx->metrics.rx_src_sender_ip[ s ] = (ulong)ctx->rx_src_champion_ip[ s ];
      }

      fd_shred_t const * shred = fd_shred_parse( raw, raw_sz );
      if( FD_UNLIKELY( !shred ) ) { ctx->metrics.parse_failed++; ctx->metrics.rx_src_parse_failed[ s ]++; continue; }

      int   is_code  = fd_shred_is_code( fd_shred_type( shred->variant ) );
      ulong global_i = (ulong)shred->fec_set_idx + (ulong)shred->idx;

      race_track_shred( ctx, shred->slot, is_code, global_i, s, fd_tickcount() );

      if( dedup_check_and_set( ctx, shred->slot, is_code, global_i ) ) {
        ctx->metrics.dedup_skipped++;
        ctx->metrics.rx_src_dedup[ s ]++;
        continue;
      }

      /* Per-FEC-set signature verification.  All shreds in the same FEC set
         share the same leader signature, so we verify once and cache the result. */
      ulong fec_idx = (ulong)shred->fec_set_idx / FD_SHRED_MCAST_FEC_SHRED_CNT;
      if( FD_LIKELY( fec_idx < FD_SHRED_MCAST_SEEN_FEC_SETS ) ) {
        ulong ring_idx = shred->slot % FD_SHRED_MCAST_DEDUP_SLOT_CNT;
        ulong word     = fec_idx >> 3;
        uchar bit      = (uchar)(1U << (fec_idx & 7U));
        if( FD_UNLIKELY( ctx->dedup[ ring_idx ].fec_bad[ word ] & bit ) ) {
          /* FEC set already known bad — drop without re-verifying */
          ctx->metrics.sig_failed++;
          continue;
        }
        if( !( ctx->dedup[ ring_idx ].fec_ok[ word ] & bit ) ) {
          /* First shred of this FEC set: must verify */
          if( FD_UNLIKELY( !fec_sigcheck( ctx, shred ) ) ) {
            ctx->dedup[ ring_idx ].fec_bad[ word ] |= bit;
            ctx->metrics.sig_failed++;
            continue;
          }
          ctx->dedup[ ring_idx ].fec_ok[ word ] |= bit;
        }
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
                                                       shred->idx );
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
   shred tile via fd_disco_shred_out_shred_sig().
   For stake messages, initialize the stake_ci update (finalized in after_frag). */
static inline void
during_frag( fd_shred_mcast_ctx_t * ctx,
              ulong                  in_idx,
              ulong                  seq    FD_PARAM_UNUSED,
              ulong                  sig    FD_PARAM_UNUSED,
              ulong                  chunk,
              ulong                  sz,
              ulong                  ctl    FD_PARAM_UNUSED ) {
  ctx->skip_frag = 0;
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_STAKE ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) )
      FD_LOG_ERR(( "smcast: corrupt stake chunk %lu not in [%lu,%lu]", chunk, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    fd_stake_ci_stake_msg_init( ctx->stake_ci, fd_type_pun_const( dcache_entry ) );
    ctx->skip_frag = 2; /* sentinel: finalize stake in after_frag */
    return;
  }
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_EPOCH ) ) {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) )
      FD_LOG_ERR(( "smcast: corrupt epoch chunk %lu not in [%lu,%lu]", chunk, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
    fd_epoch_info_msg_t const * epoch_msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    fd_stake_ci_epoch_msg_init( ctx->stake_ci, epoch_msg );
    ctx->skip_frag = 3; /* sentinel: finalize epoch in after_frag */
    return;
  }
  if( FD_UNLIKELY( sz > FD_SHRED_MAX_SZ ) ) { ctx->skip_frag = 1; return; }
  uchar const * src = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
  fd_memcpy( ctx->pkt_buf, src, sz );
  ctx->pkt_sz = sz;
}

/* after_frag: parse the shred, deduplicate, and forward to multicast TX.
   When turbine wins the race (shred is new), also publish via stem so
   downstream consumers (shred tile, dexf, …) see a complete winner stream
   regardless of which source delivered first. */
static inline void
after_frag( fd_shred_mcast_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq     FD_PARAM_UNUSED,
             ulong                  sig     FD_PARAM_UNUSED,
             ulong                  sz      FD_PARAM_UNUSED,
             ulong                  tsorig  FD_PARAM_UNUSED,
             ulong                  tspub   FD_PARAM_UNUSED,
             fd_stem_context_t *    stem ) {
  if( FD_UNLIKELY( ctx->skip_frag==2 ) ) {
    /* Frankendancer: stake_out / replay_stake — finalize started in during_frag */
    fd_stake_ci_stake_msg_fini_lsched_only( ctx->stake_ci );
    ulong ep = ctx->stake_ci->scratch[0].epoch;
    fd_per_epoch_info_t const * ei = &ctx->stake_ci->epoch_info[ ep % 2UL ];
    ctx->has_received_stake = 1;
    ctx->stake_epoch      = ei->epoch;
    ctx->stake_start_slot = ei->start_slot;
    ctx->stake_slot_cnt   = ei->slot_cnt;
    (void)in_idx;
    return;
  }
  if( FD_UNLIKELY( ctx->skip_frag==3 ) ) {
    /* Firedancer: replay_epoch — finalize epoch leader schedule */
    fd_stake_ci_stake_msg_fini_lsched_only( ctx->stake_ci );
    ulong ep = ctx->stake_ci->scratch[0].epoch;
    fd_per_epoch_info_t const * ei = &ctx->stake_ci->epoch_info[ ep % 2UL ];
    ctx->has_received_stake = 1;
    ctx->stake_epoch      = ei->epoch;
    ctx->stake_start_slot = ei->start_slot;
    ctx->stake_slot_cnt   = ei->slot_cnt;
    (void)in_idx;
    return;
  }
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

  /* Per-FEC-set signature verification — same logic as before_credit.
     Shreds from the shred tile may not have been leader-verified if the
     shred tile lacked stake weights (relay mode), so smcast is the
     authoritative verifier for all paths. */
  ulong fec_idx_t = (ulong)shred->fec_set_idx / FD_SHRED_MCAST_FEC_SHRED_CNT;
  if( FD_LIKELY( fec_idx_t < FD_SHRED_MCAST_SEEN_FEC_SETS ) ) {
    ulong ring_idx = shred->slot % FD_SHRED_MCAST_DEDUP_SLOT_CNT;
    ulong word     = fec_idx_t >> 3;
    uchar bit      = (uchar)(1U << (fec_idx_t & 7U));
    if( FD_UNLIKELY( ctx->dedup[ ring_idx ].fec_bad[ word ] & bit ) ) {
      ctx->metrics.sig_failed++;
      return;
    }
    if( !( ctx->dedup[ ring_idx ].fec_ok[ word ] & bit ) ) {
      if( FD_UNLIKELY( !fec_sigcheck( ctx, shred ) ) ) {
        ctx->dedup[ ring_idx ].fec_bad[ word ] |= bit;
        ctx->metrics.sig_failed++;
        return;
      }
      ctx->dedup[ ring_idx ].fec_ok[ word ] |= bit;
    }
  }

  /* Turbine won the race — forward to mcast destinations */
  for( ulong d=0UL; d<ctx->mcast_dst_cnt; d++ ) {
    (void)sendto( ctx->mcast_tx_sock, ctx->pkt_buf, ctx->pkt_sz, 0,
                  fd_type_pun_const( &ctx->mcast_dst_addrs[ d ] ),
                  sizeof(ctx->mcast_dst_addrs[ d ]) );
  }

  /* Also publish via stem so downstream tiles see all race winners uniformly,
     same as when mcast wins in before_credit. */
  if( FD_LIKELY( ctx->shred_tile_cnt > 0UL ) ) {
    ulong shred_sig = fd_ulong_load_8( shred->signature );
    ulong tile_idx  = shred_sig % ctx->shred_tile_cnt;
    uchar * dst = fd_chunk_to_laddr( ctx->out[ tile_idx ].mem, ctx->out[ tile_idx ].chunk );
    fd_memcpy( dst, ctx->pkt_buf, ctx->pkt_sz );
    ulong out_sig = fd_disco_shred_out_shred_sig( 0, shred->slot, shred->fec_set_idx,
                                                   shred->idx );
    ulong ts = fd_frag_meta_ts_comp( fd_tickcount() );
    fd_stem_publish( stem, ctx->out[ tile_idx ].out_idx, out_sig,
                     ctx->out[ tile_idx ].chunk, ctx->pkt_sz, 0UL, ts, ts );
    ctx->out[ tile_idx ].chunk = fd_dcache_compact_next( ctx->out[ tile_idx ].chunk, ctx->pkt_sz,
                                                          ctx->out[ tile_idx ].chunk0,
                                                          ctx->out[ tile_idx ].wmark );
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
  FD_MCNT_SET( SHRED_MCAST, PARSE_FAILED,      ctx->metrics.parse_failed    );
  FD_MCNT_SET( SHRED_MCAST, SIG_FAILED,        ctx->metrics.sig_failed      );
  for( ulong i=0UL; i<FD_SHRED_MCAST_SRC_MAX; i++ ) {
    fd_metrics_tl[ FD_METRICS_COUNTER_SHRED_MCAST_RX_MCAST_SRC0_SHREDS_OFF + 2UL*i     ] = ctx->metrics.rx_src_shreds[ i ];
    fd_metrics_tl[ FD_METRICS_COUNTER_SHRED_MCAST_RX_MCAST_SRC0_SHREDS_OFF + 2UL*i+1UL ] = ctx->metrics.rx_src_bytes [ i ];
  }
  for( ulong i=0UL; i<FD_SHRED_MCAST_SRC_MAX; i++ ) {
    fd_metrics_tl[ FD_METRICS_COUNTER_SHRED_MCAST_RX_MCAST_SRC0_DEDUP_OFF + i ] = ctx->metrics.rx_src_dedup[ i ];
  }
  for( ulong i=0UL; i<FD_SHRED_MCAST_SRC_MAX; i++ ) {
    fd_metrics_tl[ FD_METRICS_COUNTER_SHRED_MCAST_RX_MCAST_SRC0_PARSE_FAILED_OFF + i ] = ctx->metrics.rx_src_parse_failed[ i ];
  }
  for( ulong i=0UL; i<FD_SHRED_MCAST_SRC_MAX; i++ ) {
    fd_metrics_tl[ FD_METRICS_COUNTER_SHRED_MCAST_RX_MCAST_SRC0_SENDER_IP_OFF + i ] = ctx->metrics.rx_src_sender_ip[ i ];
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

  /* Race delay histograms: pairs [second, third] per source, stride 2*(FD_HISTF_BUCKET_CNT+1). */
  for( ulong s=0UL; s<FD_SHRED_RACE_SRC_CNT; s++ ) {
    ulong stride    = FD_HISTF_BUCKET_CNT + 1UL;
    ulong hist_base = FD_METRICS_HISTOGRAM_SHRED_MCAST_RACE_MCAST_SRC0_DELAY_SECOND_NANOS_OFF
                    + s * 2UL * stride;
    fd_histf_t const * hs = &ctx->race_metrics.delay_second[ s ];
    for( ulong b=0UL; b<FD_HISTF_BUCKET_CNT; b++ )
      fd_metrics_tl[ hist_base + b ] = hs->counts[ b ];
    fd_metrics_tl[ hist_base + FD_HISTF_BUCKET_CNT ] = hs->sum;

    fd_histf_t const * ht = &ctx->race_metrics.delay_third[ s ];
    for( ulong b=0UL; b<FD_HISTF_BUCKET_CNT; b++ )
      fd_metrics_tl[ hist_base + stride + b ] = ht->counts[ b ];
    fd_metrics_tl[ hist_base + stride + FD_HISTF_BUCKET_CNT ] = ht->sum;
  }

  /* Epoch info gauges */
  fd_metrics_tl[ FD_METRICS_GAUGE_SHRED_MCAST_STAKE_RECEIVED_OFF       ] = (ulong)ctx->has_received_stake;
  fd_metrics_tl[ FD_METRICS_GAUGE_SHRED_MCAST_STAKE_EPOCH_OFF          ] = ctx->stake_epoch;
  fd_metrics_tl[ FD_METRICS_GAUGE_SHRED_MCAST_STAKE_EPOCH_START_SLOT_OFF ] = ctx->stake_start_slot;
  fd_metrics_tl[ FD_METRICS_GAUGE_SHRED_MCAST_STAKE_EPOCH_SLOT_CNT_OFF ] = ctx->stake_slot_cnt;
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
