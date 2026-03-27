#define _GNU_SOURCE
#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_disco.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/pack/fd_microblock.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../flamenco/runtime/fd_system_ids.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "generated/fd_txproc_tile_seccomp.h"

/* Maximum size of an entry batch (from FD_STORE_DATA_MAX = 63985 rounded up) */
#define FD_TXLOG_ENTRY_BATCH_MAX  (65536UL)
#define FD_TXLOG_WRITER_BUF_SZ   ( 4096UL)
#define FD_TXLOG_DEDUP_CACHE_SZ  (256UL)

/* Known DEX / AMM program IDs for classification */
#define FD_TXLOG_KNOWN_PROG_CNT  (6UL)

static const char * const fd_txlog_known_prog_names[ FD_TXLOG_KNOWN_PROG_CNT ] = {
  "jupiter_v6",
  "raydium_amm_v4",
  "raydium_clmm",
  "orca_whirlpool",
  "meteora_dlmm",
  "pumpswap",
};

static const char * const fd_txlog_known_prog_b58[ FD_TXLOG_KNOWN_PROG_CNT ] = {
  "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
  "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",
  "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK",
  "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
  "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo",
  "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA",
};

typedef struct {
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
  } in[ FD_TOPO_MAX_TILE_IN_LINKS ];

  uchar  entry_batch[ FD_TXLOG_ENTRY_BATCH_MAX ];
  ulong  entry_batch_sz;
  ulong  slot;
  uint   fec_set_idx;

  /* Dedup cache: ring buffer of packed (slot<<16|fec_set_idx) seen recently */
  ulong  dedup_cache[ FD_TXLOG_DEDUP_CACHE_SZ ];
  ulong  dedup_head; /* next write position (mod FD_TXLOG_DEDUP_CACHE_SZ) */

  uchar  known_prog_ids[ FD_TXLOG_KNOWN_PROG_CNT ][ 32 ];

  int                      logfile_fd;
  fd_io_buffered_ostream_t ostream;
  uchar                    write_buf[ FD_TXLOG_WRITER_BUF_SZ ];

  int                      swaplog_fd;
  fd_io_buffered_ostream_t swap_ostream;
  uchar                    swap_write_buf[ FD_TXLOG_WRITER_BUF_SZ ];

  struct {
    ulong shredded_batches_received;
    ulong dedup_skipped;
    ulong transactions_received;
    ulong transactions_logged;
    ulong votes_skipped;
    ulong parse_errors;
    ulong dex_transactions_logged;
    ulong write_errors;
    ulong entry_batches_truncated;
  } metrics;
} fd_txlog_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof(fd_txlog_ctx_t);
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_txlog_ctx_t), sizeof(fd_txlog_ctx_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo  FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_txproc_tile( out_cnt, out,
                                             (uint)fd_log_private_logfile_fd(),
                                             (uint)tile->txproc.logfile_fd,
                                             (uint)tile->txproc.swaplog_fd );
  return sock_filter_policy_fd_txproc_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo       FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt FD_PARAM_UNUSED,
                      int *                  out_fds ) {
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  if( FD_LIKELY( -1!=tile->txproc.logfile_fd ) )
    out_fds[ out_cnt++ ] = tile->txproc.logfile_fd;
  if( FD_LIKELY( -1!=tile->txproc.swaplog_fd ) )
    out_fds[ out_cnt++ ] = tile->txproc.swaplog_fd;
  return out_cnt;
}

static void
privileged_init( fd_topo_t *      topo  FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile ) {
  FD_LOG_NOTICE(( "txlog: opening log file `%s`", tile->txproc.log_path ));
  tile->txproc.logfile_fd = open( tile->txproc.log_path, O_WRONLY|O_CREAT|O_APPEND, 0644 );
  if( FD_UNLIKELY( tile->txproc.logfile_fd<0 ) )
    FD_LOG_ERR(( "open(%s) failed (%d-%s)", tile->txproc.log_path, errno, fd_io_strerror( errno ) ));
  FD_LOG_NOTICE(( "txlog: log file opened (fd=%d)", tile->txproc.logfile_fd ));

  if( FD_LIKELY( tile->txproc.swap_log_path[0] ) ) {
    FD_LOG_NOTICE(( "txlog: opening swap log file `%s`", tile->txproc.swap_log_path ));
    tile->txproc.swaplog_fd = open( tile->txproc.swap_log_path, O_WRONLY|O_CREAT|O_APPEND, 0644 );
    if( FD_UNLIKELY( tile->txproc.swaplog_fd<0 ) )
      FD_LOG_ERR(( "open(%s) failed (%d-%s)", tile->txproc.swap_log_path, errno, fd_io_strerror( errno ) ));
    FD_LOG_NOTICE(( "txlog: swap log file opened (fd=%d)", tile->txproc.swaplog_fd ));
  } else {
    tile->txproc.swaplog_fd = -1;
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_txlog_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txlog_ctx_t), sizeof(fd_txlog_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];
    ctx->in[ i ].mem    = wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  ctx->logfile_fd     = tile->txproc.logfile_fd;
  ctx->swaplog_fd     = tile->txproc.swaplog_fd;
  ctx->entry_batch_sz = 0UL;
  ctx->slot           = 0UL;
  ctx->fec_set_idx    = 0U;
  fd_memset( ctx->dedup_cache, 0, sizeof(ctx->dedup_cache) );
  ctx->dedup_head     = 0UL;

  if( FD_UNLIKELY( !fd_io_buffered_ostream_init( &ctx->ostream, ctx->logfile_fd,
                                                  ctx->write_buf, FD_TXLOG_WRITER_BUF_SZ ) ) )
    FD_LOG_ERR(( "fd_io_buffered_ostream_init failed" ));

  /* Decode known DEX program IDs from base58 */
  for( ulong k=0UL; k<FD_TXLOG_KNOWN_PROG_CNT; k++ ) {
    if( FD_UNLIKELY( !fd_base58_decode_32( fd_txlog_known_prog_b58[ k ], ctx->known_prog_ids[ k ] ) ) )
      FD_LOG_ERR(( "txlog: failed to decode known program ID %s", fd_txlog_known_prog_b58[ k ] ));
  }

  FD_LOG_NOTICE(( "txlog: tile initialized, writing CSV to fd=%d", ctx->logfile_fd ));

  /* Write CSV header */
  static const char hdr[] = "timestamp_ns,slot,poh_hash,txn_sig,acct_cnt,program_ids,dex_programs\n";
  int err = fd_io_buffered_ostream_write( &ctx->ostream, hdr, sizeof(hdr)-1UL );
  if( FD_UNLIKELY( err ) )
    FD_LOG_ERR(( "fd_io_buffered_ostream_write header failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_LIKELY( ctx->swaplog_fd!=-1 ) ) {
    if( FD_UNLIKELY( !fd_io_buffered_ostream_init( &ctx->swap_ostream, ctx->swaplog_fd,
                                                    ctx->swap_write_buf, FD_TXLOG_WRITER_BUF_SZ ) ) )
      FD_LOG_ERR(( "fd_io_buffered_ostream_init swaplog failed" ));

    static const char swap_hdr[] = "timestamp_ns,slot,txn_sig,fee_payer,dex_programs,program_ids\n";
    int swap_err = fd_io_buffered_ostream_write( &ctx->swap_ostream, swap_hdr, sizeof(swap_hdr)-1UL );
    if( FD_UNLIKELY( swap_err ) )
      FD_LOG_ERR(( "fd_io_buffered_ostream_write swaplog header failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    FD_LOG_NOTICE(( "txlog: swap log initialized, writing CSV to fd=%d", ctx->swaplog_fd ));
  }
}

static inline void
during_frag( fd_txlog_ctx_t * ctx,
             ulong            in_idx,
             ulong            seq    FD_PARAM_UNUSED,
             ulong            sig,
             ulong            chunk,
             ulong            sz,
             ulong            ctl    FD_PARAM_UNUSED ) {
  uchar const * src = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
  ulong copy_sz = fd_ulong_min( sz, FD_TXLOG_ENTRY_BATCH_MAX );
  if( FD_UNLIKELY( sz > FD_TXLOG_ENTRY_BATCH_MAX ) ) ctx->metrics.entry_batches_truncated++;
  fd_memcpy( ctx->entry_batch, src, copy_sz );
  ctx->entry_batch_sz = copy_sz;
  /* sig encodes (slot<<16)|fec_set_idx — decode both fields */
  ctx->slot        = sig >> 16;
  ctx->fec_set_idx = (uint)(sig & 0xFFFFUL);
}

static inline void
after_frag( fd_txlog_ctx_t *    ctx,
            ulong               in_idx   FD_PARAM_UNUSED,
            ulong               seq      FD_PARAM_UNUSED,
            ulong               sig      FD_PARAM_UNUSED,
            ulong               sz       FD_PARAM_UNUSED,
            ulong               tsorig   FD_PARAM_UNUSED,
            ulong               tspub    FD_PARAM_UNUSED,
            fd_stem_context_t * stem     FD_PARAM_UNUSED ) {
  ulong  slot = ctx->slot;
  uchar * cur = ctx->entry_batch;
  uchar * end = cur + ctx->entry_batch_sz;

  /* Deduplicate: skip this FEC set if already processed (can arrive from
     multiple shred tiles when multicast is enabled). */
  ulong dedup_key = (slot << 16UL) | (ulong)ctx->fec_set_idx;
  for( ulong i=0UL; i<FD_TXLOG_DEDUP_CACHE_SZ; i++ ) {
    if( FD_UNLIKELY( ctx->dedup_cache[ i ]==dedup_key ) ) {
      ctx->metrics.dedup_skipped++;
      return;
    }
  }
  ctx->dedup_cache[ ctx->dedup_head % FD_TXLOG_DEDUP_CACHE_SZ ] = dedup_key;
  ctx->dedup_head++;

  /* Skip the ulong microblock_cnt prefix that precedes the concatenated
     fd_entry_batch_header_t + transaction payload bytes. */
  if( FD_UNLIKELY( cur + sizeof(ulong) > end ) ) return;
  cur += sizeof(ulong);

  while( cur + sizeof(fd_entry_batch_header_t) <= end ) {
    fd_entry_batch_header_t const * hdr = (fd_entry_batch_header_t const *)fd_type_pun_const( cur );
    cur += sizeof(fd_entry_batch_header_t);

    /* PoH hash in base58 */
    FD_BASE58_ENCODE_32_BYTES( hdr->hash, poh_b58 );
    poh_b58[ poh_b58_len ] = '\0';

    for( ulong t=0UL; t<hdr->txn_cnt; t++ ) {
      ulong remain = (ulong)(end - cur);
      if( FD_UNLIKELY( remain==0UL ) ) break;

      /* Parse this transaction; payload_consumed gets the wire size */
      uchar txn_buf[ FD_TXN_MAX_SZ ] __attribute__((aligned(8)));
      ulong payload_consumed = 0UL;
      ulong txn_sz = fd_txn_parse_core( cur, remain, txn_buf, NULL, &payload_consumed );
      if( FD_UNLIKELY( !txn_sz || !payload_consumed ) ) {
        ctx->metrics.parse_errors++;
        cur = end; /* abort remaining entry batches — data is corrupt */
        break;
      }

      fd_txn_t const * txn = (fd_txn_t const *)fd_type_pun_const( txn_buf );
      ctx->metrics.transactions_received++;

      /* First signature base58 */
      FD_BASE58_ENCODE_64_BYTES( cur + txn->signature_off, sig_b58 );
      sig_b58[ sig_b58_len ] = '\0';

      /* Account address base pointer */
      fd_acct_addr_t const * accts = fd_txn_get_acct_addrs( txn, cur );

      /* Skip vote transactions */
      int is_vote = 0;
      for( ushort i=0; i<txn->instr_cnt; i++ ) {
        uchar prog_idx = txn->instr[ i ].program_id;
        if( FD_UNLIKELY( prog_idx < txn->acct_addr_cnt &&
                         !memcmp( accts[ prog_idx ].b, fd_solana_vote_program_id.uc, 32UL ) ) ) {
          is_vote = 1;
          break;
        }
      }
      if( FD_UNLIKELY( is_vote ) ) {
        ctx->metrics.votes_skipped++;
        cur += payload_consumed;
        continue;
      }

      /* Collect unique program IDs from all instructions; classify known DEX programs */
      char  prog_buf[ FD_BASE58_ENCODED_32_SZ * 64UL + 64UL ];
      ulong prog_pos = 0UL;
      char  dex_buf[ 256 ];
      ulong dex_pos = 0UL;
      uchar seen[ 256 ];
      fd_memset( seen, 0, sizeof(seen) );

      for( ushort i=0; i<txn->instr_cnt; i++ ) {
        uchar prog_idx = txn->instr[ i ].program_id;
        if( FD_LIKELY( !seen[ prog_idx ] && prog_idx < txn->acct_addr_cnt ) ) {
          seen[ prog_idx ] = 1;
          if( prog_pos > 0UL && prog_pos < sizeof(prog_buf)-1UL )
            prog_buf[ prog_pos++ ] = '|';
          char  p58[ FD_BASE58_ENCODED_32_SZ ];
          ulong p58_len;
          fd_base58_encode_32( accts[ prog_idx ].b, &p58_len, p58 );
          if( FD_LIKELY( prog_pos + p58_len < sizeof(prog_buf)-1UL ) ) {
            fd_memcpy( prog_buf + prog_pos, p58, p58_len );
            prog_pos += p58_len;
          }
          /* Check against known DEX program IDs */
          for( ulong k=0UL; k<FD_TXLOG_KNOWN_PROG_CNT; k++ ) {
            if( FD_UNLIKELY( !memcmp( accts[ prog_idx ].b, ctx->known_prog_ids[ k ], 32UL ) ) ) {
              ulong name_len = strlen( fd_txlog_known_prog_names[ k ] );
              if( dex_pos > 0UL && dex_pos < sizeof(dex_buf)-1UL )
                dex_buf[ dex_pos++ ] = '|';
              if( FD_LIKELY( dex_pos + name_len < sizeof(dex_buf)-1UL ) ) {
                fd_memcpy( dex_buf + dex_pos, fd_txlog_known_prog_names[ k ], name_len );
                dex_pos += name_len;
              }
              break;
            }
          }
        }
      }
      prog_buf[ prog_pos ] = '\0';
      dex_buf [ dex_pos  ] = '\0';

      /* fee_payer = first account (accts[0]) */
      char  fp_b58[ FD_BASE58_ENCODED_32_SZ ];
      ulong fp_b58_len;
      fd_base58_encode_32( accts[0].b, &fp_b58_len, fp_b58 );
      fp_b58[ fp_b58_len ] = '\0';

      /* Format and write CSV line */
      char line[ 4096 ];
      int  len = snprintf( line, sizeof(line),
                           "%ld,%lu,%s,%s,%u,%s,%s\n",
                           fd_log_wallclock(),
                           slot,
                           poh_b58,
                           sig_b58,
                           (uint)txn->acct_addr_cnt,
                           prog_buf,
                           dex_buf );
      if( FD_LIKELY( len>0 && (ulong)len<sizeof(line) ) ) {
        int err = fd_io_buffered_ostream_write( &ctx->ostream, line, (ulong)len );
        if( FD_UNLIKELY( err ) ) {
          FD_LOG_WARNING(( "fd_io_buffered_ostream_write failed (%i-%s)", errno, fd_io_strerror( errno ) ));
          ctx->metrics.write_errors++;
        } else {
          ctx->metrics.transactions_logged++;
        }
      }

      /* Write to swaplog if this transaction touches a known DEX program */
      if( FD_UNLIKELY( dex_pos>0UL ) ) ctx->metrics.dex_transactions_logged++;
      if( FD_UNLIKELY( dex_pos>0UL && ctx->swaplog_fd!=-1 ) ) {
        char swap_line[ 4096 ];
        int  swap_len = snprintf( swap_line, sizeof(swap_line),
                                  "%ld,%lu,%s,%s,%s,%s\n",
                                  fd_log_wallclock(),
                                  slot,
                                  sig_b58,
                                  fp_b58,
                                  dex_buf,
                                  prog_buf );
        if( FD_LIKELY( swap_len>0 && (ulong)swap_len<sizeof(swap_line) ) ) {
          int swap_err = fd_io_buffered_ostream_write( &ctx->swap_ostream, swap_line, (ulong)swap_len );
          if( FD_UNLIKELY( swap_err ) )
            FD_LOG_WARNING(( "fd_io_buffered_ostream_write swaplog failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        }
      }

      cur += payload_consumed;
    }
  }

  ctx->metrics.shredded_batches_received++;
}

static inline void
metrics_write( fd_txlog_ctx_t * ctx ) {
  FD_MCNT_SET( TXPROC, SHREDDED_BATCHES_RECEIVED,  ctx->metrics.shredded_batches_received  );
  FD_MCNT_SET( TXPROC, DEDUP_SKIPPED,               ctx->metrics.dedup_skipped               );
  FD_MCNT_SET( TXPROC, TRANSACTIONS_RECEIVED,       ctx->metrics.transactions_received       );
  FD_MCNT_SET( TXPROC, TRANSACTIONS_LOGGED,         ctx->metrics.transactions_logged         );
  FD_MCNT_SET( TXPROC, VOTES_SKIPPED,               ctx->metrics.votes_skipped               );
  FD_MCNT_SET( TXPROC, PARSE_ERRORS,                ctx->metrics.parse_errors                );
  FD_MCNT_SET( TXPROC, DEX_TRANSACTIONS_LOGGED,     ctx->metrics.dex_transactions_logged     );
  FD_MCNT_SET( TXPROC, WRITE_ERRORS,                ctx->metrics.write_errors                );
  FD_MCNT_SET( TXPROC, ENTRY_BATCHES_TRUNCATED,     ctx->metrics.entry_batches_truncated     );
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_txlog_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_txlog_ctx_t)
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag
#define STEM_CALLBACK_METRICS_WRITE metrics_write

/* txlog has no outputs, so cr_max defaults to 128 and lazy defaults to
   289ns — far too frequent for a logging tile.  Match the convention
   used by other sink tiles (bank, store, poh). */
#define STEM_LAZY (128L*3000L)

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_txproc = {
  .name                     = "txproc",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
