#include "../shared/fd_config.h"

#include "../../ballet/shred/fd_shred.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/quic/fd_tpu.h"
#include "../../disco/tiles.h"
#include "../../disco/topo/fd_topob.h"
#include "../../disco/topo/fd_cpu_topo.h"
#include "../../disco/plugin/fd_plugin.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/tile/fd_tile_private.h"
#include "../../discof/gossip/fd_gossip_tile.h"

#include <netdb.h>
#include <netinet/in.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];

static int
resolve_address( char const * address,
                 uint       * ip_addr ) {
  struct addrinfo hints = { .ai_family = AF_INET };
  struct addrinfo * res;
  int err = getaddrinfo( address, NULL, &hints, &res );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "cannot resolve address \"%s\": %i-%s", address, err, gai_strerror( err ) ));
    return 0;
  }

  int resolved = 0;
  for( struct addrinfo * cur=res; cur; cur=cur->ai_next ) {
    if( FD_UNLIKELY( cur->ai_addr->sa_family!=AF_INET ) ) continue;
    struct sockaddr_in const * addr = (struct sockaddr_in const *)cur->ai_addr;
    *ip_addr = addr->sin_addr.s_addr;
    resolved = 1;
    break;
  }

  freeaddrinfo( res );
  return resolved;
}

static int
resolve_peer( char const *    peer,
              fd_ip4_port_t * ip4_port ) {
  char const * host_port = peer;
  if( FD_LIKELY( strncmp( peer, "http://", 7UL )==0 ) ) {
    host_port += 7UL;
  } else if( FD_LIKELY( strncmp( peer, "https://", 8UL )==0 ) ) {
    host_port += 8UL;
  }

  char const * colon = strrchr( host_port, ':' );
  if( FD_UNLIKELY( !colon ) )
    FD_LOG_ERR(( "invalid [gossip.entrypoints] entry \"%s\": no port number", host_port ));

  char fqdn[ 255 ];
  ulong fqdn_len = (ulong)( colon-host_port );
  if( FD_UNLIKELY( fqdn_len>254 ) )
    FD_LOG_ERR(( "invalid [gossip.entrypoints] entry \"%s\": hostname too long", host_port ));
  fd_memcpy( fqdn, host_port, fqdn_len );
  fqdn[ fqdn_len ] = '\0';

  char const * port_str = colon+1;
  char const * endptr   = NULL;
  ulong port = strtoul( port_str, (char **)&endptr, 10 );
  if( FD_UNLIKELY( !endptr || !port || port>USHORT_MAX || *endptr!='\0' ) )
    FD_LOG_ERR(( "invalid [gossip.entrypoints] entry \"%s\": invalid port number", host_port ));
  ip4_port->port = (ushort)fd_ushort_bswap( (ushort)port );

  int resolved = resolve_address( fqdn, &ip4_port->addr );
  return resolved;
}

static void
resolve_gossip_entrypoints( config_t * config ) {
  ulong entrypoint_cnt = config->gossip.entrypoints_cnt;
  for( ulong i=0UL; i<entrypoint_cnt; i++ ) {
    if( FD_UNLIKELY( 0==resolve_peer( config->gossip.entrypoints[ i ], &config->gossip.resolved_entrypoints[ i ] ) ) )
      FD_LOG_ERR(( "failed to resolve address of [gossip.entrypoints] entry \"%s\"", config->gossip.entrypoints[ i ] ));
  }
}

static void
parse_ip_port( const char * name, const char * ip_port, fd_topo_ip_port_t *parsed_ip_port) {
  char buf[ sizeof( "255.255.255.255:65536" ) ];
  memcpy( buf, ip_port, sizeof( buf ) );
  char *ip_end = strchr( buf, ':' );
  if( FD_UNLIKELY( !ip_end ) )
    FD_LOG_ERR(( "[%s] must in the form ip:port", name ));
  *ip_end = '\0';

  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( buf, &( parsed_ip_port->ip ) ) ) ) {
    FD_LOG_ERR(( "could not parse IP %s in [%s]", buf, name ));
  }

  parsed_ip_port->port = fd_cstr_to_ushort( ip_end+1 );
  if( FD_UNLIKELY( !parsed_ip_port->port ) )
    FD_LOG_ERR(( "could not parse port %s in [%s]", ip_end+1, name ));
}

void
fd_topo_configure_tile( fd_topo_tile_t * tile,
                        fd_config_t *    config );

void
fd_topo_initialize( config_t * config ) {
  ulong net_tile_cnt    = config->layout.net_tile_count;
  ulong quic_tile_cnt   = config->layout.quic_tile_count;
  ulong verify_tile_cnt = config->layout.verify_tile_count;
  ulong resolv_tile_cnt = config->layout.resolv_tile_count;
  ulong bank_tile_cnt   = config->layout.bank_tile_count;
  ulong shred_tile_cnt  = config->layout.shred_tile_count;

  /* In shred_relay mode the TPU pipeline (quic, verify, dedup, resolv,
     pack, bank, poh/Agave, store) is omitted entirely.  Only net, shred,
     sign, smcast, metric, cswtch, and gui tiles are kept.  shred_store is
     retained with a small depth so the shred tile can use its dcache for
     FEC set memory (required by Frankendancer shred tile). */
  int relay = !strcmp( config->layout.mode, "shred_relay" );

  /* In relay mode, add Firedancer gossip tiles (gossip, gossvf, ipecho)
     so the network knows this validator's TVU port and can send shreds. */
  ulong gossvf_tile_cnt = FD_UNLIKELY( relay ) ? 1UL : 0UL;

  if( FD_UNLIKELY( relay ) ) resolve_gossip_entrypoints( config );

  fd_topo_t * topo = { fd_topob_new( &config->topo, config->name ) };
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->gigantic_page_threshold = config->hugetlbfs.gigantic_page_threshold_mib << 20;

  /*             topo, name */
  fd_topob_wksp( topo, "metric_in"    );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "net_quic"     );
  fd_topob_wksp( topo, "net_shred"    );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "quic_verify"  );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "verify_dedup" );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "dedup_resolv" );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "resolv_pack"  );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "pack_bank"    );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "pack_poh"     );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "bank_pack"    );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "bank_poh"     );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "bank_busy"    );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "poh_shred"    );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "gossip_dedup" );
  fd_topob_wksp( topo, "shred_store"  );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "stake_out"    );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "executed_txn" );

  fd_topob_wksp( topo, "shred_sign"   );
  fd_topob_wksp( topo, "sign_shred"   );

  if( FD_UNLIKELY( relay ) ) {
    fd_topob_wksp( topo, "ipecho"       );
    fd_topob_wksp( topo, "gossvf"       );
    fd_topob_wksp( topo, "gossip"       );
    fd_topob_wksp( topo, "net_gossip"   );
    fd_topob_wksp( topo, "ipecho_out"   );
    fd_topob_wksp( topo, "gossvf_gossi" );
    fd_topob_wksp( topo, "gossip_gossv" );
    fd_topob_wksp( topo, "gossip_out"   );
    fd_topob_wksp( topo, "gossip_sign"  );
    fd_topob_wksp( topo, "sign_gossip"  );
  }

  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "quic"    );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "verify"  );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "dedup"        );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "resolv"       );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "pack"         );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "bank"         );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "poh"          );
  fd_topob_wksp( topo, "shred"        );
  if( FD_LIKELY( !relay ) ) fd_topob_wksp( topo, "store"        );
  fd_topob_wksp( topo, "sign"         );
  fd_topob_wksp( topo, "metric"       );
  fd_topob_wksp( topo, "cswtch"       );

  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  /*                                  topo, link_name,      wksp_name,      depth,                                    mtu,                    burst */
  if( FD_LIKELY( !relay ) ) FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_net",     "net_quic",     config->net.ingress_buffer_size,          FD_NET_MTU,             1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_net",    "net_shred",    32768UL,                                  FD_NET_MTU,             1UL );
  if( FD_LIKELY( !relay ) ) FOR(quic_tile_cnt)   fd_topob_link( topo, "quic_verify",  "quic_verify",  config->tiles.verify.receive_buffer_size, FD_TPU_REASM_MTU,       config->tiles.quic.txn_reassembly_count );
  if( FD_LIKELY( !relay ) ) FOR(verify_tile_cnt) fd_topob_link( topo, "verify_dedup", "verify_dedup", config->tiles.verify.receive_buffer_size, FD_TPU_PARSED_MTU,      1UL );
  if( FD_LIKELY( !relay ) ) fd_topob_link( topo, "gossip_dedup", "gossip_dedup", 2048UL,                                   FD_TPU_RAW_MTU,         1UL );
  /* dedup_resolv is large currently because pack can encounter stalls when running at very high throughput rates that would
     otherwise cause drops. */
  if( FD_LIKELY( !relay ) ) fd_topob_link( topo, "dedup_resolv", "dedup_resolv", 65536UL,                                  FD_TPU_PARSED_MTU,      1UL );
  if( FD_LIKELY( !relay ) ) FOR(resolv_tile_cnt) fd_topob_link( topo, "resolv_pack",  "resolv_pack",  65536UL,              FD_TPU_RESOLVED_MTU,    1UL );
  if( FD_LIKELY( !relay ) ) fd_topob_link( topo, "stake_out",    "stake_out",    128UL,                                    FD_STAKE_OUT_MTU,       1UL );
  /* pack_bank is shared across all banks, so if one bank stalls due to complex transactions, the buffer neeeds to be large so that
     other banks can keep proceeding. */
  if( FD_LIKELY( !relay ) ) fd_topob_link( topo, "pack_bank",    "pack_bank",    65536UL,                                  USHORT_MAX,             1UL );
  if( FD_LIKELY( !relay ) ) fd_topob_link( topo, "pack_poh",     "pack_poh",     65536UL,                                  sizeof(fd_done_packing_t), 1UL );
  if( FD_LIKELY( !relay ) ) FOR(bank_tile_cnt) fd_topob_link( topo, "bank_poh",   "bank_poh",     16384UL,                  USHORT_MAX,             1UL );
  if( FD_LIKELY( !relay ) ) FOR(bank_tile_cnt) fd_topob_link( topo, "bank_pack",  "bank_pack",    16384UL,                  USHORT_MAX,             3UL );
  if( FD_LIKELY( !relay ) ) fd_topob_link( topo, "poh_pack",     "bank_poh",     128UL,                                    sizeof(fd_became_leader_t), 1UL );
  if( FD_LIKELY( !relay ) ) fd_topob_link( topo, "poh_shred",    "poh_shred",    16384UL,                                  USHORT_MAX,             2UL );
  if( FD_LIKELY( !relay ) ) fd_topob_link( topo, "crds_shred",   "poh_shred",    128UL,                                    8UL  + 40200UL * 46UL,  1UL );
  if( FD_LIKELY( !relay ) ) fd_topob_link( topo, "replay_resol", "bank_poh",     128UL,                                    sizeof(fd_completed_bank_t), 1UL );
  if( FD_LIKELY( !relay ) ) fd_topob_link( topo, "executed_txn", "executed_txn", 16384UL,                                  64UL, 1UL );
  /* See long comment in fd_shred.c for an explanation about the size of this dcache. */
  if( FD_LIKELY( !relay ) )
    FOR(shred_tile_cnt) fd_topob_link( topo, "shred_store", "shred_store", 65536UL, 4UL*FD_SHRED_STORE_MTU, 4UL+config->tiles.shred.max_pending_shred_sets );
  else
    FOR(shred_tile_cnt) fd_topob_link( topo, "shred_store", "shred_store", 128UL,   4UL*FD_SHRED_STORE_MTU, 4UL+config->tiles.shred.max_pending_shred_sets )->permit_no_consumers = 1;

  FOR(shred_tile_cnt)  fd_topob_link( topo, "shred_sign",   "shred_sign",   128UL,                                    32UL,                   1UL );
  FOR(shred_tile_cnt)  fd_topob_link( topo, "sign_shred",   "sign_shred",   128UL,                                    64UL,                   1UL );

  if( FD_UNLIKELY( relay ) ) {
    /**/                 fd_topob_link( topo, "gossip_net",   "net_gossip",   32768UL,                                  FD_NET_MTU,                          1UL );
    /**/                 fd_topob_link( topo, "ipecho_out",   "ipecho_out",   2UL,                                      0UL,                                 1UL );
    FOR(gossvf_tile_cnt) fd_topob_link( topo, "gossvf_gossi", "gossvf_gossi", config->net.ingress_buffer_size,          sizeof(fd_gossip_view_t)+FD_NET_MTU, 1UL );
    /**/                 fd_topob_link( topo, "gossip_gossv", "gossip_gossv", 65536UL*4UL,                              sizeof(fd_gossip_ping_update_t),     1UL );
    /**/                 fd_topob_link( topo, "gossip_out",   "gossip_out",   65536UL*4UL,                              sizeof(fd_gossip_update_message_t),  1UL );
    /**/                 fd_topob_link( topo, "gossip_sign",  "gossip_sign",  128UL,                                    2048UL,                              1UL );
    /**/                 fd_topob_link( topo, "sign_gossip",  "sign_gossip",  128UL,                                    sizeof(fd_ed25519_sig_t),            1UL );
  }

  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  /* Unassigned tiles will be floating, unless auto topology is enabled. */
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;

  int is_auto_affinity = !strcmp( config->layout.affinity, "auto" );
  int is_agave_auto_affinity = !strcmp( config->frankendancer.layout.agave_affinity, "auto" );

  if( FD_UNLIKELY( is_auto_affinity != is_agave_auto_affinity ) ) {
    FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.affinity] and [layout.agave_affinity] must both be set to 'auto' or both be set to a specific CPU affinity string." ));
  }

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  ulong affinity_tile_cnt = 0UL;
  if( FD_LIKELY( !is_auto_affinity ) ) affinity_tile_cnt = fd_tile_private_cpus_parse( config->layout.affinity, parsed_tile_to_cpu );

  ulong tile_to_cpu[ FD_TILE_MAX ] = {0};
  for( ulong i=0UL; i<affinity_tile_cnt; i++ ) {
    if( FD_UNLIKELY( parsed_tile_to_cpu[ i ]!=USHORT_MAX && parsed_tile_to_cpu[ i ]>=cpus->cpu_cnt ) )
      FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.affinity] specifies a CPU index of %hu, but the system "
                   "only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                   "in the system.",
                   parsed_tile_to_cpu[ i ], cpus->cpu_cnt ));
    tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==USHORT_MAX, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }

  fd_topos_net_tiles( topo, config->layout.net_tile_count, &config->net, config->tiles.netlink.max_routes, config->tiles.netlink.max_peer_routes, config->tiles.netlink.max_neighbors, tile_to_cpu );

  if( FD_LIKELY( !relay ) ) FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_quic",  i, config->net.ingress_buffer_size );
  FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_shred", i, config->net.ingress_buffer_size );
  if( FD_UNLIKELY( relay ) ) FOR(net_tile_cnt) fd_topos_net_rx_link( topo, "net_gossvf", i, config->net.ingress_buffer_size );

  /*                                  topo, tile_name, tile_wksp, metrics_wksp, cpu_idx,                       is_agave, uses_keyswitch */
  if( FD_LIKELY( !relay ) ) FOR(quic_tile_cnt)   fd_topob_tile( topo, "quic",   "quic",   "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
  if( FD_LIKELY( !relay ) ) FOR(verify_tile_cnt) fd_topob_tile( topo, "verify", "verify", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
  if( FD_LIKELY( !relay ) ) fd_topob_tile( topo, "dedup",   "dedup",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  if( FD_LIKELY( !relay ) ) FOR(resolv_tile_cnt) fd_topob_tile( topo, "resolv",  "resolv",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 1,        0 );
  if( FD_LIKELY( !relay ) ) fd_topob_tile( topo, "pack",    "pack",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        config->tiles.bundle.enabled );
  if( FD_LIKELY( !relay ) ) FOR(bank_tile_cnt)   fd_topob_tile( topo, "bank",    "bank",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 1,        0 );
  if( FD_LIKELY( !relay ) ) fd_topob_tile( topo, "poh",     "poh",     "metric_in",  tile_to_cpu[ topo->tile_cnt ], 1,        1 );
  FOR(shred_tile_cnt)        fd_topob_tile( topo, "shred",   "shred",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  if( FD_LIKELY( !relay ) ) fd_topob_tile( topo, "store",   "store",   "metric_in",  tile_to_cpu[ topo->tile_cnt ], 1,        0 );
  /**/                 fd_topob_tile( topo, "sign",    "sign",    "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  if( FD_UNLIKELY( relay ) ) {
    /**/               fd_topob_tile( topo, "ipecho",  "ipecho",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
    FOR(gossvf_tile_cnt) fd_topob_tile( topo, "gossvf", "gossvf", "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
    /**/               fd_topob_tile( topo, "gossip",  "gossip",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        1 );
  }
  /**/                 fd_topob_tile( topo, "metric",  "metric",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );
  /**/                 fd_topob_tile( topo, "cswtch",  "cswtch",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0,        0 );

  /*                                      topo, tile_name, tile_kind_id, fseq_wksp,   link_name,      link_kind_id, reliable,            polled */
  if( FD_LIKELY( !relay ) )
    for( ulong j=0UL; j<quic_tile_cnt; j++ )
                   fd_topos_tile_in_net(  topo,                          "metric_in", "quic_net",     j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  for( ulong j=0UL; j<shred_tile_cnt; j++ )
                   fd_topos_tile_in_net(  topo,                          "metric_in", "shred_net",    j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */

  if( FD_LIKELY( !relay ) ) {
    FOR(quic_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                         fd_topob_tile_in(  topo, "quic",    i,            "metric_in", "net_quic",     j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
    FOR(quic_tile_cnt)   fd_topob_tile_out( topo, "quic",    i,                         "quic_verify",  i                                                  );
    FOR(quic_tile_cnt)   fd_topob_tile_out( topo, "quic",    i,                         "quic_net",     i                                                  );
    /* All verify tiles read from all QUIC tiles, packets are round robin. */
    FOR(verify_tile_cnt) for( ulong j=0UL; j<quic_tile_cnt; j++ )
                         fd_topob_tile_in(  topo, "verify",  i,            "metric_in", "quic_verify",  j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers, verify tiles may be overrun */
    FOR(verify_tile_cnt) fd_topob_tile_out( topo, "verify",  i,                         "verify_dedup", i                                                  );
  }
  if( FD_LIKELY( !relay ) ) {
    /* Declare the single gossip link before the variable length verify-dedup links so we could have a compile-time index to the gossip link. */
    /**/                 fd_topob_tile_in(  topo, "dedup",   0UL,          "metric_in", "gossip_dedup", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    FOR(verify_tile_cnt) fd_topob_tile_in(  topo, "dedup",   0UL,          "metric_in", "verify_dedup", i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "dedup",   0UL,          "metric_in", "executed_txn", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_out( topo, "dedup",   0UL,                       "dedup_resolv", 0UL                                                );
    FOR(resolv_tile_cnt) fd_topob_tile_in(  topo, "resolv",  i,            "metric_in", "dedup_resolv", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    FOR(resolv_tile_cnt) fd_topob_tile_in(  topo, "resolv",  i,            "metric_in", "replay_resol", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    FOR(resolv_tile_cnt) fd_topob_tile_out( topo, "resolv",  i,                         "resolv_pack",  i                                                  );
    /**/                 fd_topob_tile_in(  topo, "pack",    0UL,          "metric_in", "resolv_pack",  0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /* The PoH to pack link is reliable, and must be.  The fragments going
       across here are "you became leader" which pack must respond to
       by publishing microblocks, otherwise the leader TPU will hang
       forever.

       It's marked as unreliable since otherwise we have a reliable credit
       loop which will also starve the pack tile.  This is OK because we
       will never send more than one leader message until the pack tile
       must acknowledge it with a packing done frag, so there will be at
       most one in flight at any time. */
    /**/                 fd_topob_tile_in(  topo, "pack",   0UL,           "metric_in", "poh_pack",     0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "pack",   0UL,           "metric_in", "executed_txn", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
                         fd_topob_tile_out( topo, "pack",   0UL,                        "pack_bank",    0UL                                                );
                         fd_topob_tile_out( topo, "pack",   0UL,                        "pack_poh",     0UL                                                );
    FOR(bank_tile_cnt)   fd_topob_tile_in(  topo, "bank",   i,             "metric_in", "pack_bank",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    FOR(bank_tile_cnt)   fd_topob_tile_out( topo, "bank",   i,                          "bank_poh",     i                                                  );
    FOR(bank_tile_cnt)   fd_topob_tile_out( topo, "bank",   i,                          "bank_pack",    i                                                  );
    FOR(bank_tile_cnt)   fd_topob_tile_in(  topo, "poh",    0UL,           "metric_in", "bank_poh",     i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    if( FD_LIKELY( config->tiles.pack.use_consumed_cus ) )
      FOR(bank_tile_cnt) fd_topob_tile_in(  topo, "pack",   0UL,           "metric_in", "bank_pack",    i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "poh",    0UL,           "metric_in", "stake_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "poh",    0UL,           "metric_in", "pack_poh",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "poh_shred",    0UL                                                );
    /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "poh_pack",     0UL                                                );
  }
  FOR(shred_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                       fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "net_shred",    j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
  if( FD_LIKELY( !relay ) ) {
    FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "poh_shred",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "stake_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "crds_shred",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }
  FOR(shred_tile_cnt)  fd_topob_tile_out( topo, "shred",  i,                          "shred_store",  i                                                  );
  FOR(shred_tile_cnt)  fd_topob_tile_out( topo, "shred",  i,                          "shred_net",    i                                                  );
  if( FD_LIKELY( !relay ) )
    FOR(shred_tile_cnt)  fd_topob_tile_in(  topo, "store",  0UL,           "metric_in", "shred_store",  i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

  /* Sign links don't need to be reliable because they are synchronous,
     so there's at most one fragment in flight at a time anyway.  The
     sign links are also not polled by fd_stem, instead the tiles will
     read the sign responses out of band in a dedicated spin loop. */

  for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
    /**/               fd_topob_tile_in(  topo, "sign",   0UL,           "metric_in", "shred_sign",     i,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/               fd_topob_tile_out( topo, "shred",  i,                          "shred_sign",     i                                                  );
    /**/               fd_topob_tile_in(  topo, "shred",  i,             "metric_in", "sign_shred",     i,          FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
    /**/               fd_topob_tile_out( topo, "sign",   0UL,                        "sign_shred",     i                                                  );
  }

  if( FD_LIKELY( !relay ) ) {
    /* PoH tile represents the Agave address space, so it's
       responsible for publishing Agave provided data to
       these links. */
    /**/               fd_topob_tile_out( topo, "poh",    0UL,                        "gossip_dedup", 0UL                                                  );
    /**/               fd_topob_tile_out( topo, "poh",    0UL,                        "stake_out",    0UL                                                  );
    /**/               fd_topob_tile_out( topo, "poh",    0UL,                        "crds_shred",   0UL                                                  );
    /**/               fd_topob_tile_out( topo, "poh",    0UL,                        "replay_resol", 0UL                                                  );
    /**/               fd_topob_tile_out( topo, "poh",    0UL,                        "executed_txn", 0UL                                                  );
  }

  if( FD_UNLIKELY( relay ) ) {
    /* ipecho: no inputs (contacts entrypoints directly); outputs shred_version to downstream tiles */
    /**/                 fd_topob_tile_out(   topo, "ipecho", 0UL,                        "ipecho_out",   0UL                                                );

    /* gossvf: reads gossip UDP from net, plus feedback from gossip tile and ipecho */
    FOR(gossvf_tile_cnt) for( ulong j=0UL; j<net_tile_cnt; j++ )
                         fd_topob_tile_in(    topo, "gossvf", i,            "metric_in", "net_gossvf",   j,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */
    FOR(gossvf_tile_cnt) fd_topob_tile_out(   topo, "gossvf", i,                         "gossvf_gossi", i                                                  );
    FOR(gossvf_tile_cnt) fd_topob_tile_in(    topo, "gossvf", i,            "metric_in", "gossip_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    FOR(gossvf_tile_cnt) fd_topob_tile_in(    topo, "gossvf", i,            "metric_in", "gossip_gossv", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    FOR(gossvf_tile_cnt) fd_topob_tile_in(    topo, "gossvf", i,            "metric_in", "ipecho_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

    /* gossip: reads verified gossip from gossvf, shred_version from ipecho, signatures from sign */
    /**/                 fd_topob_tile_out(   topo, "gossip", 0UL,                        "gossip_out",   0UL                                                );
    /**/                 fd_topob_tile_out(   topo, "gossip", 0UL,                        "gossip_net",   0UL                                                );
    /**/                 fd_topob_tile_out(   topo, "gossip", 0UL,                        "gossip_gossv", 0UL                                                );
    /**/                 fd_topob_tile_in(    topo, "gossip", 0UL,           "metric_in", "ipecho_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    FOR(gossvf_tile_cnt) fd_topob_tile_in(    topo, "gossip", 0UL,           "metric_in", "gossvf_gossi", i,            FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

    /* gossip <-> sign (signing gossip messages) */
    /**/                 fd_topob_tile_in(    topo, "sign",   0UL,           "metric_in", "gossip_sign",  0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/                 fd_topob_tile_out(   topo, "gossip", 0UL,                        "gossip_sign",  0UL                                                  );
    /**/                 fd_topob_tile_in(    topo, "gossip", 0UL,           "metric_in", "sign_gossip",  0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
    /**/                 fd_topob_tile_out(   topo, "sign",   0UL,                        "sign_gossip",  0UL                                                  );

    /* net tile: gossip tile sends UDP packets out through the net tile */
    /**/                 fd_topos_tile_in_net( topo,                         "metric_in", "gossip_net",   0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED ); /* No reliable consumers of networking fragments, may be dropped or overrun */

    /* shred tile: receives shred_version from ipecho so it can filter shreds correctly */
    FOR(shred_tile_cnt)  fd_topob_tile_in(    topo, "shred",  i,            "metric_in", "ipecho_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

    /* shred tile: receives contact info from gossip so it can compute turbine children for retransmit */
    FOR(shred_tile_cnt)  fd_topob_tile_in(    topo, "shred",  i,            "metric_in", "gossip_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }

  /* For now the only plugin consumer is the GUI */
  int plugins_enabled = config->tiles.gui.enabled;
  if( FD_LIKELY( plugins_enabled && !relay ) ) {
    fd_topob_wksp( topo, "plugin_in"    );
    fd_topob_wksp( topo, "plugin_out"   );
    fd_topob_wksp( topo, "plugin"       );

    /**/                 fd_topob_link( topo, "plugin_out",   "plugin_out",   128UL,                                    8UL+40200UL*(58UL+12UL*34UL), 1UL );
    /**/                 fd_topob_link( topo, "replay_plugi", "plugin_in",    128UL,                                    4098*8UL,                     1UL );
    /**/                 fd_topob_link( topo, "gossip_plugi", "plugin_in",    128UL,                                    8UL+40200UL*(58UL+12UL*34UL), 1UL );
    /**/                 fd_topob_link( topo, "poh_plugin",   "plugin_in",    128UL,                                    16UL,                         1UL );
    /**/                 fd_topob_link( topo, "startp_plugi", "plugin_in",    128UL,                                    56UL,                         1UL );
    /**/                 fd_topob_link( topo, "votel_plugin", "plugin_in",    128UL,                                    8UL,                          1UL );
    /**/                 fd_topob_link( topo, "valcfg_plugi", "plugin_in",    128UL,                                    608UL,                        1UL );

    /**/                 fd_topob_tile( topo, "plugin",  "plugin",  "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0, 0 );

    /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "replay_plugi", 0UL                                                );
    /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "gossip_plugi", 0UL                                                );
    /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "poh_plugin",   0UL                                                );
    /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "startp_plugi", 0UL                                                );
    /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "votel_plugin", 0UL                                                );
    /**/                 fd_topob_tile_out( topo, "plugin", 0UL,                        "plugin_out",   0UL                                                );
    /**/                 fd_topob_tile_out( topo, "poh",    0UL,                        "valcfg_plugi", 0UL                                                );

    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "replay_plugi", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "gossip_plugi", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "stake_out",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "poh_plugin",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "startp_plugi", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "votel_plugin", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    /**/                 fd_topob_tile_in(  topo, "plugin", 0UL,           "metric_in", "valcfg_plugi", 0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  }

  if( FD_LIKELY( config->tiles.gui.enabled ) ) {
    fd_topob_wksp( topo, "gui"          );
    /**/                 fd_topob_tile( topo, "gui",     "gui",     "metric_in",  tile_to_cpu[ topo->tile_cnt ], 0, 1 );
    if( FD_LIKELY( !relay ) ) {
      /**/               fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "plugin_out",   0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
      /**/               fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "poh_pack",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
      /**/               fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "pack_bank",    0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
      /**/               fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "pack_poh",     0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
      FOR(bank_tile_cnt) fd_topob_tile_in(  topo, "gui",    0UL,           "metric_in", "bank_poh",     i,            FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    }
  }

  if( FD_UNLIKELY( config->tiles.bundle.enabled ) ) {
    fd_topob_wksp( topo, "bundle_verif" );
    fd_topob_wksp( topo, "bundle_sign"  );
    fd_topob_wksp( topo, "sign_bundle"  );
    fd_topob_wksp( topo, "pack_sign"    );
    fd_topob_wksp( topo, "sign_pack"    );
    fd_topob_wksp( topo, "bundle"       );

    /**/                 fd_topob_link( topo, "bundle_verif", "bundle_verif", config->tiles.verify.receive_buffer_size, FD_TPU_PARSED_MTU,         1UL );
    /**/                 fd_topob_link( topo, "bundle_sign",  "bundle_sign",  65536UL,                                  9UL,                       1UL );
    /**/                 fd_topob_link( topo, "sign_bundle",  "sign_bundle",  128UL,                                    64UL,                      1UL );
    /**/                 fd_topob_link( topo, "pack_sign",    "pack_sign",    65536UL,                                  1232UL,                    1UL );
    /**/                 fd_topob_link( topo, "sign_pack",    "sign_pack",    128UL,                                    64UL,                      1UL );

    /**/                 fd_topob_tile( topo, "bundle",  "bundle",  "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 1 );

    /**/                 fd_topob_tile_out( topo, "bundle", 0UL, "bundle_verif", 0UL );
    FOR(verify_tile_cnt) fd_topob_tile_in(  topo, "verify", i,             "metric_in", "bundle_verif",   0UL,        FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );

    /**/                 fd_topob_tile_in(  topo, "sign",   0UL,           "metric_in", "bundle_sign",    0UL,        FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/                 fd_topob_tile_out( topo, "bundle", 0UL,                        "bundle_sign",    0UL                                                );
    /**/                 fd_topob_tile_in(  topo, "bundle", 0UL,           "metric_in", "sign_bundle",    0UL,        FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
    /**/                 fd_topob_tile_out( topo, "sign",   0UL,                        "sign_bundle",    0UL                                                );

    /**/                 fd_topob_tile_in(  topo, "sign",   0UL,           "metric_in", "pack_sign",      0UL,        FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
    /**/                 fd_topob_tile_out( topo, "pack",   0UL,                        "pack_sign",      0UL                                                );
    /**/                 fd_topob_tile_in(  topo, "pack",   0UL,           "metric_in", "sign_pack",      0UL,        FD_TOPOB_UNRELIABLE, FD_TOPOB_UNPOLLED );
    /**/                 fd_topob_tile_out( topo, "sign",   0UL,                        "sign_pack",      0UL                                                );

    if( plugins_enabled ) {
      fd_topob_wksp( topo, "bundle_plugi" );
      /* bundle_plugi must be kind of deep, to prevent exhausting shared
         flow control credits when publishing many packets at once. */
      fd_topob_link( topo, "bundle_plugi", "bundle_plugi", 65536UL, sizeof(fd_plugin_msg_block_engine_update_t), 1UL );
      fd_topob_tile_in( topo, "plugin", 0UL, "metric_in", "bundle_plugi", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
      fd_topob_tile_out( topo, "bundle", 0UL, "bundle_plugi", 0UL );
    }
  }

  if( FD_UNLIKELY( config->tiles.dexfilter.enabled ) ) {
    fd_topob_wksp( topo, "shred_dexfilter" );
    fd_topob_wksp( topo, "dexfilter" );

    FOR(shred_tile_cnt) fd_topob_link( topo, "shred_dexfilter", "shred_dexfilter", 1024UL, 65536UL, 1UL );

    fd_topob_tile( topo, "dexfilter", "dexfilter", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );

    FOR(shred_tile_cnt) fd_topob_tile_out( topo, "shred",  i,      "shred_dexfilter", i );
    FOR(shred_tile_cnt) fd_topob_tile_in(  topo, "dexfilter", 0UL, "metric_in", "shred_dexfilter", i, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  }

  if( FD_UNLIKELY( config->tiles.shred_mcast.enabled ) ) {
    fd_topob_wksp( topo, "shred_mcast" );
    fd_topob_wksp( topo, "mcast_shred" );

    /* One shred_mcast link per shred tile — each carries raw shred bytes (shred → shred_mcast) */
    FOR(shred_tile_cnt) fd_topob_link( topo, "shred_mcast", "shred_mcast", 1024UL, FD_SHRED_MAX_SZ, 1UL );
    /* One mcast_shred link per shred tile — shred_mcast forwards mcast-received shreds back to each shred tile */
    FOR(shred_tile_cnt) fd_topob_link( topo, "mcast_shred", "mcast_shred", 1024UL, FD_SHRED_MAX_SZ, 1UL );

    fd_topob_tile( topo, "smcast", "shred_mcast", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0 );
    strncpy( topo->tiles[ topo->tile_cnt-1UL ].metrics_name, "shred_mcast", 13UL );

    FOR(shred_tile_cnt) fd_topob_tile_out( topo, "shred",  i,    "shred_mcast", i );
    FOR(shred_tile_cnt) fd_topob_tile_in(  topo, "smcast", 0UL, "metric_in", "shred_mcast", i, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );

    FOR(shred_tile_cnt) fd_topob_tile_out( topo, "smcast", 0UL, "mcast_shred", i );
    FOR(shred_tile_cnt) fd_topob_tile_in(  topo, "shred",       i,   "metric_in", "mcast_shred", i, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  }

  if( FD_LIKELY( !is_auto_affinity ) ) {
    if( FD_UNLIKELY( affinity_tile_cnt<topo->tile_cnt ) )
      FD_LOG_ERR(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] only provides for %lu cores. "
                   "You should either increase the number of cores dedicated to Firedancer in the affinity string, or decrease the number of cores needed by reducing "
                   "the total tile count. You can reduce the tile count by decreasing individual tile counts in the [layout] section of the configuration file.",
                   topo->tile_cnt, affinity_tile_cnt ));
    if( FD_UNLIKELY( affinity_tile_cnt>topo->tile_cnt ) )
      FD_LOG_WARNING(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] provides for %lu cores. "
                       "Not all cores in the affinity will be used by Firedancer. You may wish to increase the number of tiles in the system by increasing "
                       "individual tile counts in the [layout] section of the configuration file.",
                       topo->tile_cnt, affinity_tile_cnt ));

    if( FD_LIKELY( strcmp( "", config->frankendancer.layout.agave_affinity ) ) ) {
      ushort agave_cpu[ FD_TILE_MAX ];
      ulong agave_cpu_cnt = fd_tile_private_cpus_parse( config->frankendancer.layout.agave_affinity, agave_cpu );

      for( ulong i=0UL; i<agave_cpu_cnt; i++ ) {
        if( FD_UNLIKELY( agave_cpu[ i ]>=cpus->cpu_cnt ) )
          FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.agave_affinity] specifies a CPU index of %hu, but the system "
                       "only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                       "in the system.",
                       agave_cpu[ i ], cpus->cpu_cnt ));

        for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
          fd_topo_tile_t * tile = &topo->tiles[ j ];
          if( tile->cpu_idx==agave_cpu[ i ] ) FD_LOG_WARNING(( "Tile `%s:%lu` is already assigned to CPU %hu, but the CPU is also assigned to Agave. "
                                                               "This may cause contention between the two tiles.", tile->name, tile->kind_id, agave_cpu[ i ] ));
        }

        if( FD_UNLIKELY( topo->agave_affinity_cnt>FD_TILE_MAX ) ) {
          FD_LOG_ERR(( "The CPU affinity string in the configuration file under [layout.agave_affinity] specifies more CPUs than Firedancer can use. "
                        "You should reduce the number of CPUs in the affinity string." ));
        }
        topo->agave_affinity_cpu_idx[ topo->agave_affinity_cnt++ ] = agave_cpu[ i ];
      }
    }
  } else {
    ushort blocklist_cores[ FD_TILE_MAX ];
    topo->blocklist_cores_cnt = fd_tile_private_cpus_parse( config->layout.blocklist_cores, blocklist_cores );
    if( FD_UNLIKELY( topo->blocklist_cores_cnt>FD_TILE_MAX ) ) {
      FD_LOG_ERR(( "The CPU string in the configuration file under [layout.blocklist_cores] specifies more CPUs than Firedancer can use. "
                    "You should reduce the number of CPUs in the excluded cores string." ));
    }

    for( ulong i=0UL; i<topo->blocklist_cores_cnt; i++ ) {
      /* Since we use fd_tile_private_cpus_parse() like for affinity, the user
         may input a string containing `f`. That's parsed correctly, but it's
         meaningless for blocklisted cores, so we reject it here.  */
      if( FD_UNLIKELY( blocklist_cores[ i ]==USHORT_MAX ) ) {
        FD_LOG_ERR(( "The CPU string in the configuration file under [layout.blocklist_cores] contains invalid values: `f`. "
                      "You should fix the excluded cores string." ));
      }
      topo->blocklist_cores_cpu_idx[ i ] = blocklist_cores[ i ];
    }
  }

  /* There is a special fseq that sits between the pack, bank, and poh
     tiles to indicate when the bank/poh tiles are done processing a
     microblock.  Pack uses this to determine when to "unlock" accounts
     that it marked as locked because they were being used. */

  if( FD_LIKELY( !relay ) ) {
    for( ulong i=0UL; i<bank_tile_cnt; i++ ) {
      fd_topo_obj_t * busy_obj = fd_topob_obj( topo, "fseq", "bank_busy" );

      fd_topo_tile_t * poh_tile = &topo->tiles[ fd_topo_find_tile( topo, "poh", 0UL ) ];
      fd_topo_tile_t * pack_tile = &topo->tiles[ fd_topo_find_tile( topo, "pack", 0UL ) ];
      fd_topob_tile_uses( topo, poh_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
      fd_topob_tile_uses( topo, pack_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
      FD_TEST( fd_pod_insertf_ulong( topo->props, busy_obj->id, "bank_busy.%lu", i ) );
    }
  }

  /* There's another special fseq that's used to communicate the shred
     version from the Agave boot path to the shred tile. */
  if( FD_LIKELY( !relay ) ) {
    fd_topo_obj_t * poh_shred_obj = fd_topob_obj( topo, "fseq", "poh_shred" );
    fd_topo_tile_t * poh_tile = &topo->tiles[ fd_topo_find_tile( topo, "poh", 0UL ) ];
    fd_topob_tile_uses( topo, poh_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    for( ulong i=0UL; i<shred_tile_cnt; i++ ) {
      fd_topo_tile_t * shred_tile = &topo->tiles[ fd_topo_find_tile( topo, "shred", i ) ];
      fd_topob_tile_uses( topo, shred_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    }
    FD_TEST( fd_pod_insertf_ulong( topo->props, poh_shred_obj->id, "poh_shred" ) );
  }

  FOR(net_tile_cnt) fd_topos_net_tile_finish( topo, i );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    fd_topo_configure_tile( tile, config );
  }

  if( FD_UNLIKELY( is_auto_affinity ) ) fd_topob_auto_layout( topo, 1 );

  fd_topob_finish( topo, CALLBACKS );
  config->topo = *topo;
}

void
fd_topo_configure_tile( fd_topo_tile_t * tile,
                        fd_config_t *    config ) {
  int plugins_enabled = config->tiles.gui.enabled;

  if( FD_UNLIKELY( !strcmp( tile->name, "net" ) || !strcmp( tile->name, "sock" ) ) ) {

    tile->net.shred_listen_port              = config->tiles.shred.shred_listen_port;
    if( FD_LIKELY( strcmp( config->layout.mode, "shred_relay" ) ) ) {
      tile->net.quic_transaction_listen_port   = config->tiles.quic.quic_transaction_listen_port;
      tile->net.legacy_transaction_listen_port = config->tiles.quic.regular_transaction_listen_port;
    } else {
      tile->net.gossip_listen_port             = config->gossip.port;
    }

  } else if( FD_UNLIKELY( !strcmp( tile->name, "netlnk" ) ) ) {

    /* already configured */

  } else if( FD_UNLIKELY( !strcmp( tile->name, "quic" ) ) ) {

    tile->quic.reasm_cnt                      = config->tiles.quic.txn_reassembly_count;
    tile->quic.out_depth                      = config->tiles.verify.receive_buffer_size;
    tile->quic.max_concurrent_connections     = config->tiles.quic.max_concurrent_connections;
    tile->quic.max_concurrent_handshakes      = config->tiles.quic.max_concurrent_handshakes;
    tile->quic.quic_transaction_listen_port   = config->tiles.quic.quic_transaction_listen_port;
    tile->quic.idle_timeout_millis            = config->tiles.quic.idle_timeout_millis;
    tile->quic.ack_delay_millis               = config->tiles.quic.ack_delay_millis;
    tile->quic.retry                          = config->tiles.quic.retry;
    fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( tile->quic.key_log_path ), config->tiles.quic.ssl_key_log_file, sizeof(tile->quic.key_log_path) ) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "bundle" ) ) ) {
    strncpy( tile->bundle.url, config->tiles.bundle.url, sizeof(tile->bundle.url) );
    tile->bundle.url_len = strnlen( tile->bundle.url, 255 );
    strncpy( tile->bundle.sni, config->tiles.bundle.tls_domain_name, 256 );
    tile->bundle.sni_len = strnlen( tile->bundle.sni, 255 );
    strncpy( tile->bundle.identity_key_path, config->paths.identity_key, sizeof(tile->bundle.identity_key_path) );
    strncpy( tile->bundle.key_log_path, config->development.bundle.ssl_key_log_file, sizeof(tile->bundle.key_log_path) );
    tile->bundle.buf_sz = config->development.bundle.buffer_size_kib<<10;
    tile->bundle.ssl_heap_sz = config->development.bundle.ssl_heap_size_mib<<20;
    tile->bundle.keepalive_interval_nanos = config->tiles.bundle.keepalive_interval_millis * (ulong)1e6;
    tile->bundle.tls_cert_verify = !!config->tiles.bundle.tls_cert_verify;
  } else if( FD_UNLIKELY( !strcmp( tile->name, "verify" ) ) ) {
    tile->verify.tcache_depth = config->tiles.verify.signature_cache_size;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "dedup" ) ) ) {
    tile->dedup.tcache_depth = config->tiles.dedup.signature_cache_size;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "resolv" ) ) ) {

  } else if( FD_UNLIKELY( !strcmp( tile->name, "pack" ) ) ) {
    tile->pack.max_pending_transactions      = config->tiles.pack.max_pending_transactions;
    tile->pack.bank_tile_count               = config->layout.bank_tile_count;
    tile->pack.larger_max_cost_per_block     = config->development.bench.larger_max_cost_per_block;
    tile->pack.larger_shred_limits_per_block = config->development.bench.larger_shred_limits_per_block;
    tile->pack.use_consumed_cus              = config->tiles.pack.use_consumed_cus;
    tile->pack.schedule_strategy             = config->tiles.pack.schedule_strategy_enum;

    if( FD_UNLIKELY( config->tiles.bundle.enabled ) ) {
#define PARSE_PUBKEY( _tile, f ) \
      if( FD_UNLIKELY( !fd_base58_decode_32( config->tiles.bundle.f, tile->_tile.bundle.f ) ) )  \
        FD_LOG_ERR(( "[tiles.bundle.enabled] set to true, but failed to parse [tiles.bundle."#f"] %s", config->tiles.bundle.f ));
      tile->pack.bundle.enabled = 1;
      PARSE_PUBKEY( pack, tip_distribution_program_addr );
      PARSE_PUBKEY( pack, tip_payment_program_addr      );
      PARSE_PUBKEY( pack, tip_distribution_authority    );
      tile->pack.bundle.commission_bps = config->tiles.bundle.commission_bps;
      strncpy( tile->pack.bundle.identity_key_path, config->paths.identity_key, sizeof(tile->pack.bundle.identity_key_path) );
      strncpy( tile->pack.bundle.vote_account_path, config->paths.vote_account, sizeof(tile->pack.bundle.vote_account_path) );
    } else {
      fd_memset( &tile->pack.bundle, '\0', sizeof(tile->pack.bundle) );
    }
  } else if( FD_UNLIKELY( !strcmp( tile->name, "bank" ) ) ) {

  } else if( FD_UNLIKELY( !strcmp( tile->name, "poh" ) ) ) {
    strncpy( tile->poh.identity_key_path, config->paths.identity_key, sizeof(tile->poh.identity_key_path) );

    tile->poh.plugins_enabled = plugins_enabled;
    tile->poh.bank_cnt = config->layout.bank_tile_count;
    tile->poh.lagged_consecutive_leader_start = config->tiles.poh.lagged_consecutive_leader_start;

    if( FD_UNLIKELY( config->tiles.bundle.enabled ) ) {
      tile->poh.bundle.enabled = 1;
      PARSE_PUBKEY( poh, tip_distribution_program_addr );
      PARSE_PUBKEY( poh, tip_payment_program_addr      );
      strncpy( tile->poh.bundle.vote_account_path, config->paths.vote_account, sizeof(tile->poh.bundle.vote_account_path) );
#undef PARSE_PUBKEY
    } else {
      fd_memset( &tile->poh.bundle, '\0', sizeof(tile->poh.bundle) );
    }

  } else if( FD_UNLIKELY( !strcmp( tile->name, "shred" ) ) ) {
    strncpy( tile->shred.identity_key_path, config->paths.identity_key, sizeof(tile->shred.identity_key_path) );

    tile->shred.depth                         = config->topo.links[ tile->out_link_id[ 0 ] ].depth;
    tile->shred.fec_resolver_depth            = config->tiles.shred.max_pending_shred_sets;
    tile->shred.expected_shred_version        = config->consensus.expected_shred_version;
    tile->shred.shred_listen_port             = config->tiles.shred.shred_listen_port;
    tile->shred.larger_shred_limits_per_block = config->development.bench.larger_shred_limits_per_block;
    for( ulong i=0UL; i<config->tiles.shred.additional_shred_destinations_retransmit_cnt; i++ ) {
      parse_ip_port( "tiles.shred.additional_shred_destinations_retransmit",
                      config->tiles.shred.additional_shred_destinations_retransmit[ i ],
                      &tile->shred.adtl_dests_retransmit[ i ] );
    }
    tile->shred.adtl_dests_retransmit_cnt = config->tiles.shred.additional_shred_destinations_retransmit_cnt;
    for( ulong i=0UL; i<config->tiles.shred.additional_shred_destinations_leader_cnt; i++ ) {
      parse_ip_port( "tiles.shred.additional_shred_destinations_leader",
                      config->tiles.shred.additional_shred_destinations_leader[ i ],
                      &tile->shred.adtl_dests_leader[ i ] );
    }
    tile->shred.adtl_dests_leader_cnt = config->tiles.shred.additional_shred_destinations_leader_cnt;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "store" ) ) ) {
    tile->store.disable_blockstore_from_slot = config->development.bench.disable_blockstore_from_slot;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "sign" ) ) ) {
    strncpy( tile->sign.identity_key_path, config->paths.identity_key, sizeof(tile->sign.identity_key_path) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "metric" ) ) ) {
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.metric.prometheus_listen_address, &tile->metric.prometheus_listen_addr ) ) )
      FD_LOG_ERR(( "failed to parse prometheus listen address `%s`", config->tiles.metric.prometheus_listen_address ));
    tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "cswtch" ) ) ) {

  } else if( FD_UNLIKELY( !strcmp( tile->name, "gui" ) ) ) {
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.gui.gui_listen_address, &tile->gui.listen_addr ) ) )
      FD_LOG_ERR(( "failed to parse gui listen address `%s`", config->tiles.gui.gui_listen_address ));
    tile->gui.listen_port = config->tiles.gui.gui_listen_port;
    tile->gui.is_voting = strcmp( config->paths.vote_account, "" );
    strncpy( tile->gui.cluster, config->cluster, sizeof(tile->gui.cluster) );
    strncpy( tile->gui.identity_key_path, config->paths.identity_key, sizeof(tile->gui.identity_key_path) );
    strncpy( tile->gui.vote_key_path, config->paths.vote_account, sizeof(tile->gui.vote_key_path) );
    tile->gui.max_http_connections      = config->tiles.gui.max_http_connections;
    tile->gui.max_websocket_connections = config->tiles.gui.max_websocket_connections;
    tile->gui.max_http_request_length   = config->tiles.gui.max_http_request_length;
    tile->gui.send_buffer_size_mb       = config->tiles.gui.send_buffer_size_mb;
    tile->gui.schedule_strategy         = config->tiles.pack.schedule_strategy_enum;
    tile->gui.websocket_compression     = config->development.gui.websocket_compression;
    tile->gui.frontend_release_channel  = config->development.gui.frontend_release_channel_enum;
    strncpy( tile->gui.layout_mode, config->layout.mode, sizeof(tile->gui.layout_mode)-1UL );
    tile->gui.layout_mode[ sizeof(tile->gui.layout_mode)-1UL ] = '\0';

  } else if( FD_UNLIKELY( !strcmp( tile->name, "plugin" ) ) ) {

  } else if( FD_UNLIKELY( !strcmp( tile->name, "smcast" ) ) ) {
    ulong src_cnt = config->tiles.shred_mcast.mcast_srcs_cnt;
    if( FD_UNLIKELY( src_cnt>FD_SHRED_MCAST_SRC_MAX ) )
      FD_LOG_ERR(( "tiles.shred_mcast.mcast_srcs: too many entries (max %lu)", FD_SHRED_MCAST_SRC_MAX ));
    tile->shred_mcast.mcast_src_cnt = src_cnt;
    for( ulong i=0UL; i<src_cnt; i++ ) {
      fd_topo_ip_port_t src_parsed;
      parse_ip_port( "tiles.shred_mcast.mcast_srcs", config->tiles.shred_mcast.mcast_srcs[ i ], &src_parsed );
      tile->shred_mcast.mcast_src_ips  [ i ] = src_parsed.ip;
      tile->shred_mcast.mcast_src_ports[ i ] = src_parsed.port;
      tile->shred_mcast.mcast_rx_socks [ i ] = -1;
    }
    ulong dst_cnt = config->tiles.shred_mcast.mcast_dsts_cnt;
    if( FD_UNLIKELY( dst_cnt>FD_SHRED_MCAST_DST_MAX ) )
      FD_LOG_ERR(( "tiles.shred_mcast.mcast_dsts: too many entries (max %lu)", FD_SHRED_MCAST_DST_MAX ));
    tile->shred_mcast.mcast_dst_cnt = dst_cnt;
    for( ulong i=0UL; i<dst_cnt; i++ ) {
      fd_topo_ip_port_t dst_parsed;
      parse_ip_port( "tiles.shred_mcast.mcast_dsts", config->tiles.shred_mcast.mcast_dsts[ i ], &dst_parsed );
      tile->shred_mcast.mcast_dst_ips  [ i ] = dst_parsed.ip;
      tile->shred_mcast.mcast_dst_ports[ i ] = dst_parsed.port;
    }
    tile->shred_mcast.mcast_ttl     = (uchar)config->tiles.shred_mcast.mcast_ttl;
    tile->shred_mcast.mcast_tx_sock = -1;

  } else if( FD_UNLIKELY( !strcmp( tile->name, "ipecho" ) ) ) {

    tile->ipecho.expected_shred_version = config->consensus.expected_shred_version;
    tile->ipecho.bind_address           = config->net.ip_addr;
    tile->ipecho.bind_port              = config->gossip.port;
    tile->ipecho.entrypoints_cnt        = config->gossip.entrypoints_cnt;
    fd_memcpy( tile->ipecho.entrypoints, config->gossip.resolved_entrypoints, tile->ipecho.entrypoints_cnt * sizeof(fd_ip4_port_t) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "gossvf" ) ) ) {

    strncpy( tile->gossvf.identity_key_path, config->paths.identity_key, sizeof(tile->gossvf.identity_key_path) );
    tile->gossvf.tcache_depth          = 1<<22UL;
    tile->gossvf.shred_version         = 0U;
    tile->gossvf.allow_private_address = config->development.gossip.allow_private_address;
    tile->gossvf.boot_timestamp_nanos  = config->boot_timestamp_nanos;
    tile->gossvf.entrypoints_cnt       = config->gossip.entrypoints_cnt;
    fd_memcpy( tile->gossvf.entrypoints, config->gossip.resolved_entrypoints, tile->gossvf.entrypoints_cnt * sizeof(fd_ip4_port_t) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "dexfilter" ) ) ) {

    fd_cstr_ncpy( tile->dexfilter.log_path,      config->tiles.dexfilter.log_path,      sizeof(tile->dexfilter.log_path)      );
    fd_cstr_ncpy( tile->dexfilter.swap_log_path, config->tiles.dexfilter.swap_log_path, sizeof(tile->dexfilter.swap_log_path) );

  } else if( FD_UNLIKELY( !strcmp( tile->name, "gossip" ) ) ) {

    tile->gossip.ip_addr               = config->net.ip_addr;
    strncpy( tile->gossip.identity_key_path, config->paths.identity_key, sizeof(tile->gossip.identity_key_path) );
    tile->gossip.shred_version         = config->consensus.expected_shred_version;
    tile->gossip.max_entries           = config->tiles.gossip.max_entries;
    tile->gossip.boot_timestamp_nanos  = config->boot_timestamp_nanos;
    tile->gossip.ports.gossip          = config->gossip.port;
    tile->gossip.ports.tvu             = config->tiles.shred.shred_listen_port;
    tile->gossip.ports.tpu             = 0; /* relay does not serve TPU */
    tile->gossip.ports.tpu_quic        = 0; /* relay does not serve TPU QUIC */
    tile->gossip.ports.repair          = 0; /* relay does not do repair */
    tile->gossip.entrypoints_cnt           = config->gossip.entrypoints_cnt;
    fd_memcpy( tile->gossip.entrypoints, config->gossip.resolved_entrypoints, tile->gossip.entrypoints_cnt * sizeof(fd_ip4_port_t) );
    tile->gossip.restrict_to_entrypoints   = 0; /* Must gossip with full cluster so our TVU is known and shreds are delivered */

  } else {
    FD_LOG_ERR(( "unknown tile name %lu `%s`", tile->id, tile->name ));
  }
}
