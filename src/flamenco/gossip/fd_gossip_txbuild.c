#include "fd_gossip_txbuild.h"

#include "fd_gossip_private.h"
#include "../../disco/fd_disco_base.h" /* FD_GOSSIP_MTU */

struct __attribute__((packed)) crds_val_hdr {
  uchar sig[ 64UL ];
  uint  tag; /* CRDS value tag */
};

typedef struct crds_val_hdr crds_val_hdr_t;

struct __attribute__((packed)) crds_msg {
  uint msg_type;
  uchar identity_pubkey[ 32UL ];
  ulong crds_len;
  uchar crds[ ];
};

typedef struct crds_msg crds_msg_t;

/* Internal helper: write the message header at txbuild->bytes. */

static void
txbuild_write_hdr( fd_gossip_txbuild_t * txbuild,
                   uchar const *         identity_pubkey,
                   uchar                 msg_type ) {
  txbuild->tag       = msg_type;
  txbuild->bytes_len = 44UL; /* offsetof( crds_msg_t, crds ) */
  txbuild->crds_len  = 0UL;

  crds_msg_t * msg = (crds_msg_t *)txbuild->bytes;
  msg->msg_type = msg_type;
  fd_memcpy( msg->identity_pubkey, identity_pubkey, 32UL );
  msg->crds_len = 0UL;
}

void
fd_gossip_txbuild_init( fd_gossip_txbuild_t * txbuild,
                        uchar const *         identity_pubkey,
                        uchar                 msg_type ) {
  txbuild->bytes = txbuild->_bytes;
  txbuild_write_hdr( txbuild, identity_pubkey, msg_type );
}

void
fd_gossip_txbuild_init_ext( fd_gossip_txbuild_t * txbuild,
                             uchar const *         identity_pubkey,
                             uchar                 msg_type,
                             uchar *               ext_bytes ) {
  txbuild->bytes = ext_bytes ? ext_bytes : txbuild->_bytes;
  txbuild_write_hdr( txbuild, identity_pubkey, msg_type );
}

int
fd_gossip_txbuild_can_fit( fd_gossip_txbuild_t const * txbuild,
                           ulong                       crds_len ) {
  return crds_len<=(FD_GOSSIP_MTU - txbuild->bytes_len) &&
         txbuild->crds_len < FD_GOSSIP_MSG_MAX_CRDS;
}

uchar *
fd_gossip_txbuild_reserve( fd_gossip_txbuild_t * txbuild,
                            ulong                 crds_len ) {
  if( FD_UNLIKELY( !fd_gossip_txbuild_can_fit( txbuild, crds_len ) ) ) return NULL;
  return txbuild->bytes + txbuild->bytes_len;
}

void
fd_gossip_txbuild_commit( fd_gossip_txbuild_t * txbuild,
                           ulong                 crds_len ) {
  FD_TEST( crds_len <= FD_GOSSIP_CRDS_MAX_SZ );
  FD_TEST( txbuild->crds_len < FD_GOSSIP_MSG_MAX_CRDS );

  crds_msg_t *     msg = (crds_msg_t *)txbuild->bytes;
  crds_val_hdr_t * hdr = (crds_val_hdr_t *)( txbuild->bytes + txbuild->bytes_len );

  msg->crds_len++;
  txbuild->crds[ txbuild->crds_len ].tag = hdr->tag;
  txbuild->crds[ txbuild->crds_len ].off = (ushort)txbuild->bytes_len;
  txbuild->crds[ txbuild->crds_len ].sz  = (ushort)crds_len;
  txbuild->crds_len++;
  txbuild->bytes_len += crds_len;
}

void
fd_gossip_txbuild_append( fd_gossip_txbuild_t * txbuild,
                          ulong                 crds_len,
                          uchar const *         crds ) {
  FD_TEST( crds_len<=FD_GOSSIP_CRDS_MAX_SZ );
  FD_TEST( fd_gossip_txbuild_can_fit( txbuild, crds_len ) );

  fd_memcpy( txbuild->bytes + txbuild->bytes_len, crds, crds_len );
  fd_gossip_txbuild_commit( txbuild, crds_len );
}
