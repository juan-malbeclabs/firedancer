#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_txbuild_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_txbuild_h

#include "fd_gossip_private.h"

/* fd_gossip_txbuild_t provides a set of APIs to incrementally build a
   push or pull response message from CRDS values.  The caller is
   responsible for checking there is space before appending a new value,
   and flushing the final message. */

struct fd_gossip_txbuild {
  uchar  tag;

  ulong  bytes_len;
  uchar *bytes;     /* Active write buffer; points to _bytes or an external
                       dcache buffer set by fd_gossip_txbuild_init_ext() */

  ulong crds_len;
  struct {
   ulong tag;
   ulong off;
   ulong sz;
  } crds[ FD_GOSSIP_MSG_MAX_CRDS ];

  /* Internal fallback storage used when no external buffer is provided.
     Must be last so callers can embed this struct without waste when
     they always supply an external buffer. */
  uchar _bytes[ 1232UL ];
};

typedef struct fd_gossip_txbuild fd_gossip_txbuild_t;

FD_PROTOTYPES_BEGIN

/* fd_gossip_txbuild_init() initializes the builder to use its internal
   _bytes[] storage.  identity_pubkey and tag are as in init_ext(). */

void
fd_gossip_txbuild_init( fd_gossip_txbuild_t * txbuild,
                        uchar const *         identity_pubkey,
                        uchar                 tag );

/* fd_gossip_txbuild_init_ext() initializes the builder to write into
   ext_bytes rather than the internal _bytes[] array.  ext_bytes must
   point to at least FD_GOSSIP_MTU bytes and must remain valid until
   fd_gossip_txbuild_flush() is called.  When ext_bytes is non-NULL the
   caller is responsible for managing the buffer lifetime (e.g. a
   dcache chunk for zero-copy sends).  tag must be
   FD_GOSSIP_MESSAGE_PUSH or FD_GOSSIP_MESSAGE_PULL_RESPONSE. */

void
fd_gossip_txbuild_init_ext( fd_gossip_txbuild_t * txbuild,
                             uchar const *         identity_pubkey,
                             uchar                 tag,
                             uchar *               ext_bytes );

/* fd_gossip_txbuild_can_fit() returns 1 if the outgoing message can fit
   an additional CRDS value of size crds_len, or 0 otherwise.  If the
   message cannot fit it is undefined behavior to append it. */

int
fd_gossip_txbuild_can_fit( fd_gossip_txbuild_t const * txbuild,
                           ulong                       crds_len );

/* fd_gossip_txbuild_reserve() returns a pointer to the current write
   position in the txbuild buffer if crds_len bytes fit, or NULL if they
   do not.  The caller may write exactly crds_len bytes starting at the
   returned pointer and must then call fd_gossip_txbuild_commit() to
   finalise the value.  Unlike fd_gossip_txbuild_append(), no memcpy is
   performed — the caller writes directly into the final location. */

uchar *
fd_gossip_txbuild_reserve( fd_gossip_txbuild_t * txbuild,
                            ulong                 crds_len );

/* fd_gossip_txbuild_commit() finalises a CRDS value that was written
   directly to the pointer returned by fd_gossip_txbuild_reserve().
   crds_len must equal the value passed to the matching reserve() call.
   The value's tag is read from the first 68 bytes (sig + discriminant)
   written there by the caller. */

void
fd_gossip_txbuild_commit( fd_gossip_txbuild_t * txbuild,
                           ulong                 crds_len );

/* Appends the CRDS value to the builder->msg buffer by copying crds_len
   bytes from crds.  Assumes fd_gossip_txbuild_can_fit() returned 1. */
void
fd_gossip_txbuild_append( fd_gossip_txbuild_t * txbuild,
                          ulong                 crds_len,
                          uchar const *         crds );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_txbuild_h */
