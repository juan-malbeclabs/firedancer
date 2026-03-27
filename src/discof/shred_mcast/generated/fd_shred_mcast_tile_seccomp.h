/* THIS FILE IS GENERATED FROM fd_shred_mcast_tile.seccomppolicy. DO NOT EDIT BY HAND! */
#ifndef HEADER_fd_src_discof_shred_mcast_generated_fd_shred_mcast_tile_seccomp_h
#define HEADER_fd_src_discof_shred_mcast_generated_fd_shred_mcast_tile_seccomp_h

#if defined(__linux__)

#include "../../../../src/util/fd_util_base.h"
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <sys/syscall.h>
#include <signal.h>
#include <stddef.h>

#if defined(__i386__)
# define ARCH_NR  AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define ARCH_NR  AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
# define ARCH_NR AUDIT_ARCH_AARCH64
#else
# error "Target architecture is unsupported by seccomp."
#endif

static const unsigned int sock_filter_policy_fd_shred_mcast_tile_instr_cnt = 20;

/* logfile_fd:    log file descriptor (may be -1, passed as UINT_MAX)
   mcast_rx_sock: UDP socket joined to source multicast group (RX)
   mcast_tx_sock: UDP socket for sending to destination multicast group (TX) */
static void
populate_sock_filter_policy_fd_shred_mcast_tile( ulong                out_cnt,
                                                  struct sock_filter * out,
                                                  unsigned int         logfile_fd,
                                                  unsigned int         mcast_rx_sock,
                                                  unsigned int         mcast_tx_sock ) {
  FD_TEST( out_cnt >= 20 );
  struct sock_filter filter[20] = {
    /* [0]  Check arch — kill if mismatch */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, ( offsetof( struct seccomp_data, arch ) ) ),
    /* [1] */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, ARCH_NR, 0, /* RET_KILL_PROCESS */ 16 ),
    /* [2]  Load syscall number */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, ( offsetof( struct seccomp_data, nr ) ) ),
    /* [3]  if == recvmmsg → check_recvmmsg [8] */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, SYS_recvmmsg, /* check_recvmmsg */ 4, 0 ),
    /* [4]  if == sendto → check_sendto [10] */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, SYS_sendto, /* check_sendto */ 5, 0 ),
    /* [5]  if == write → check_write [12] */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, SYS_write, /* check_write */ 6, 0 ),
    /* [6]  if == fsync → check_fsync [16] */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, SYS_fsync, /* check_fsync */ 9, 0 ),
    /* [7]  none matched → kill */
    { BPF_JMP | BPF_JA, 0, 0, /* RET_KILL_PROCESS */ 10 },

//  check_recvmmsg:
    /* [8]  load arg[0] */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    /* [9]  if == mcast_rx_sock → RET_ALLOW [19], else → RET_KILL [18] */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, mcast_rx_sock, /* RET_ALLOW */ 9, /* RET_KILL_PROCESS */ 8 ),

//  check_sendto:
    /* [10] load arg[0] */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    /* [11] if == mcast_tx_sock → RET_ALLOW [19], else → RET_KILL [18] */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, mcast_tx_sock, /* RET_ALLOW */ 7, /* RET_KILL_PROCESS */ 6 ),

//  check_write:
    /* [12] load arg[0] */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    /* [13] if == 2 (stderr) → RET_ALLOW [19] */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, 2, /* RET_ALLOW */ 5, /* lbl_1 */ 0 ),
//  lbl_1:
    /* [14] load arg[0] */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    /* [15] if == logfile_fd → RET_ALLOW [19], else → RET_KILL [18] */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, logfile_fd, /* RET_ALLOW */ 3, /* RET_KILL_PROCESS */ 2 ),

//  check_fsync:
    /* [16] load arg[0] */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    /* [17] if == logfile_fd → RET_ALLOW [19], else → RET_KILL [18] */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, logfile_fd, /* RET_ALLOW */ 1, /* RET_KILL_PROCESS */ 0 ),

//  RET_KILL_PROCESS:
    /* [18] KILL_PROCESS is placed before ALLOW since it is the fallthrough case */
    BPF_STMT( BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS ),
//  RET_ALLOW:
    /* [19] ALLOW has to be reached by jumping */
    BPF_STMT( BPF_RET | BPF_K, SECCOMP_RET_ALLOW ),
  };
  fd_memcpy( out, filter, sizeof( filter ) );
}

#endif /* defined(__linux__) */

#endif /* HEADER_fd_src_discof_shred_mcast_generated_fd_shred_mcast_tile_seccomp_h */
