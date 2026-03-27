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

static const unsigned int sock_filter_policy_fd_shred_mcast_tile_instr_cnt = 26;

/* logfile_fd:       log file descriptor (may be -1, passed as UINT_MAX)
   mcast_rx_sock_N:  UDP sockets joined to source multicast groups (RX),
                     up to 8; unused slots should be passed as UINT_MAX
   mcast_tx_sock:    UDP socket for sending to destination groups (TX) */
static void
populate_sock_filter_policy_fd_shred_mcast_tile( ulong                out_cnt,
                                                  struct sock_filter * out,
                                                  unsigned int         logfile_fd,
                                                  unsigned int         mcast_rx_sock_0,
                                                  unsigned int         mcast_rx_sock_1,
                                                  unsigned int         mcast_rx_sock_2,
                                                  unsigned int         mcast_rx_sock_3,
                                                  unsigned int         mcast_rx_sock_4,
                                                  unsigned int         mcast_rx_sock_5,
                                                  unsigned int         mcast_rx_sock_6,
                                                  unsigned int         mcast_rx_sock_7,
                                                  unsigned int         mcast_tx_sock ) {
  FD_TEST( out_cnt >= 26 );

  /* Instruction layout:
     [0]     load arch
     [1]     JEQ ARCH_NR → [2] else → [24] KILL
     [2]     load syscall nr
     [3]     JEQ recvmmsg  → [8]  check_recvmmsg
     [4]     JEQ sendto    → [17] check_sendto
     [5]     JEQ write     → [19] check_write
     [6]     JEQ fsync     → [22] check_fsync
     [7]     JA → [24] KILL
     [8]     load arg[0]
     [9-16]  JEQ rx_sock_0..7 → [25] ALLOW (last: else → [24] KILL)
     [17]    load arg[0]
     [18]    JEQ tx_sock → [25] ALLOW else → [24] KILL
     [19]    load arg[0]
     [20]    JEQ 2 (stderr) → [25] ALLOW
     [21]    JEQ logfile_fd → [25] ALLOW else → [24] KILL
     [22]    load arg[0]
     [23]    JEQ logfile_fd → [25] ALLOW else → [24] KILL
     [24]    RET KILL_PROCESS
     [25]    RET ALLOW                                             */

  struct sock_filter filter[26] = {
    /* [0]  Check arch — kill if mismatch */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, ( offsetof( struct seccomp_data, arch ) ) ),
    /* [1]  jt=0 (→[2] continue), jf=22 (→[24] KILL) */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, ARCH_NR, 0, 22 ),
    /* [2]  Load syscall number */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, ( offsetof( struct seccomp_data, nr ) ) ),
    /* [3]  if == recvmmsg → [8] check_recvmmsg (jt=4), else fall */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, SYS_recvmmsg, 4, 0 ),
    /* [4]  if == sendto → [17] check_sendto (jt=12), else fall */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, SYS_sendto, 12, 0 ),
    /* [5]  if == write → [19] check_write (jt=13), else fall */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 13, 0 ),
    /* [6]  if == fsync → [22] check_fsync (jt=15), else fall */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, SYS_fsync, 15, 0 ),
    /* [7]  none matched → [24] KILL (k=16) */
    { BPF_JMP | BPF_JA, 0, 0, 16 },

//  check_recvmmsg:
    /* [8]  load arg[0] */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof( struct seccomp_data, args[0] ) ),
    /* [9]  if == rx_sock_0 → [25] ALLOW (jt=15), else fall */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, mcast_rx_sock_0, 15, 0 ),
    /* [10] if == rx_sock_1 → [25] ALLOW (jt=14), else fall */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, mcast_rx_sock_1, 14, 0 ),
    /* [11] if == rx_sock_2 → [25] ALLOW (jt=13), else fall */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, mcast_rx_sock_2, 13, 0 ),
    /* [12] if == rx_sock_3 → [25] ALLOW (jt=12), else fall */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, mcast_rx_sock_3, 12, 0 ),
    /* [13] if == rx_sock_4 → [25] ALLOW (jt=11), else fall */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, mcast_rx_sock_4, 11, 0 ),
    /* [14] if == rx_sock_5 → [25] ALLOW (jt=10), else fall */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, mcast_rx_sock_5, 10, 0 ),
    /* [15] if == rx_sock_6 → [25] ALLOW (jt=9), else fall */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, mcast_rx_sock_6, 9, 0 ),
    /* [16] if == rx_sock_7 → [25] ALLOW (jt=8), else → [24] KILL (jf=7) */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, mcast_rx_sock_7, 8, 7 ),

//  check_sendto:
    /* [17] load arg[0] */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof( struct seccomp_data, args[0] ) ),
    /* [18] if == tx_sock → [25] ALLOW (jt=6), else → [24] KILL (jf=5) */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, mcast_tx_sock, 6, 5 ),

//  check_write:
    /* [19] load arg[0] */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof( struct seccomp_data, args[0] ) ),
    /* [20] if == 2 (stderr) → [25] ALLOW (jt=4), else fall */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, 2, 4, 0 ),
    /* [21] if == logfile_fd → [25] ALLOW (jt=3), else → [24] KILL (jf=2) */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, logfile_fd, 3, 2 ),

//  check_fsync:
    /* [22] load arg[0] */
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, offsetof( struct seccomp_data, args[0] ) ),
    /* [23] if == logfile_fd → [25] ALLOW (jt=1), else → [24] KILL (jf=0) */
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, logfile_fd, 1, 0 ),

//  RET_KILL_PROCESS:
    /* [24] KILL_PROCESS is placed before ALLOW since it is the fallthrough case */
    BPF_STMT( BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS ),
//  RET_ALLOW:
    /* [25] ALLOW has to be reached by jumping */
    BPF_STMT( BPF_RET | BPF_K, SECCOMP_RET_ALLOW ),
  };
  fd_memcpy( out, filter, sizeof( filter ) );
}

#endif /* defined(__linux__) */

#endif /* HEADER_fd_src_discof_shred_mcast_generated_fd_shred_mcast_tile_seccomp_h */
