# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Firedancer

## Overview

This repo contains two validator clients:

- **Firedancer** — A fully C-based Solana validator client.
- **Frankendancer** — A hybrid validator that uses an FFI shim to call out to the `agave/` Rust submodule for some functions.

## Topologies

- **Firedancer topology:** `src/app/firedancer/topology.c`
  - All files in `src/discof/` are for Firedancer only (not Frankendancer).
- **Frankendancer topology:** `src/app/fdctl/topology.c`
  - All files in `src/discoh/` are for Frankendancer only (not Firedancer).
- Many other files are shared between both clients — see the topology files for details.

## Building

**Firedancer:**
```bash
make -j
```

**Frankendancer:**
```bash
git submodule update --init --recursive && make -j fdctl solana
```

**Build variables:**
- `MACHINE` — selects a machine profile from `config/machine/*.mk` (default: `native`)
- `EXTRAS` — optional features, e.g. `debug`, `clang`, `asan`, `fuzz`, `llvm-cov`
- `BUILDDIR` — output directory (default: `build/`)

Example: `make -j EXTRAS="debug clang" MACHINE=linux_clang_x86_64`

## Running Tests

```bash
# Run all unit tests
contrib/test/run_unit_tests.sh

# Run integration tests (requires sudo, modifies system)
sudo contrib/test/run_integration_tests.sh

# Run test vectors
contrib/test/run_test_vectors.sh

# Build then run a single unit test binary directly
make -j && build/native/gcc/unit-test/test_<name>
```

The unit test runner is NUMA-aware and runs tests in parallel. Integration tests run sequentially and may modify system configuration.

## Auto-generated Code

Do not edit generated files directly — regenerate them instead.

- **Metrics:** After changing `metrics.xml`, run:
  ```bash
  make -C src/disco/metrics metrics
  ```
  Regenerates all files in `src/disco/metrics/generated/` and `book/api/metrics-generated.md`.

- **Features:** After changing `feature_map.json`, run:
  ```bash
  cd src/flamenco/features && make generate
  ```
  Regenerates `fd_features_generated.h` and `fd_features_generated.c`.

- **Types:** After changing `fd_types.json`, run:
  ```bash
  cd src/flamenco/types && make stubs
  ```
  Regenerates `fd_types.h` and `fd_types.c`.

## Fuzzing

```bash
# Build fuzzer
make -j CC=clang EXTRAS=fuzz BUILDDIR=clang-fuzz

# Build coverage report
make -j CC=clang EXTRAS=llvm-cov BUILDDIR=clang-cov

# Start fuzzing
CORPUS=/data/corpus/my_fuzzer
mkdir $CORPUS
build/clang-fuzz/fuzz-test/my_fuzzer $CORPUS -timeout=3

# View coverage report
./contrib/test/single_test_cov.sh build/clang-cov/fuzz-test/my_fuzzer $CORPUS
python3 -m http.server 12000
```

## Architecture

### Tile-Based IPC Model

The core design uses **tiles** — single-threaded processes communicating via shared memory. Each tile runs in a seccomp sandbox with an installed syscall allowlist.

**Tango** (`src/tango/`) is the IPC framework:
- `mcache/` — metadata cache for passing transaction/shred descriptors between tiles
- `dcache/` — data cache holding the actual payload chunks
- `fseq/` / `fctl/` — sequence numbers and flow control
- `cnc/` — control channel for tile lifecycle management

**Disco** (`src/disco/`) builds on Tango with higher-level tile logic:
- Network ingestion (QUIC, UDP), deduplication, SigVerify, pack, bank, PoH, shred
- Metrics collection (`src/disco/metrics/`)
- Tile scheduling and topology infrastructure

### Source Directory Map

| Directory | Purpose |
|-----------|---------|
| `src/app/` | Binary entry points: `firedancer/`, `fdctl/`, `fddev/`, `fddbg/` |
| `src/ballet/` | Cryptographic primitives (Ed25519, SHA-256/512, Blake3, shred encoding) |
| `src/disco/` | Shared tile logic (networking, verification, metrics, GUI) |
| `src/discof/` | Firedancer-only tiles (replay, gossip, repair, tower) |
| `src/discoh/` | Frankendancer-only tiles (Agave FFI shim) |
| `src/flamenco/` | Execution engine: VM (`src/flamenco/vm/`), runtime, account DB, program cache, types, features |
| `src/funk/` | Key-value store used by the account database |
| `src/tango/` | Low-level IPC primitives (mcache, dcache, fseq, fctl, cnc) |
| `src/util/` | Foundational utilities: allocators, logging, math, SIMD, net, sandbox |
| `src/wiredancer/` | FPGA acceleration (AWS-F1 SigVerify) |

### Key Design Patterns

- **No `stdint.h` types** — use `fd_util_base.h` types instead (`ulong` not `uint64_t`, `uint` not `uint32_t`, etc.)
- **No `stdbool.h`** — use `int` with `0`/`1`
- **`FD_LIKELY` / `FD_UNLIKELY`** — annotate branch prediction hints; always wrap error paths with `FD_UNLIKELY`
- **Include guards** — use `#ifndef HEADER_fd_src_path_to_file_fd_file_name_h` style, not `#pragma once`
- **`fd_io`** over `stdio.h` for streaming file I/O
- Prefer `do { ... } while(0)` scopes to avoid resource leaks on complex exit paths (see `CONTRIBUTING.md` §8.2)

## Code Style

The authoritative style reference is `src/tango`. Key rules are documented in `CONTRIBUTING.md`:
- Vertical alignment for declarations and `#define` tables
- Spaces inside `if(` / `for(` brackets; no space before bracket
- Return type and modifiers on a separate line from the function name
- One argument per line in function prototypes, vertically aligned
- Comment text wraps at 72 columns; documentation comment precedes the prototype
