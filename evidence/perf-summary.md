# TR-8 Performance Evaluation

Protection and recovery of application records, AES-GCM against
ChaCha20-Poly1305 under identical conditions.

## Measurement environment

| Property | Value |
|---|---|
| cpu name | 12th Gen Intel(R) Core(TM) i5-12450H |
| processor | Intel64 Family 6 Model 154 Stepping 3, GenuineIntel |
| machine | AMD64 |
| cpu count | 12 |
| platform | Windows-11-10.0.26200-SP0 |
| python | 3.13.3 |
| implementation | CPython |
| cryptography | 43.0.3 |
| openssl | OpenSSL 3.3.2 3 Sep 2024 |
| process priority | default (unchanged) |
| cpu affinity | pinned to CPU 2 |
| timestamp | 2026-08-16 15:22:07 |
| batches per measurement | 18 (2 sweeps x 9; **minimum** reported) |
| configuration ordering | the two AEAD suites measured back to back |
| batch byte budget | 64 MiB |
| garbage collection | disabled across each timed region |

## Measurement stability

The figure reported everywhere below is the **fastest** of the
9 batches, not the mean or median. Benchmark interference is
one-sided -- preemption, cache eviction and clock dips can only add
time -- so the minimum is the least-contaminated estimate of the true
cost. This matters on this host in particular: it is a hybrid CPU with
performance and efficiency cores, and an unpinned thread migrating
between the two measures 2-3x apart, which is larger than the effect
being studied. The process is pinned to one core and raised in
priority for the same reason.

How much noise remained, as the ratio of the median batch to the
fastest batch (1.00 would mean a perfectly quiet host):

- Median across all 72 measurements: **1.16x**
- Worst five: chacha20-poly1305/open/1 MiB 1.43x, aes-gcm/open/1 MiB 1.41x, chacha20-poly1305/recover/1 MiB 1.39x, aes-gcm/seal/16 KiB 1.34x, chacha20-poly1305/recover/16 B 1.30x

Differences smaller than the residual spread should not be read as
real; the conclusions drawn in the report rest on ratios well above it.

## Required sizes (TR-8 minimum)

Full subsystem path, i.e. what an application actually pays.

| Record size | Operation | AES-GCM | ChaCha20-Poly1305 | Faster | Margin |
|---|---|---|---|---|---|
| 64 B | protect | 7.62 us (8 MiB/s) | 8.06 us (8 MiB/s) | AES-GCM | 1.06x |
| 64 B | recover | 10.48 us (6 MiB/s) | 10.64 us (6 MiB/s) | AES-GCM | 1.02x |
| 1 KiB | protect | 8.24 us (119 MiB/s) | 9.15 us (107 MiB/s) | AES-GCM | 1.11x |
| 1 KiB | recover | 10.95 us (89 MiB/s) | 11.57 us (84 MiB/s) | AES-GCM | 1.06x |
| 64 KiB | protect | 22.60 us (2,765 MiB/s) | 45.67 us (1,368 MiB/s) | AES-GCM | 2.02x |
| 64 KiB | recover | 28.21 us (2,216 MiB/s) | 50.11 us (1,247 MiB/s) | AES-GCM | 1.78x |

## All measured sizes

### Protection (sender)

| Record size | AES-GCM us/rec | AES-GCM MiB/s | ChaCha20 us/rec | ChaCha20 MiB/s | Ratio (ChaCha/AES) |
|---|---|---|---|---|---|
| 16 B | 6.713 | 2 | 6.979 | 2 | 1.04x |
| 64 B | 7.621 | 8 | 8.056 | 8 | 1.06x |
| 256 B | 7.916 | 31 | 8.452 | 29 | 1.07x |
| 1 KiB | 8.235 | 119 | 9.147 | 107 | 1.11x |
| 4 KiB | 7.584 | 515 | 9.238 | 423 | 1.22x |
| 16 KiB | 10.987 | 1,422 | 16.938 | 923 | 1.54x |
| 64 KiB | 22.602 | 2,765 | 45.674 | 1,368 | 2.02x |
| 256 KiB | 97.096 | 2,575 | 185.487 | 1,348 | 1.91x |
| 1 MiB | 902.923 | 1,108 | 1265.895 | 790 | 1.40x |

### Recovery (receiver)

| Record size | AES-GCM us/rec | AES-GCM MiB/s | ChaCha20 us/rec | ChaCha20 MiB/s | Ratio (ChaCha/AES) |
|---|---|---|---|---|---|
| 16 B | 9.555 | 2 | 8.986 | 2 | 0.94x |
| 64 B | 10.477 | 6 | 10.641 | 6 | 1.02x |
| 256 B | 10.689 | 23 | 11.070 | 22 | 1.04x |
| 1 KiB | 10.954 | 89 | 11.575 | 84 | 1.06x |
| 4 KiB | 10.152 | 385 | 11.663 | 335 | 1.15x |
| 16 KiB | 13.880 | 1,126 | 19.621 | 796 | 1.41x |
| 64 KiB | 28.207 | 2,216 | 50.111 | 1,247 | 1.78x |
| 256 KiB | 85.233 | 2,933 | 174.013 | 1,437 | 2.04x |
| 1 MiB | 1034.589 | 967 | 1311.619 | 762 | 1.27x |

## Subsystem overhead over the bare AEAD call

Difference between the full path and the raw primitive: nonce
allocation, header build/parse, binding checks and the replay window.

| Record size | AES-GCM protect | AES-GCM recover | ChaCha20 protect | ChaCha20 recover |
|---|---|---|---|---|
| 16 B | +4.877 us (73%) | +7.643 us (80%) | +4.811 us (69%) | +6.783 us (75%) |
| 64 B | +5.432 us (71%) | +8.294 us (79%) | +5.602 us (70%) | +8.146 us (77%) |
| 256 B | +5.668 us (72%) | +8.398 us (79%) | +5.774 us (68%) | +8.387 us (76%) |
| 1 KiB | +5.757 us (70%) | +8.406 us (77%) | +6.082 us (66%) | +8.772 us (76%) |
| 4 KiB | +4.832 us (64%) | +7.375 us (73%) | +4.870 us (53%) | +7.296 us (63%) |
| 16 KiB | +5.334 us (49%) | +8.311 us (60%) | +5.593 us (33%) | +8.155 us (42%) |
| 64 KiB | +6.859 us (30%) | +12.491 us (44%) | +7.362 us (16%) | +11.821 us (24%) |
| 256 KiB | +39.075 us (40%) | +27.657 us (32%) | +39.107 us (21%) | +26.107 us (15%) |
| 1 MiB | +364.008 us (40%) | +520.017 us (50%) | +352.944 us (28%) | +409.034 us (31%) |

## Hardware acceleration: AES-GCM with AES-NI disabled

Re-measured in a child process with `OPENSSL_ia32cap=~0x200000200000000:~0x0`,
which clears the AES-NI and PCLMULQDQ feature bits so OpenSSL falls back
to its software AES and GHASH paths. ChaCha20-Poly1305 uses neither
instruction, so its column is the control: it should barely move, and
the extent to which it does not is what licenses reading the AES-GCM
change as an AES-NI effect rather than a change in the machine.

The `:~0x0` suffix on the mask matters. Without it OpenSSL also zeroes
the CPUID leaf-7 feature words, disabling AVX2 -- which ChaCha20's fast
path uses -- and the control then drops by nearly half, making AES-GCM's
relative loss look smaller than it is. See the note in `bench/perf.py`.

| Record size | Operation | AES-GCM (AES-NI) | AES-GCM (software) | Slowdown | ChaCha20 (control) |
|---|---|---|---|---|---|
| 16 B | seal | 8 MiB/s | 6 MiB/s | 1.33x slower | 7 -> 6 MiB/s |
| 16 B | open | 8 MiB/s | 6 MiB/s | 1.28x slower | 7 -> 5 MiB/s |
| 64 B | seal | 28 MiB/s | 16 MiB/s | 1.76x slower | 25 -> 25 MiB/s |
| 64 B | open | 28 MiB/s | 18 MiB/s | 1.59x slower | 24 -> 24 MiB/s |
| 256 B | seal | 109 MiB/s | 56 MiB/s | 1.92x slower | 91 -> 90 MiB/s |
| 256 B | open | 107 MiB/s | 60 MiB/s | 1.77x slower | 91 -> 88 MiB/s |
| 1 KiB | seal | 394 MiB/s | 112 MiB/s | 3.52x slower | 319 -> 315 MiB/s |
| 1 KiB | open | 383 MiB/s | 115 MiB/s | 3.32x slower | 348 -> 308 MiB/s |
| 4 KiB | seal | 1,419 MiB/s | 153 MiB/s | 9.30x slower | 894 -> 757 MiB/s |
| 4 KiB | open | 1,406 MiB/s | 144 MiB/s | 9.75x slower | 895 -> 763 MiB/s |
| 16 KiB | seal | 2,764 MiB/s | 169 MiB/s | 16.38x slower | 1,377 -> 1,163 MiB/s |
| 16 KiB | open | 2,806 MiB/s | 168 MiB/s | 16.73x slower | 1,363 -> 1,108 MiB/s |
| 64 KiB | seal | 3,970 MiB/s | 167 MiB/s | 23.84x slower | 1,631 -> 1,384 MiB/s |
| 64 KiB | open | 3,977 MiB/s | 172 MiB/s | 23.07x slower | 1,632 -> 1,353 MiB/s |
| 256 KiB | seal | 4,309 MiB/s | 143 MiB/s | 30.15x slower | 1,708 -> 1,350 MiB/s |
| 256 KiB | open | 4,342 MiB/s | 152 MiB/s | 28.57x slower | 1,690 -> 1,351 MiB/s |
| 1 MiB | seal | 1,856 MiB/s | 136 MiB/s | 13.63x slower | 1,095 -> 841 MiB/s |
| 1 MiB | open | 1,943 MiB/s | 141 MiB/s | 13.75x slower | 1,108 -> 795 MiB/s |

