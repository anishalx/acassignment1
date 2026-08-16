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
| timestamp | 2026-08-16 20:29:33 |
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

- Median across all 72 measurements: **1.05x**
- Worst five: chacha20-poly1305/recover/1 KiB 2.11x, chacha20-poly1305/seal/1 KiB 2.10x, chacha20-poly1305/open/1 KiB 2.05x, aes-gcm/protect/4 KiB 2.03x, aes-gcm/seal/1 KiB 2.01x

Differences smaller than the residual spread should not be read as
real; the conclusions drawn in the report rest on ratios well above it.

## Required sizes (TR-8 minimum)

Full subsystem path, i.e. what an application actually pays.

| Record size | Operation | AES-GCM | ChaCha20-Poly1305 | Faster | Margin |
|---|---|---|---|---|---|
| 64 B | protect | 5.53 us (11 MiB/s) | 5.72 us (11 MiB/s) | AES-GCM | 1.04x |
| 64 B | recover | 7.30 us (8 MiB/s) | 7.67 us (8 MiB/s) | AES-GCM | 1.05x |
| 1 KiB | protect | 6.38 us (153 MiB/s) | 7.40 us (132 MiB/s) | AES-GCM | 1.16x |
| 1 KiB | recover | 8.48 us (115 MiB/s) | 8.88 us (110 MiB/s) | AES-GCM | 1.05x |
| 64 KiB | protect | 18.37 us (3,402 MiB/s) | 36.61 us (1,707 MiB/s) | AES-GCM | 1.99x |
| 64 KiB | recover | 23.80 us (2,626 MiB/s) | 41.49 us (1,506 MiB/s) | AES-GCM | 1.74x |

## All measured sizes

### Protection (sender)

| Record size | AES-GCM us/rec | AES-GCM MiB/s | ChaCha20 us/rec | ChaCha20 MiB/s | Ratio (ChaCha/AES) |
|---|---|---|---|---|---|
| 16 B | 5.349 | 3 | 5.606 | 3 | 1.05x |
| 64 B | 5.527 | 11 | 5.725 | 11 | 1.04x |
| 256 B | 5.789 | 42 | 6.009 | 41 | 1.04x |
| 1 KiB | 6.381 | 153 | 7.403 | 132 | 1.16x |
| 4 KiB | 6.695 | 583 | 7.847 | 498 | 1.17x |
| 16 KiB | 9.127 | 1,712 | 13.762 | 1,135 | 1.51x |
| 64 KiB | 18.372 | 3,402 | 36.613 | 1,707 | 1.99x |
| 256 KiB | 69.606 | 3,592 | 146.260 | 1,709 | 2.10x |
| 1 MiB | 794.842 | 1,258 | 1076.427 | 929 | 1.35x |

### Recovery (receiver)

| Record size | AES-GCM us/rec | AES-GCM MiB/s | ChaCha20 us/rec | ChaCha20 MiB/s | Ratio (ChaCha/AES) |
|---|---|---|---|---|---|
| 16 B | 7.222 | 2 | 7.658 | 2 | 1.06x |
| 64 B | 7.296 | 8 | 7.671 | 8 | 1.05x |
| 256 B | 7.729 | 32 | 7.934 | 31 | 1.03x |
| 1 KiB | 8.484 | 115 | 8.884 | 110 | 1.05x |
| 4 KiB | 8.876 | 440 | 10.175 | 384 | 1.15x |
| 16 KiB | 12.117 | 1,290 | 16.381 | 954 | 1.35x |
| 64 KiB | 23.800 | 2,626 | 41.493 | 1,506 | 1.74x |
| 256 KiB | 73.939 | 3,381 | 148.560 | 1,683 | 2.01x |
| 1 MiB | 817.372 | 1,223 | 1192.911 | 838 | 1.46x |

## Subsystem overhead over the bare AEAD call

Difference between the full path and the raw primitive: nonce
allocation, header build/parse, binding checks and the replay window.

| Record size | AES-GCM protect | AES-GCM recover | ChaCha20 protect | ChaCha20 recover |
|---|---|---|---|---|
| 16 B | +3.803 us (71%) | +5.659 us (78%) | +3.886 us (69%) | +5.927 us (77%) |
| 64 B | +3.948 us (71%) | +5.679 us (78%) | +3.969 us (69%) | +5.888 us (77%) |
| 256 B | +4.167 us (72%) | +6.035 us (78%) | +4.086 us (68%) | +5.929 us (75%) |
| 1 KiB | +4.530 us (71%) | +6.592 us (78%) | +5.129 us (69%) | +6.563 us (74%) |
| 4 KiB | +4.258 us (64%) | +6.516 us (73%) | +4.280 us (55%) | +6.563 us (65%) |
| 16 KiB | +4.536 us (50%) | +7.521 us (62%) | +4.497 us (33%) | +7.053 us (43%) |
| 64 KiB | +5.419 us (29%) | +10.911 us (46%) | +5.073 us (14%) | +9.858 us (24%) |
| 256 KiB | +22.485 us (32%) | +27.124 us (37%) | +25.722 us (18%) | +28.472 us (19%) |
| 1 MiB | +335.444 us (42%) | +361.725 us (44%) | +346.500 us (32%) | +441.448 us (37%) |

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
| 16 B | seal | 10 MiB/s | 8 MiB/s | 1.26x slower | 9 -> 8 MiB/s |
| 16 B | open | 10 MiB/s | 8 MiB/s | 1.29x slower | 9 -> 8 MiB/s |
| 64 B | seal | 39 MiB/s | 26 MiB/s | 1.50x slower | 35 -> 34 MiB/s |
| 64 B | open | 38 MiB/s | 25 MiB/s | 1.49x slower | 34 -> 33 MiB/s |
| 256 B | seal | 150 MiB/s | 87 MiB/s | 1.74x slower | 127 -> 125 MiB/s |
| 256 B | open | 144 MiB/s | 86 MiB/s | 1.68x slower | 122 -> 123 MiB/s |
| 1 KiB | seal | 528 MiB/s | 172 MiB/s | 3.07x slower | 429 -> 383 MiB/s |
| 1 KiB | open | 516 MiB/s | 163 MiB/s | 3.16x slower | 421 -> 382 MiB/s |
| 4 KiB | seal | 1,603 MiB/s | 223 MiB/s | 7.18x slower | 1,095 -> 1,093 MiB/s |
| 4 KiB | open | 1,655 MiB/s | 222 MiB/s | 7.44x slower | 1,081 -> 1,085 MiB/s |
| 16 KiB | seal | 3,404 MiB/s | 242 MiB/s | 14.08x slower | 1,687 -> 1,694 MiB/s |
| 16 KiB | open | 3,400 MiB/s | 242 MiB/s | 14.06x slower | 1,675 -> 1,684 MiB/s |
| 64 KiB | seal | 4,825 MiB/s | 247 MiB/s | 19.56x slower | 1,982 -> 1,984 MiB/s |
| 64 KiB | open | 4,849 MiB/s | 248 MiB/s | 19.53x slower | 1,976 -> 1,994 MiB/s |
| 256 KiB | seal | 5,306 MiB/s | 249 MiB/s | 21.29x slower | 2,074 -> 2,046 MiB/s |
| 256 KiB | open | 5,340 MiB/s | 249 MiB/s | 21.43x slower | 2,082 -> 2,069 MiB/s |
| 1 MiB | seal | 2,177 MiB/s | 225 MiB/s | 9.67x slower | 1,370 -> 1,252 MiB/s |
| 1 MiB | open | 2,195 MiB/s | 223 MiB/s | 9.82x slower | 1,331 -> 1,271 MiB/s |

