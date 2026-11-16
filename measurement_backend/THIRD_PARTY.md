# Third party source

GmSSL: https://github.com/guanzhi/GmSSL

Commit: `24ae482701a7b124826c382fffc55c19f76d475d`

Copyright 2014–2024 The GmSSL Project. Distributed under Apache License 2.0;
see `vendor/gmssl-src/LICENSE` for the full license and individual source files
for their copyright notices. The verification equation in `native/crypto.c`
is adapted from `src/sm9_sign.c` under the same license. GmSSL source is unmodified.
`vendor-lock.json` records the SHA-256 of every distributed upstream file.

The Python test extraction vector is transcribed from the pinned upstream
`tests/sm9test.c` constants `hex_ks` and `hex_ds` for identity `Alice`.
This provenance does not assert that the complete implementation is certified.

OpenSSL 3 is linked from the host system by `native/x509.c` (Apache-2.0).
Documentation: https://docs.openssl.org/3.0/man7/EVP_PKEY-SM2/
No OpenSSL binary or source is redistributed in the source archive.

Optional Eclipse SUMO 1.28.0 is installed locally from the PyPI `eclipse-sumo`
wheel with a pinned SHA-256 in `scripts/install_sumo.py`. Consult the installed
distribution for its complete license notices. The runtime is excluded from
the source archive. `examples/sumo` contains generated experiment inputs and
outputs, with provenance recorded alongside the trace.

gmalg 1.1.2 (https://github.com/ww-rm/gmalg), MIT, is vendored under
`vendor/gmalg-python` with its license and metadata. `gmalg-lock.json` records
the pinned wheel digest and distributed file digests. It is used only for
independent correctness tests, not receiver timing.

`native/miller.c` adapts the optimal-Ate loop structure from the pinned GmSSL
`src/sm9_z256.c` (Apache-2.0), separating Q-only line coefficients.

Optional ns-3 3.44.post0 (GPL-2.0-only) and Memray 1.20.0 (Apache-2.0), with
their wheel dependencies, are confined to `.runtime` and excluded from the
source package. The pinned wheel URLs and digests are in
`optional-runtime-lock.json`. Their installed distributions contain license
notices. `native/wireless.cc` is a simulation driver linking to ns-3, not a
redistribution of the simulator binary.
