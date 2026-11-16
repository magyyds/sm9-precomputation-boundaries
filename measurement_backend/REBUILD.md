# Optional Linux source rebuild

The supplied binary measurement route was smoke-tested under Ubuntu22.04/WSL2 on x86-64. To build from the retained source, use a copy of this backend directory and a C compiler plus CMake >=3.16:

```text
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target siap_crypto kernel bridge -j 4
```

The targets place `libsiap_crypto.so` in `build/`, the pinned GmSSL library in `build/vendor/gmssl-src/bin/`, and `kernel.so`/`bridge.so` beside their Python adapters. `measure_revision.py` explicitly preloads `libgmssl.so.3.3` and then uses these relative paths. Run `remeasure.py` from the parent capsule to keep a new measurement archive separate. This rebuild target set is limited to the dependencies used in this revision; it does not build the larger project's network simulators.

The supplied original binaries and a new build may differ in compiler flags and timing. Record the new source/library hashes and environment with the new measurement output instead of treating a remeasurement as identical to the retained calibration.
