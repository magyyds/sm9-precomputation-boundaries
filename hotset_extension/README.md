# Interior hot-set simulation extension

This directory supplies the additional experiments in Section 4.5 and Supplementary
Section S12/Table S9, including the four interior ratios H/K = 1.125, 1.25, 1.5 and 1.75.
The simulations retain the original calibration and contain no new hardware timings.

## Reproduce and verify

From the repository root, install `requirements-reproduction.txt`, then run:

```sh
python verify_publication.py
python reproduce_hotset_extension.py
python plot_compact_figure.py
```

`reproduce_hotset_extension.py` verifies all extension/input hashes, computes in a new
temporary directory, compares all three CSVs byte-for-byte and checks array equality
for all 630 identity/arrival files. `--output NEW_DIRECTORY` chooses a destination.
`--verify-only` checks the retained evidence without repeating the simulations.
The script reports the result directory and writes `reproduction_check.json` there.
The numerical extension needs only Python and NumPy; figure reproduction additionally
needs Matplotlib. The root requirements file pins the tested dependencies.

## Design and files

- K = 8; H = 4, 8, 9, 10, 12, 14, 16; scan shares 0.10, 0.20, 0.40.
- Reference loads 0.90, 0.95, 1.00; Q-only, Second-hit, and Window-Frequency (1,024 requests).
- Thirty paired seeds, 271101–271130, with 4,096 messages per trace.
- The four new H values add 3,240 evaluations; the original values supply 2,430 rechecks.
- `retained_results/hotset_expanded_runs.csv` contains all 5,670 run records.
- `retained_results/hotset_expanded_summary.csv` contains per-policy seed summaries.
- `retained_results/hotset_expanded_paired.csv` contains every paired contrast at all loads.
- `retained_results/trace_*.npz` retains 630 arrays of identities and unit arrival gaps.
- `retained_results/verification.json` records design, runtime, queue checks and original input hashes.
- `reproduction_check.json` records the verified repository-entry-point reproduction.
- `compact_figure/` retains compact Fig. 2, its numerical source and layout checks.
- `manifest.json` records SHA-256 hashes of required inputs, scripts and retained evidence.

All policies within a cell share the same identity and arrival trace. Non-centre cells
use the original shared-uniform generator; H = 8 with 20% scans retains its original
mixed-scan trace. The additional points are simulated, not interpolated outcome values.
Integer H at fixed K does not establish a universal continuous crossover.

Paired Second-hit minus Window-Frequency differences use 10,000 percentile bootstrap
resamples of 30 seed blocks (seed 811610). Intervals are descriptive and pointwise;
no FWER or FDR adjustment is applied. The ±0.5-pp practical margin was adopted during
revision and is neither preregistered nor deployment-validated. The earlier 0.01-pp
plotting and selection tolerance is separate. No formal equivalence test is asserted.
