# SM9 precomputation admission and queueing boundaries

This repository archives the numerical evidence and code for *Admission and Queueing Boundaries for SM9 Verification Precomputation*. It includes the earlier calibration and R2 results plus the single-host R3 extension: hot-set/scan sensitivity, deadline curves, held-out offline policy selection, near-tie cost maps, joint calibration/trace bootstrap and Python metadata allocation.

This is a calibration-driven single-server simulation study. No six-machine cluster is required. Each calibration process ran on the same host; simulation seeds and bootstrap replicates are not additional hardware experiments.

## Reproduce

Use Python 3.12 (tested with 3.12.14), NumPy 2.3.5 and Matplotlib 3.11.2:

```sh
git clone https://github.com/magyyds/sm9-precomputation-boundaries.git
cd sm9-precomputation-boundaries
python -m pip install -r requirements-reproduction.txt
python verify_publication.py
python reproduce_round3.py
python reproduce_hotset_extension.py
python plot_compact_figure.py
```

Alternatively download and extract the current source ZIP. The v3.0.0 tag/release preserves the earlier R3 snapshot and does not include the interior hot-set extension. Installing Python/dependencies may require network access; after installation, simulation and plotting use the included inputs offline. Windows users may run `START_LOCAL.ps1`.

`reproduce_round3.py` verifies its input hashes, writes to a new directory, recomputes the R3 extension, checks the queues and held-out decisions, redraws the three new figures and compares deterministic CSVs/plotting values against this archive. The reference full reproduction passed; `reproduction_round3_check.json` records the comparisons. Python allocation byte peaks are new allocator observations; event counts are checked exactly. `--no-plots` skips rendering while retaining the archived plotting values. Do not change seeds or calibration and expect the same reference hashes.

`reproduce.py` reruns the baseline/R2 numerical analyses and the seven earlier figures; [baseline instructions](README_v2.md) describe optional cryptographic remeasurement. Neither default entry point remeasures crypto timings. `python verify_round3.py` checks the retained R3 results without rerunning the full bootstrap.

## Interior hot-set extension

The current main branch also includes the four added hot-set ratios (3,240 new evaluations), all 2,430 anchor rechecks, paired intervals and 630 retained identity/arrival arrays. [Extension documentation](hotset_extension/README.md) maps these files to Section 4.5 and Supplementary Table S9. `reproduce_hotset_extension.py` verifies their hashes and reproduces every retained numerical outcome in a new directory. `plot_compact_figure.py` recreates the single-column Fig. 2 from unchanged numerical source data.

## Data and figure map

| Material | Location |
|---|---|
| Original calibration and process provenance | `revision_measurements/`, `calibration/`, `measurement_backend/` |
| Baseline and R2 run-level results | `revision_results/`, `round2_results/` |
| R3 run-level records, summaries, configuration and verification | `round3_results/` |
| Identity, arrival, empirical service and bootstrap arrays | `traces/`, `revision_traces/`, `round2_traces/`, `round3_traces/` |
| Added interior hot-set records, inputs and paired intervals | `hotset_extension/retained_results/` |
| Compact Fig. 2 and plotting values | `hotset_extension/compact_figure/` |
| Extension hashes and reproduction check | `hotset_extension/manifest.json`, `hotset_extension/reproduction_check.json` |
| Baseline/R2/R3 combined numerical export | `round3_experiment_data.json` |
| Plotting source values | `revision_figure_source_data.json`, `round3_figure_source_data.json` |
| Five main and five supplementary figure exports | `revision_figures/` (600 dpi PNG, PDF, SVG) |
| Plotting scripts | `plot_revision_figures.py`, `plot_round3_figures.py` |
| Input and full archive hashes | `input_manifest.json`, `round3_input_manifest.json`, `publication_manifest.json` |

The baseline/R2/R3 JSON contains the run/summary tables, the 12 raw calibration records and all ten manuscript figures' source values. It indexes **1,206 external NPZ files** by relative path, byte size and SHA-256. JSON alone supports plotting of the stored numerical results; exact experiment replay also requires the external arrays. `revision_experiment_data.json` is the preserved baseline/R2 snapshot.

R3 counts: 2,430 hot-set/scan queue evaluations; 450 deadline queue paths with 1,800 threshold readouts; 540 held-out trace–capacity decisions from 30 held-out seed blocks (3,240 candidate costs); two arrival conventions with 10,000 joint bootstrap replicates each; four near-tie cost grids; 1,080 Python metadata traces. Units, seeds, cost normalization and arrival conventions are recorded in the configuration and CSV headers. A 0.01-percentage-point near-best tolerance is descriptive, not a statistical equivalence test.

## Version and citation

Use the current main branch for the complete revised evidence, including the interior hot-set extension. Record the Git commit when citing or reproducing this version. The **v3.0.0** tag/release preserves the prior R3 snapshot; v2.0.0 preserves baseline/R2. `CITATION.cff` supplies the study title and author order. No DOI has been assigned by this repository. The release includes an archive with a SHA-256 checksum; the Git commit identifies the exact tree. Third-party source notices in `measurement_backend/` remain unchanged.
