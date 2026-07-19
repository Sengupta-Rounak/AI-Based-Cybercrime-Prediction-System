# Live Monitoring Guide

The Live Monitoring workspace continuously scores prepared timestamped network windows every two seconds. It displays the current attack status, 5-, 10-, and 30-second probabilities, selected horizon, risk score, priority, recommended action, and strongest precursor features.

## Status meanings

- **No Threat** — no horizon crossed its warning threshold.
- **Threat Under Review** — probability is close to a threshold or confidence is insufficient.
- **Predicted attack type** — one or more horizons crossed the warning threshold and the type classifier returned a sufficiently confident class.

## Important limitation

The bundled monitor is a continuous temporal replay of `data/processed/universal_pre_attack_windows.csv`. It does not capture live packets directly. PCAP and CSV files can be audited in Data Workspace, but supervised use requires reliable labels and timestamp alignment.
