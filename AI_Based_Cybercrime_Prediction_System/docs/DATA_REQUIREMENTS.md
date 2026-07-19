# Data Requirements

## Network forecasting

Mandatory:

- timestamp
- verified attack label or attack schedule

Strongly recommended:

- source and destination IP
- source and destination port
- protocol
- flow duration
- packets and bytes per second
- packet-length statistics
- SYN, ACK, and RST counts
- forward and backward packet counts

Raw PCAP captures are unlabelled unless aligned with a verified attack schedule. Train, validation, and test periods must be chronological and separated to prevent overlapping-window leakage.

## Incident-text prediction

Prediction requires one narrative field such as `summary`, `incident_text`, `description`, `report_text`, `text`, or `message`.

Training and evaluation additionally require verified labels. Recommended provenance fields are record ID, incident date, source, campaign ID, and a synthetic/real flag. IDs, dates, sources, hashes, and split metadata must not be used as predictive text features.

## Real-world evaluation

Use an independently sourced labelled test set, remove duplicates and source overlap, preserve complete campaigns, and report per-class metrics, calibration, abstention rate, and known coverage limitations.
