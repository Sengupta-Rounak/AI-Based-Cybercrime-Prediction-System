# System Architecture

The application uses a portable local Python server and a browser-based interface.

## Network forecasting

A 91-feature temporal model scores recent traffic for 5-, 10- and 30-second attack horizons. It produces probability, risk, priority, attack type, precursor evidence and recommended actions.

## Text intelligence

A synthetic fallback classifier supports benign/threat workflow testing. A separate real incident multi-label classifier uses TF-IDF word and character features with one-vs-rest linear classifiers and label-specific thresholds. One narrative may receive several related incident labels.

## Data and evaluation

The Data Workspace audits CSV and PCAP files. Text Intelligence supports single and batch inference, evaluation and verified-data training. Reports expose only model metrics, model cards and essential technical documentation.
