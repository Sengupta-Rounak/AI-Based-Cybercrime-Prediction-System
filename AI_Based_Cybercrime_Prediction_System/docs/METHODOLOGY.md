# Model Methodology

## Network model

The network pipeline creates sliding temporal windows, engineers 91 traffic features and produces independent 5-, 10- and 30-second forecasts. Time-ordered evaluation and uncertainty states are used to reduce leakage and overconfident warnings.

## Real incident classifier

Verified incident narratives were cleaned, deduplicated and split chronologically. The classifier uses word unigrams, word bigrams and character 3-5 grams with one-vs-rest linear models. Label-specific thresholds were selected from validation data. Multiple incident labels may be returned for one narrative.

## Scientific limits

Internal chronological holdout results are not independent external validation. Rare classes remain experimental. The real incident corpus contains confirmed incidents rather than genuine benign operational narratives, so a separate benign dataset is required for a defensible threat-versus-no-threat evaluation.
