# About the Model

The **AI Based Cybercrime Prediction System** uses a hybrid machine-learning architecture rather than a single model. It combines network-behaviour forecasting with incident-text intelligence so that structured traffic patterns and unstructured security narratives can be analysed within one local application.

The system currently contains three specialised model components:

1. **Network Pre-Attack Forecasting Model**
2. **Portable Single-Label Incident Text Classifier**
3. **Real Incident Multi-Label Classifier**

All inference is performed locally. The application does not require a cloud API, large language model, external database, or internet connection during normal use.

---

## 1. Network Pre-Attack Forecasting Model

### Objective

The network model estimates whether an attack may begin within the next:

- **5 seconds**
- **10 seconds**
- **30 seconds**

It is designed as a near-term forecasting component rather than a simple classifier of traffic that is already malicious.

### Input representation

Recent traffic is converted into rolling observation windows. Each window is represented through **91 engineered temporal features**, including:

- traffic volume and flow rate;
- source and destination diversity;
- source and destination concentration;
- port diversity and entropy;
- protocol entropy;
- packets and bytes per second;
- SYN, ACK, and RST behaviour;
- packet-length statistics;
- flow-duration statistics;
- forward and backward packet counts;
- temporal slopes;
- coefficients of variation;
- traffic burstiness;
- SYN-to-ACK, RST-to-ACK, and forward-to-backward ratios.

For major measurements, the feature pipeline calculates:

- mean;
- standard deviation;
- minimum;
- maximum;
- median;
- 95th percentile;
- temporal slope;
- coefficient of variation.

This gives the model information about both the current traffic level and the direction in which the traffic is changing.

### Architecture

The network model follows a two-stage design.

#### Stage 1: Attack-onset forecasting

A separate **Extra Trees classifier** is used for each prediction horizon.

Each classifier estimates:

```text
0 = no attack expected within the horizon
1 = attack expected within the horizon
```

The system therefore produces independent risk estimates for 5, 10, and 30 seconds.

#### Stage 2: Future attack-type classification

When the attack-onset probability crosses the configured warning threshold, a **Random Forest classifier** estimates the most likely future attack family.

Supported network categories include:

- bot activity;
- distributed denial of service;
- multiple denial-of-service variants;
- FTP and SSH credential attacks;
- heartbleed-style exploitation;
- infiltration;
- port scanning;
- web brute force;
- SQL injection;
- cross-site scripting.

When the attack-type confidence is too low, the model returns an unknown or review state rather than forcing a specific class.

### Output

The network model can return:

- attack probability;
- forecast horizon;
- risk level;
- warning priority;
- likely attack category;
- confidence score;
- contributing traffic indicators;
- suggested defensive action.

### Validation status

The bundled network model was trained and evaluated on controlled synthetic temporal traffic. Its recorded metrics demonstrate that the pipeline and interface operate correctly, but they must not be presented as proof of real-world network performance.

The network component should currently be described as a **research and demonstration forecasting model**.

---

## 2. Portable Single-Label Incident Text Classifier

### Objective

The portable text classifier assigns one category to an incident description. It supports:

- standard text prediction;
- binary benign-versus-malicious triage;
- batch CSV classification;
- the standard NLP Evaluation Lab;
- offline inference on low-resource computers.

### Algorithm

The classifier uses:

- **Multinomial Naive Bayes**
- word unigrams
- word bigrams
- Laplace smoothing

A unigram is a single word, such as:

```text
credential
ransomware
malware
```

A bigram is a two-word sequence, such as:

```text
password reset
encrypted files
failed login
```

The model learns how strongly each word or phrase is associated with the available incident classes.

### Supported categories

The portable classifier supports categories such as:

- benign;
- phishing;
- identity theft;
- account takeover;
- ransomware;
- malware;
- botnet;
- brute force;
- distributed denial of service;
- port scan;
- SQL injection;
- cross-site scripting.

### Confidence handling

The classifier uses a minimum confidence threshold and a review margin.

A result can be marked for review when:

- the highest probability is too low;
- the two strongest classes are too close;
- the text is too short;
- the wording is outside the model's familiar vocabulary.

This reduces the risk of presenting an uncertain prediction as a definitive conclusion.

### Validation status

The portable text classifier was trained and tested using synthetic incident narratives. It is useful for:

- software testing;
- demonstrations;
- interface validation;
- offline fallback prediction;
- evaluation workflow testing.

Its synthetic accuracy must not be represented as operational real-world performance.

---

## 3. Real Incident Multi-Label Classifier

### Objective

Real cybersecurity incidents often involve several connected attack behaviours.

For example:

```text
Phishing
   ↓
Credential compromise
   ↓
Account takeover
   ↓
Confidential-data exposure
```

A normal multiclass model must choose only one category. The multi-label model can assign several relevant categories to the same narrative.

### Text representation

The model converts each incident narrative into a sparse **TF-IDF** feature vector using:

- word unigrams;
- word bigrams;
- character trigrams;
- character four-grams;
- character five-grams.

The combined vocabulary contains approximately **24,000 text features**.

Word features capture meaningful security terms and phrases. Character features help recognise:

- spelling variations;
- technical abbreviations;
- compound security terms;
- uncommon tokens;
- partial word patterns;
- formatting differences.

### Classification architecture

The model uses a **one-vs-rest linear classification architecture**.

A separate binary classifier is trained for each category:

```text
Is this phishing?          Yes or No
Is this ransomware?       Yes or No
Is this account takeover? Yes or No
Is this a data breach?    Yes or No
```

Because each category is evaluated independently, multiple labels may be returned for one incident.

The classifiers use logistic decision functions trained through stochastic gradient optimisation. Label-specific thresholds are tuned on validation data rather than applying one universal threshold to every category.

### Primary categories

The strongest supported categories are:

- phishing;
- ransomware;
- malware;
- account takeover;
- web exploitation;
- social engineering;
- privilege misuse;
- data breach.

### Limited-evidence categories

The following categories are available but should be interpreted more conservatively:

- botnet or command-and-control activity;
- denial-of-service activity;
- brute-force activity;
- port scanning;
- SQL injection;
- cross-site scripting.

These labels contain fewer validation and test examples and therefore use stricter decision thresholds.

### Training and validation design

The model was trained using verified real incident narratives.

The data was divided chronologically into:

| Partition | Records |
|---|---:|
| Training | 4,624 |
| Validation | 1,073 |
| Testing | 1,186 |

The validation partition was used for:

- threshold selection;
- calibration decisions;
- model selection;
- review-state tuning.

The later chronological test partition was reserved for final internal evaluation.

### Internal chronological performance

| Metric | Result |
|---|---:|
| Primary-label micro-F1 | **0.7650** |
| Primary-label macro-F1 | **0.6186** |
| Sample-level F1 | **0.7843** |
| Mean average precision | **0.6830** |
| Exact multi-label match | **0.3929** |
| Hamming loss | **0.1176** |

These metrics represent an **internal chronological evaluation**. They do not yet constitute independent external validation.

### Review and out-of-scope detection

The model checks how much of a submitted narrative is represented in its known vocabulary.

A prediction may be marked as:

- `REVIEW`
- `UNCLASSIFIED_INCIDENT`

when:

- no category crosses its threshold;
- lexical coverage is very low;
- the narrative is unrelated to the training domain;
- evidence is insufficient;
- multiple uncertain categories compete closely.

This abstention behaviour is intentional. It is safer to request analyst review than to force a misleading category.

### Explainability

The multi-label model can identify words and phrases that contributed most strongly to the predicted category.

For example, a ransomware prediction may be supported by terms such as:

```text
encrypted files
payment demand
backup deletion
```

These explanations are derived directly from model coefficients. They are not generated by a large language model.

---

## Why Classical Machine Learning Was Used

The system uses classical machine-learning models because they are:

- fast on ordinary computers;
- suitable for structured network features;
- effective for sparse text representations;
- compatible with Windows x64 and ARM64;
- small enough to distribute with the application;
- capable of local and offline inference;
- easier to inspect and explain;
- independent of paid cloud services;
- suitable for reproducible academic evaluation.

The system does not depend on ChatGPT, Gemini, Claude, or another generative AI API for prediction.

---

## Model Usage by Interface Module

| Interface module | Model used |
|---|---|
| Live Monitoring | Network Extra Trees and Random Forest ensemble |
| Network Forecasting | Network Extra Trees and Random Forest ensemble |
| Standard Text Prediction | Portable Multinomial Naive Bayes classifier |
| NLP Evaluation Lab | Portable single-label text classifier |
| Multi-Label Incident Intelligence | TF-IDF one-vs-rest linear classifier |
| Multi-Label Evaluation | Real incident multi-label classifier |

---

## Scientific Status

The three model components have different levels of evidence.

| Component | Scientific status |
|---|---|
| Network forecasting model | Synthetic research demonstration |
| Portable single-label text classifier | Synthetic fallback and workflow-testing model |
| Real incident multi-label classifier | Real-data trained with internal chronological evaluation |

The real incident multi-label classifier is the strongest evidence-backed component. However, it still requires evaluation on a separately sourced and independently labelled external dataset before it can be described as externally validated.

---

## Current Limitations

- The network model has not yet been validated on independent real timestamped attack-onset traffic.
- The portable single-label classifier is based on synthetic narratives.
- The multi-label model has internal chronological testing but no independent external validation.
- Genuine benign operational reports are not sufficiently represented in the real incident model.
- Some categories contain limited evidence.
- Performance may change across organisations, sectors, languages, and reporting styles.
- The system does not identify criminals or establish intent, responsibility, or legal guilt.
- Predictions require qualified human review before operational or consequential action.

---

## Intended Use

The system is intended for:

- cybersecurity research;
- academic projects;
- defensive analytics;
- incident triage;
- model evaluation;
- dataset auditing;
- controlled demonstrations;
- analyst decision support.

It should not be used as the sole basis for:

- legal conclusions;
- public attribution;
- employee disciplinary action;
- destructive containment;
- account termination;
- accusations against individuals;
- automated emergency reporting.

---

## Model Summary

The AI Based Cybercrime Prediction System is best described as:

> A local hybrid cybersecurity research system combining multi-horizon network attack forecasting, portable incident-text classification, and real-data multi-label incident intelligence with confidence thresholds, abstention logic, explainable outputs, and human-review safeguards.

The project demonstrates how structured network telemetry and unstructured incident narratives can be analysed together without relying on cloud inference or generative AI services.
