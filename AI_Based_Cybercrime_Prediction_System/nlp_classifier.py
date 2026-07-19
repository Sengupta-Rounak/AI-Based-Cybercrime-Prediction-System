from __future__ import annotations

import csv
import gzip
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

TOKEN_RE = re.compile(r"[a-z][a-z0-9_-]{1,}")
URL_RE = re.compile(r"https?://\S+|www\.\S+", re.I)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w.-]+\.\w+\b", re.I)
NUMBER_RE = re.compile(r"\b\d+(?:\.\d+)?\b")
NON_ALNUM_RE = re.compile(r"[^a-z0-9_ ]+")
SPACE_RE = re.compile(r"\s+")

STOPWORDS = {
    "the", "a", "an", "and", "or", "to", "of", "in", "on", "for", "with", "from", "by", "at",
    "as", "is", "was", "were", "be", "been", "being", "that", "this", "it", "its", "their", "they",
    "them", "after", "before", "through", "into", "no", "not", "could", "would", "should", "had", "has",
    "have", "within", "without", "while", "when", "which", "who", "during", "than", "then", "also",
}

DEFAULT_ACTIONS = {
    "BENIGN": "No immediate intervention is required. Continue routine monitoring and preserve normal audit logs.",
    "PHISHING": "Quarantine the message, block the sender and linked domain, reset exposed credentials, and notify affected users.",
    "IDENTITY_THEFT": "Lock affected profiles, verify the victim through a trusted channel, preserve evidence, and notify the relevant fraud team.",
    "ACCOUNT_TAKEOVER": "Terminate active sessions, reset credentials, restore multifactor authentication, and review recent account changes.",
    "RANSOMWARE": "Isolate affected systems, protect offline backups, preserve forensic evidence, and activate the ransomware response plan.",
    "MALWARE": "Isolate the endpoint, block observed indicators, run forensic triage, and inspect persistence mechanisms.",
    "BOTNET": "Isolate suspected devices, block command-and-control indicators, and inspect peer systems for similar beaconing.",
    "DDOS": "Apply rate limiting and upstream filtering, protect the targeted service, and validate capacity and failover controls.",
    "PORT_SCAN": "Review the source and targeted services, restrict unnecessary ports, and correlate the activity with firewall telemetry.",
    "BRUTE_FORCE": "Rate-limit authentication, lock or protect targeted accounts, require strong MFA, and review successful logins.",
    "SQL_INJECTION": "Block the request pattern, review parameterised queries, enable relevant WAF controls, and inspect database access logs.",
    "XSS": "Block the payload, apply output encoding and CSP controls, and review stored or reflected user input paths.",
}

DEFAULT_SEVERITY = {
    "BENIGN": "Low", "PHISHING": "High", "IDENTITY_THEFT": "Critical", "ACCOUNT_TAKEOVER": "Critical",
    "RANSOMWARE": "Critical", "MALWARE": "High", "BOTNET": "High", "DDOS": "Critical", "PORT_SCAN": "Medium",
    "BRUTE_FORCE": "High", "SQL_INJECTION": "Critical", "XSS": "High",
}


def _normalise_text(text: str) -> str:
    normalized = URL_RE.sub(" URLTOKEN ", str(text).lower())
    normalized = EMAIL_RE.sub(" EMAILTOKEN ", normalized)
    normalized = NUMBER_RE.sub(" NUMTOKEN ", normalized)
    normalized = NON_ALNUM_RE.sub(" ", normalized)
    return SPACE_RE.sub(" ", normalized).strip()


def token_features(text: str, profile: str = "word") -> list[str]:
    """Return portable sparse features.

    ``word`` preserves the original unigram/bigram model. ``robust`` adds
    character 3-5 grams, which is more tolerant of spelling variation,
    abbreviations and vendor-specific wording in real incident narratives.
    """
    normalized = _normalise_text(text)
    tokens = [t for t in TOKEN_RE.findall(normalized) if len(t) > 1 and t not in STOPWORDS]
    features = [f"u:{token}" for token in tokens]
    features.extend(f"b:{left}_{right}" for left, right in zip(tokens, tokens[1:]))
    if profile in {"robust", "word_char", "real_world"}:
        compact = "_".join(tokens)[:5000]
        for n in (3, 4, 5):
            limit = max(len(compact) - n + 1, 0)
            # Cap character features per document so extremely long reports do not dominate.
            step = max(1, math.ceil(limit / 1800)) if limit else 1
            for index in range(0, limit, step):
                gram = compact[index:index + n]
                if "__" not in gram and gram.strip("_"):
                    features.append(f"c{n}:{gram}")
    return features


def _softmax(scores: dict[str, float]) -> dict[str, float]:
    if not scores:
        return {}
    maximum = max(scores.values())
    exponentials = {label: math.exp(max(min(value - maximum, 700.0), -700.0)) for label, value in scores.items()}
    total = sum(exponentials.values()) or 1.0
    return {label: value / total for label, value in exponentials.items()}


def _metrics(y_true: list[str], y_pred: list[str], classes: list[str]) -> dict[str, Any]:
    accuracy = sum(a == b for a, b in zip(y_true, y_pred)) / max(len(y_true), 1)
    per_class: dict[str, Any] = {}
    macro_f1 = 0.0
    confusion = {actual: {predicted: 0 for predicted in classes} for actual in classes}
    for actual, predicted in zip(y_true, y_pred):
        confusion.setdefault(actual, {name: 0 for name in classes})
        confusion[actual][predicted] = confusion[actual].get(predicted, 0) + 1
    for label in classes:
        tp = sum(1 for a, b in zip(y_true, y_pred) if a == label and b == label)
        fp = sum(1 for a, b in zip(y_true, y_pred) if a != label and b == label)
        fn = sum(1 for a, b in zip(y_true, y_pred) if a == label and b != label)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        macro_f1 += f1
        per_class[label] = {"precision": precision, "recall": recall, "f1": f1, "support": sum(1 for value in y_true if value == label)}
    macro_f1 /= max(len(classes), 1)
    return {
        "records": len(y_true),
        "accuracy": accuracy,
        "macro_f1": macro_f1,
        "per_class": per_class,
        "confusion_matrix": confusion,
    }


class PortableTextClassifier:
    def __init__(self, model: dict[str, Any]):
        self.model = model
        self.classes = list(model["classes"])
        self.class_log_prior = {str(k): float(v) for k, v in model["class_log_prior"].items()}
        self.unknown_log_probability = {str(k): float(v) for k, v in model["unknown_log_probability"].items()}
        self.token_log_probabilities = model["token_log_probabilities"]
        self.confidence_threshold = float(model.get("confidence_threshold", 0.45))
        self.review_margin = float(model.get("review_margin", 0.12))
        self.class_thresholds = {str(k): float(v) for k, v in model.get("class_thresholds", {}).items()}
        self.ood_coverage_threshold = float(model.get("ood_coverage_threshold", 0.0))
        self.feature_profile = str(model.get("feature_profile", "word"))
        self.source_is_synthetic = bool(model.get("source_is_synthetic", True))
        self.validation_status = str(model.get("validation_status", "synthetic_demo"))
        self.actions = {**DEFAULT_ACTIONS, **model.get("actions", {})}
        self.severity = {**DEFAULT_SEVERITY, **model.get("severity", {})}

    @classmethod
    def load(cls, path: Path) -> "PortableTextClassifier":
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            return cls(json.load(handle))

    def predict(self, text: str, evidence_limit: int = 8) -> dict[str, Any]:
        text = str(text or "").strip()
        if len(text) < 8:
            raise ValueError("Enter a longer incident description before classification.")
        counts = Counter(token_features(text, self.feature_profile))
        total_feature_count = sum(counts.values())
        known_feature_count = sum(count for token, count in counts.items() if token in self.token_log_probabilities)
        lexical_coverage = known_feature_count / max(total_feature_count, 1)

        scores: dict[str, float] = {}
        for label in self.classes:
            score = self.class_log_prior[label]
            unknown = self.unknown_log_probability[label]
            for token, count in counts.items():
                token_scores = self.token_log_probabilities.get(token)
                score += count * float(token_scores.get(label, unknown) if token_scores else unknown)
            scores[label] = score
        probabilities = _softmax(scores)
        ordered = sorted(probabilities.items(), key=lambda item: item[1], reverse=True)
        predicted, confidence = ordered[0]
        runner_up = ordered[1][1] if len(ordered) > 1 else 0.0
        margin = confidence - runner_up
        required_confidence = self.class_thresholds.get(predicted, self.confidence_threshold)
        out_of_scope = self.ood_coverage_threshold > 0 and lexical_coverage < self.ood_coverage_threshold
        review = out_of_scope or confidence < required_confidence or margin < self.review_margin
        decision = "REVIEW" if review else ("NO_THREAT" if predicted == "BENIGN" else "THREAT_DETECTED")
        if out_of_scope:
            display_label = "Out-of-Scope Review"
        elif predicted == "BENIGN" and decision != "REVIEW":
            display_label = "No Threat"
        elif decision == "REVIEW":
            display_label = "Threat Under Review"
        else:
            display_label = predicted.replace("_", " ").title()

        evidence: list[dict[str, Any]] = []
        second_label = ordered[1][0] if len(ordered) > 1 else predicted
        for token, count in counts.items():
            token_scores = self.token_log_probabilities.get(token)
            if not token_scores:
                continue
            contribution = count * (
                float(token_scores.get(predicted, self.unknown_log_probability[predicted]))
                - float(token_scores.get(second_label, self.unknown_log_probability[second_label]))
            )
            if contribution > 0:
                term = token.split(":", 1)[1] if ":" in token else token
                evidence.append({"term": term.replace("_", " "), "contribution": contribution, "count": count})
        evidence.sort(key=lambda item: item["contribution"], reverse=True)

        if self.source_is_synthetic:
            note = "Synthetic fallback model; use a real-data model and external validation for operational conclusions. Model evidence is not proof of causation."
        elif self.validation_status == "externally_validated":
            note = "Real-data model with recorded external validation. Results remain domain-specific and require analyst review. Model evidence is not proof of causation."
        else:
            note = "Real-data model with internal validation only; an independent external dataset is still required. Model evidence is not proof of causation."

        return {
            "predicted_attack": predicted,
            "display_attack": display_label,
            "binary_label": "BENIGN" if predicted == "BENIGN" else "MALICIOUS",
            "confidence": confidence,
            "decision": decision,
            "margin": margin,
            "lexical_coverage": lexical_coverage,
            "out_of_scope": out_of_scope,
            "severity": self.severity.get(predicted, "Medium"),
            "recommended_action": self.actions.get(predicted, "Escalate the incident for analyst review."),
            "probabilities": [{"label": label, "probability": probability} for label, probability in ordered],
            "probability_map": dict(probabilities),
            "top3": [label for label, _ in ordered[:3]],
            "evidence": evidence[:evidence_limit],
            "model_note": note,
            "model_source": "synthetic" if self.source_is_synthetic else "real_data",
            "validation_status": self.validation_status,
        }

    def evaluate_rows(self, rows: Iterable[dict[str, str]], text_column: str, label_column: str) -> dict[str, Any]:
        y_true: list[str] = []
        y_pred: list[str] = []
        for row in rows:
            actual = str(row.get(label_column, "")).strip().upper().replace(" ", "_")
            if not actual:
                continue
            result = self.predict(str(row.get(text_column, "")))
            y_true.append(actual)
            y_pred.append(result["predicted_attack"])
        return _metrics(y_true, y_pred, self.classes)


def train_model(
    rows: list[dict[str, str]],
    text_column: str = "incident_text",
    label_column: str = "attack_type",
    *,
    alpha: float = 0.1,
    min_document_frequency: int = 1,
    max_features: int = 12000,
    feature_profile: str = "word",
    balanced_priors: bool = False,
) -> dict[str, Any]:
    class_documents: Counter[str] = Counter()
    document_frequency: Counter[str] = Counter()
    token_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        label = str(row.get(label_column, "")).strip().upper().replace(" ", "_")
        text = str(row.get(text_column, "")).strip()
        if not label or not text:
            continue
        counts = Counter(token_features(text, feature_profile))
        class_documents[label] += 1
        document_frequency.update(counts.keys())
        token_counts[label].update(counts)
    classes = sorted(class_documents)
    if len(classes) < 2:
        raise ValueError("At least two attack classes are required to train the text classifier.")
    overall = Counter()
    for counts in token_counts.values():
        overall.update(counts)
    vocabulary = [token for token, _ in overall.most_common() if document_frequency[token] >= min_document_frequency][:max_features]
    if not vocabulary:
        raise ValueError("No usable text features were produced from the training data.")
    vocab_set = set(vocabulary)
    total_documents = sum(class_documents.values())
    if balanced_priors:
        class_log_prior = {label: -math.log(len(classes)) for label in classes}
    else:
        class_log_prior = {label: math.log((class_documents[label] + 1) / (total_documents + len(classes))) for label in classes}
    unknown: dict[str, float] = {}
    token_log_probabilities: dict[str, dict[str, float]] = {token: {} for token in vocabulary}
    for label in classes:
        denominator = sum(token_counts[label][token] for token in vocab_set) + alpha * len(vocabulary)
        unknown[label] = math.log(alpha / denominator)
        for token in vocabulary:
            token_log_probabilities[token][label] = math.log((token_counts[label][token] + alpha) / denominator)
    return {
        "format": "portable_multinomial_naive_bayes_text_v2",
        "algorithm": "Multinomial Naive Bayes with word and optional character n-gram features",
        "classes": classes,
        "class_documents": dict(class_documents),
        "training_records": total_documents,
        "vocabulary_size": len(vocabulary),
        "alpha": alpha,
        "feature_profile": feature_profile,
        "balanced_priors": balanced_priors,
        "class_log_prior": class_log_prior,
        "unknown_log_probability": unknown,
        "token_log_probabilities": token_log_probabilities,
        "confidence_threshold": 0.45,
        "review_margin": 0.12,
        "ood_coverage_threshold": 0.0,
        "actions": DEFAULT_ACTIONS,
        "severity": DEFAULT_SEVERITY,
        "text_column": text_column,
        "label_column": label_column,
    }


def save_model(model: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8", compresslevel=9) as handle:
        json.dump(model, handle, ensure_ascii=False, separators=(",", ":"))
