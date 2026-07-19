from __future__ import annotations

import gzip
import hashlib
import json
import pickle
from pathlib import Path

from nlp_classifier import PortableTextClassifier
from nlp_evaluation import evaluate_records
from realworld_nlp import audit_records, deduplicate_records, normalise_records, split_records
from incident_multilabel import PortableIncidentMultiLabelClassifier

ROOT = Path(__file__).resolve().parent
NETWORK_PATH = ROOT / "models" / "portable_prediction_model.pkl.gz"
FALLBACK_TEXT_PATH = ROOT / "models" / "portable_text_classifier.json.gz"
REAL_TEXT_PATH = ROOT / "models" / "portable_text_classifier_realworld.json.gz"
POINTER_PATH = ROOT / "models" / "active_text_model.json"
INCIDENT_MODEL_PATH = ROOT / "models" / "real_incident_multilabel_classifier.json.gz"


def active_text_path() -> Path:
    try:
        pointer = json.loads(POINTER_PATH.read_text(encoding="utf-8"))
        path = ROOT / pointer["model_path"]
        return path if path.exists() else FALLBACK_TEXT_PATH
    except Exception:
        return FALLBACK_TEXT_PATH


def main() -> int:
    with gzip.open(NETWORK_PATH, "rb") as handle:
        network = pickle.load(handle)
    text_path = active_text_path()
    text = PortableTextClassifier.load(text_path)
    incident = PortableIncidentMultiLabelClassifier.load(INCIDENT_MODEL_PATH)
    evaluation_smoke = evaluate_records([
        {"actual_attack":"BENIGN", "predicted_attack":"BENIGN", "confidence":0.92, "decision":"NO_THREAT", "top3":["BENIGN"], "probability_map":{"BENIGN":0.92,"PHISHING":0.08}, "record_id":"V1", "incident_text":"Routine update completed."},
        {"actual_attack":"PHISHING", "predicted_attack":"PHISHING", "confidence":0.89, "decision":"THREAT_DETECTED", "top3":["PHISHING"], "probability_map":{"BENIGN":0.03,"PHISHING":0.89}, "record_id":"V2", "incident_text":"Fake sign-in message."},
    ], text.classes)
    raw = [
        {"incident_text": f"Verified incident narrative caseword{chr(97 + (i % 26))}{chr(97 + (i // 26))} with suspicious login activity", "attack_type": "BRUTE_FORCE", "event_date": f"2024-01-{(i % 28)+1:02d}", "incident_id": f"B{i}"}
        for i in range(60)
    ] + [
        {"incident_text": f"Verified report phishword{chr(97 + (i % 26))}{chr(97 + (i // 26))} describing a fraudulent email and fake sign-in link", "attack_type": "PHISHING", "event_date": f"2024-02-{(i % 28)+1:02d}", "incident_id": f"P{i}"}
        for i in range(60)
    ]
    records, adapter = normalise_records(raw, "verification fixture")
    audit = audit_records(records, adapter, "fixture")
    split, split_info = split_records(deduplicate_records(records))
    checks = {
        "network_feature_count": len(network.get("feature_columns", [])),
        "network_horizons": sorted(int(value) for value in network.get("horizons", {})),
        "active_text_model": str(text_path.relative_to(ROOT)).replace("\\", "/"),
        "active_text_source_is_synthetic": bool(text.model.get("source_is_synthetic", True)),
        "active_text_validation_status": text.model.get("validation_status", "synthetic_demonstration"),
        "text_class_count": len(text.classes),
        "network_sha256": hashlib.sha256(NETWORK_PATH.read_bytes()).hexdigest(),
        "text_sha256": hashlib.sha256(text_path.read_bytes()).hexdigest(),
        "phishing_smoke_test": text.predict("A fake bank email asked the user to verify credentials through an unfamiliar link.")["predicted_attack"],
        "benign_smoke_test": text.predict("A scheduled software update completed successfully and all integrity checks passed.")["predicted_attack"],
        "nlp_evaluation_accuracy_smoke": evaluation_smoke["accuracy"],
        "realworld_module_present": (ROOT / "realworld_nlp.py").exists(),
        "realworld_fixture_records": audit["records"],
        "realworld_fixture_split_strategy": split_info.get("strategy"),
        "realworld_fixture_split_sizes": {name: len(values) for name, values in split.items()},
        "real_model_available": REAL_TEXT_PATH.exists(),
        "real_incident_multilabel_model_valid": len(incident.labels) == 14 and len(incident.primary_labels) == 8,
        "real_incident_phishing_smoke": incident.predict("A fraudulent email impersonated a bank and directed the user to a fake credential page.")["predicted_attack"],
        "real_incident_model_sha256": hashlib.sha256(INCIDENT_MODEL_PATH.read_bytes()).hexdigest(),
        "focused_reports_present": all((ROOT / path).exists() for path in [
            "models/cybercrime_prediction_metrics.json",
            "models/model_card.json",
            "models/real_incident_multilabel_metrics.json",
            "models/real_incident_multilabel_model_card.json",
            "docs/ARCHITECTURE.md",
            "docs/METHODOLOGY.md",
            "docs/DATA_REQUIREMENTS.md",
        ]),
    }
    checks["valid"] = (
        checks["network_feature_count"] == 91
        and checks["network_horizons"] == [5, 10, 30]
        and checks["text_class_count"] >= 2
        and checks["nlp_evaluation_accuracy_smoke"] == 1.0
        and checks["realworld_module_present"]
        and checks["realworld_fixture_records"] == 120
        and all(size > 0 for size in checks["realworld_fixture_split_sizes"].values())
        and checks["real_incident_multilabel_model_valid"]
        and checks["focused_reports_present"]
        and checks["real_incident_phishing_smoke"] in {"PHISHING", "SOCIAL_ENGINEERING", "DATA_BREACH"}
    )
    print(json.dumps(checks, indent=2))
    return 0 if checks["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
