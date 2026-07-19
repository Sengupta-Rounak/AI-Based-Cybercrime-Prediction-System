from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import math
import statistics
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from nlp_classifier import PortableTextClassifier, save_model, train_model, token_features
from nlp_evaluation import evaluate_records, normalise_label

TEXT_COLUMNS = [
    "incident_text", "incident description", "incident_description", "description",
    "summary", "narrative", "report_text", "report text", "text", "message", "details",
]
LABEL_COLUMNS = [
    "attack_type", "attack type", "label", "class", "category", "incident_type",
    "incident type", "threat_type", "threat type",
]
DATE_COLUMNS = [
    "event_date", "event date", "timestamp", "date", "incident_date", "incident date",
    "created_at", "created at", "timeline.incident.year",
]
GROUP_COLUMNS = [
    "campaign_id", "campaign id", "incident_id", "incident id", "case_id", "case id",
    "ticket_id", "ticket id", "source_id", "source id", "record_id", "record id", "id",
]
SOURCE_COLUMNS = ["source", "source_name", "source name", "dataset", "provider", "reference"]
SYNTHETIC_COLUMNS = ["synthetic", "is_synthetic", "generated"]
SPLIT_COLUMNS = ["split", "partition", "set"]

LABEL_ALIASES = {
    "NORMAL": "BENIGN", "LEGITIMATE": "BENIGN", "SAFE": "BENIGN", "NO_THREAT": "BENIGN",
    "PHISH": "PHISHING", "SPEARPHISHING": "PHISHING", "SPEAR_PHISHING": "PHISHING",
    "IDENTITY_FRAUD": "IDENTITY_THEFT", "ATO": "ACCOUNT_TAKEOVER",
    "DENIAL_OF_SERVICE": "DDOS", "DOS": "DDOS", "D_DOS": "DDOS",
    "PORTSCAN": "PORT_SCAN", "SCAN": "PORT_SCAN",
    "BRUTEFORCE": "BRUTE_FORCE", "PASSWORD_ATTACK": "BRUTE_FORCE",
    "SQLI": "SQL_INJECTION", "CROSS_SITE_SCRIPTING": "XSS",
}

Incident_PRIORITY = [
    "RANSOMWARE", "BOTNET", "PHISHING", "SQL_INJECTION", "XSS", "BRUTE_FORCE",
    "PORT_SCAN", "DDOS", "ACCOUNT_TAKEOVER", "MALWARE",
]


def _key_lookup(columns: Iterable[str]) -> dict[str, str]:
    return {str(value).strip().lower(): str(value) for value in columns}


def _find_column(columns: Iterable[str], candidates: list[str]) -> str | None:
    lookup = _key_lookup(columns)
    return next((lookup[name] for name in candidates if name in lookup), None)


def _clean_text(value: Any) -> str:
    return " ".join(str(value or "").replace("\x00", " ").split()).strip()


def _normalised_text_hash(text: str) -> str:
    normal = " ".join(token.split(":", 1)[-1] for token in token_features(text, "word") if token.startswith("u:"))
    return hashlib.sha256(normal.encode("utf-8", errors="ignore")).hexdigest()


def _parse_date(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.isdigit() and len(text) == 4:
        try:
            return datetime(int(text), 1, 1)
        except ValueError:
            return None
    text = text.replace("Z", "+00:00")
    candidates = [text, text[:19], text[:10]]
    for candidate in candidates:
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            pass
    for fmt in ("%m/%d/%Y", "%d/%m/%Y", "%Y/%m/%d", "%d-%m-%Y", "%m-%d-%Y", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    return None


def _boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "generated", "synthetic"}


def _iter_json_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("records", "incidents", "data", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        # STIX and similar bundles are not a directly labelled incident dataset.
        if isinstance(payload.get("objects"), list):
            return [item for item in payload["objects"] if isinstance(item, dict)]
        # Some Incident joined files are keyed by incident ID.
        if payload and all(isinstance(value, dict) for value in payload.values()):
            return [dict(value, _record_key=str(key)) for key, value in payload.items()]
        return [payload]
    return []


def load_raw_records(path: Path) -> tuple[list[dict[str, Any]], str]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
            return list(csv.DictReader(handle)), "generic_csv"
    if suffix in {".jsonl", ".ndjson"}:
        records = []
        with path.open(encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                try:
                    item = json.loads(line)
                    if isinstance(item, dict):
                        records.append(item)
                except json.JSONDecodeError:
                    continue
        return records, "generic_jsonl"
    if suffix == ".json":
        with path.open(encoding="utf-8-sig", errors="replace") as handle:
            payload = json.load(handle)
        return _iter_json_payload(payload), "generic_json"
    if suffix == ".gz" and path.name.lower().endswith(".json.gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            payload = json.load(handle)
        return _iter_json_payload(payload), "generic_json_gzip"
    if suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            candidates = [name for name in archive.namelist() if not name.endswith("/") and Path(name).suffix.lower() in {".json", ".jsonl", ".ndjson", ".csv"}]
            if not candidates:
                raise ValueError("The ZIP does not contain a supported CSV, JSON or JSONL dataset.")
            # Prefer joined Incident JSON, then the largest supported file.
            candidates.sort(key=lambda name: ("incident" not in name.lower(), -archive.getinfo(name).file_size))
            name = candidates[0]
            with archive.open(name) as raw:
                if Path(name).suffix.lower() == ".csv":
                    text = io.TextIOWrapper(raw, encoding="utf-8-sig", errors="replace", newline="")
                    return list(csv.DictReader(text)), f"zip_csv:{name}"
                if Path(name).suffix.lower() in {".jsonl", ".ndjson"}:
                    records = []
                    text = io.TextIOWrapper(raw, encoding="utf-8-sig", errors="replace")
                    for line in text:
                        try:
                            item = json.loads(line)
                            if isinstance(item, dict):
                                records.append(item)
                        except json.JSONDecodeError:
                            continue
                    return records, f"zip_jsonl:{name}"
                text = io.TextIOWrapper(raw, encoding="utf-8-sig", errors="replace")
                return _iter_json_payload(json.load(text)), f"zip_json:{name}"
    raise ValueError("Supported real-world NLP formats are CSV, JSON, JSONL, JSON.GZ and ZIP.")


def _flatten_truthy(value: Any, prefix: str = "") -> list[str]:
    output: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if child is True or str(child).strip().lower() in {"yes", "true"}:
                output.append(path.lower())
            elif isinstance(child, (dict, list)):
                output.extend(_flatten_truthy(child, path))
    elif isinstance(value, list):
        for child in value:
            output.extend(_flatten_truthy(child, prefix))
    return output


def _incident_label(record: dict[str, Any]) -> tuple[str | None, list[str]]:
    paths = _flatten_truthy(record.get("action", {}), "action")
    joined = " | ".join(paths).lower()
    candidates: set[str] = set()
    if "phishing" in joined or "pretexting" in joined:
        candidates.add("PHISHING")
    if "ransomware" in joined:
        candidates.add("RANSOMWARE")
    if "botnet" in joined or "c2" in joined or "command and control" in joined:
        candidates.add("BOTNET")
    if "sql" in joined and ("inject" in joined or "sqli" in joined):
        candidates.add("SQL_INJECTION")
    if "xss" in joined or "cross site scripting" in joined:
        candidates.add("XSS")
    if "brute force" in joined or "password guess" in joined:
        candidates.add("BRUTE_FORCE")
    if "scan" in joined or "reconnaissance" in joined:
        candidates.add("PORT_SCAN")
    if "denial of service" in joined or ".dos" in joined or "ddos" in joined:
        candidates.add("DDOS")
    if "stolen cred" in joined or "credential reuse" in joined or "use of stolen" in joined:
        candidates.add("ACCOUNT_TAKEOVER")
    if any(path.startswith("action.malware") for path in paths):
        candidates.add("MALWARE")
    selected = next((label for label in Incident_PRIORITY if label in candidates), None)
    return selected, sorted(candidates)


def _is_incident_record(record: dict[str, Any]) -> bool:
    return "summary" in record and "action" in record and ("incident_id" in record or "timeline" in record or "victim" in record)


def normalise_records(raw_records: list[dict[str, Any]], source_name: str) -> tuple[list[dict[str, str]], dict[str, Any]]:
    if not raw_records:
        raise ValueError("The supplied dataset contains no records.")
    incident_count = sum(_is_incident_record(record) for record in raw_records[:100])
    incident_mode = incident_count >= max(1, min(len(raw_records[:100]), 10) // 2)
    output: list[dict[str, str]] = []
    skipped_unlabelled = 0
    ambiguous = 0

    if incident_mode:
        for index, record in enumerate(raw_records):
            text = _clean_text(record.get("summary"))
            label, candidates = _incident_label(record)
            if not text or not label:
                skipped_unlabelled += 1
                continue
            if len(candidates) > 1:
                ambiguous += 1
            timeline = record.get("timeline", {}) if isinstance(record.get("timeline"), dict) else {}
            incident = timeline.get("incident", {}) if isinstance(timeline.get("incident"), dict) else {}
            year = incident.get("year")
            month = incident.get("month", 1)
            day = incident.get("day", 1)
            try:
                event_date = datetime(int(year), int(month), int(day)).date().isoformat() if year else ""
            except (TypeError, ValueError):
                event_date = str(year or "")
            output.append({
                "record_id": _clean_text(record.get("incident_id") or record.get("_record_key") or f"Incident-{index+1}"),
                "incident_text": text,
                "attack_type": label,
                "event_date": event_date,
                "group_id": _clean_text(record.get("campaign_id") or record.get("incident_id") or f"Incident-{index+1}"),
                "source_name": "structured incident taxonomy Community Database",
                "synthetic": "false",
            })
        mode = "incident_structured incident taxonomy"
    else:
        columns = list(raw_records[0].keys())
        text_column = _find_column(columns, TEXT_COLUMNS)
        label_column = _find_column(columns, LABEL_COLUMNS)
        date_column = _find_column(columns, DATE_COLUMNS)
        group_column = _find_column(columns, GROUP_COLUMNS)
        source_column = _find_column(columns, SOURCE_COLUMNS)
        synthetic_column = _find_column(columns, SYNTHETIC_COLUMNS)
        split_column = _find_column(columns, SPLIT_COLUMNS)
        if not text_column:
            raise ValueError("No recognised incident-text column was found. Use incident_text, description, summary, narrative, report_text, text or message.")
        if not label_column:
            raise ValueError("No recognised attack-label column was found. Real-world training requires verified labels.")
        for index, record in enumerate(raw_records):
            text = _clean_text(record.get(text_column))
            label = LABEL_ALIASES.get(normalise_label(record.get(label_column)), normalise_label(record.get(label_column)))
            if not text or not label:
                skipped_unlabelled += 1
                continue
            output.append({
                "record_id": _clean_text(record.get(group_column) if group_column else "") or f"ROW-{index+1}",
                "incident_text": text,
                "attack_type": label,
                "event_date": _clean_text(record.get(date_column) if date_column else ""),
                "group_id": _clean_text(record.get(group_column) if group_column else "") or f"ROW-{index+1}",
                "source_name": _clean_text(record.get(source_column) if source_column else "") or source_name,
                "synthetic": "true" if synthetic_column and _boolish(record.get(synthetic_column)) else "false",
                "split": _clean_text(record.get(split_column) if split_column else "").lower(),
            })
        mode = "generic_labelled"

    return output, {
        "adapter": mode,
        "raw_records": len(raw_records),
        "normalised_records": len(output),
        "skipped_unlabelled_or_empty": skipped_unlabelled,
        "ambiguous_incident_records": ambiguous,
    }


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[low]
    return ordered[low] * (high - position) + ordered[high] * (position - low)


def audit_records(records: list[dict[str, str]], adapter_info: dict[str, Any], source_hash: str) -> dict[str, Any]:
    counts = Counter(record["attack_type"] for record in records)
    synthetic_count = sum(_boolish(record.get("synthetic")) for record in records)
    text_hashes = Counter(_normalised_text_hash(record["incident_text"]) for record in records)
    duplicate_rows = sum(count - 1 for count in text_hashes.values() if count > 1)
    lengths = [len(record["incident_text"].split()) for record in records]
    dates = [_parse_date(record.get("event_date")) for record in records]
    dates = [value for value in dates if value]
    source_counts = Counter(record.get("source_name", "Unknown") for record in records)
    low_evidence = {label: count for label, count in counts.items() if count < 30}
    ready = len(records) >= 200 and len(counts) >= 2 and not low_evidence and synthetic_count == 0
    warnings = []
    if synthetic_count:
        warnings.append(f"{synthetic_count} records are marked synthetic; the resulting model cannot be labelled real-world-only.")
    if low_evidence:
        warnings.append("Some classes contain fewer than 30 records and are not ready for dependable class-level evaluation.")
    if duplicate_rows / max(len(records), 1) > 0.10:
        warnings.append("More than 10% of records are exact text duplicates; duplicate leakage controls will remove them.")
    if len(source_counts) < 2:
        warnings.append("Only one source is present; source-domain external validation will still be required.")
    if not dates:
        warnings.append("No parseable event dates were found; a chronological holdout cannot be constructed.")
    return {
        **adapter_info,
        "source_sha256": source_hash,
        "records": len(records),
        "classes": len(counts),
        "class_distribution": dict(counts),
        "synthetic_records": synthetic_count,
        "exact_duplicate_records": duplicate_rows,
        "duplicate_rate": duplicate_rows / max(len(records), 1),
        "median_text_words": statistics.median(lengths) if lengths else 0,
        "p95_text_words": _percentile([float(x) for x in lengths], 0.95),
        "source_count": len(source_counts),
        "source_distribution": dict(source_counts.most_common(20)),
        "date_start": min(dates).date().isoformat() if dates else None,
        "date_end": max(dates).date().isoformat() if dates else None,
        "classes_below_30": low_evidence,
        "real_world_training_ready": ready,
        "warnings": warnings,
    }


def deduplicate_records(records: list[dict[str, str]]) -> list[dict[str, str]]:
    # Keep duplicate text inside the same logical record only once, preventing exact leakage.
    seen: set[str] = set()
    output = []
    for record in records:
        fingerprint = _normalised_text_hash(record["incident_text"])
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        copy = dict(record)
        copy["text_fingerprint"] = fingerprint
        output.append(copy)
    return output


def split_records(records: list[dict[str, str]]) -> tuple[dict[str, list[dict[str, str]]], dict[str, Any]]:
    explicit = {name: [] for name in ("train", "validation", "test")}
    if records and all(record.get("split") in {"train", "validation", "test"} for record in records if record.get("split")) and sum(bool(record.get("split")) for record in records) >= len(records) * 0.95:
        for record in records:
            explicit[record.get("split", "train")].append(record)
        if all(explicit.values()):
            return explicit, {"strategy": "provided_split", "chronological": False, "group_aware": False}

    dated = [(record, _parse_date(record.get("event_date"))) for record in records]
    dated_count = sum(date is not None for _, date in dated)
    if dated_count >= len(records) * 0.80:
        dated.sort(key=lambda item: (item[1] or datetime.min, item[0]["record_id"]))
        n = len(dated)
        first = max(1, int(n * 0.70))
        second = max(first + 1, int(n * 0.85))
        split = {
            "train": [record for record, _ in dated[:first]],
            "validation": [record for record, _ in dated[first:second]],
            "test": [record for record, _ in dated[second:]],
        }
        return split, {"strategy": "chronological_70_15_15", "chronological": True, "group_aware": False}

    # Group-aware deterministic split. Every campaign/incident remains in exactly one partition.
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for record in records:
        grouped[record.get("group_id") or record["record_id"]].append(record)
    split = {"train": [], "validation": [], "test": []}
    for group, group_records in grouped.items():
        bucket = int(hashlib.sha256(group.encode("utf-8", errors="ignore")).hexdigest()[:8], 16) % 100
        target = "train" if bucket < 70 else ("validation" if bucket < 85 else "test")
        split[target].extend(group_records)
    if all(split.values()):
        return split, {"strategy": "group_hash_70_15_15", "chronological": False, "group_aware": True}

    # Final deterministic stratified fallback.
    split = {"train": [], "validation": [], "test": []}
    by_class: dict[str, list[dict[str, str]]] = defaultdict(list)
    for record in records:
        by_class[record["attack_type"]].append(record)
    for label, items in by_class.items():
        items.sort(key=lambda item: hashlib.sha256((item["text_fingerprint"] + label).encode()).hexdigest())
        n = len(items)
        first, second = max(1, int(n * 0.70)), max(2, int(n * 0.85))
        split["train"].extend(items[:first])
        split["validation"].extend(items[first:second])
        split["test"].extend(items[second:])
    return split, {"strategy": "stratified_hash_70_15_15", "chronological": False, "group_aware": False}


def _prediction_records(classifier: PortableTextClassifier, records: list[dict[str, str]]) -> list[dict[str, Any]]:
    output = []
    for record in records:
        result = classifier.predict(record["incident_text"])
        output.append({
            "record_id": record["record_id"],
            "incident_text": record["incident_text"],
            "actual_attack": record["attack_type"],
            "predicted_attack": result["predicted_attack"],
            "confidence": result["confidence"],
            "decision": result["decision"],
            "top3": result["top3"],
            "probability_map": result["probability_map"],
            "lexical_coverage": result["lexical_coverage"],
        })
    return output


def _tune_thresholds(classifier: PortableTextClassifier, validation: list[dict[str, str]]) -> dict[str, float]:
    base = []
    for record in validation:
        result = classifier.predict(record["incident_text"])
        base.append((record["attack_type"], result["predicted_attack"], result["confidence"], result["margin"], result["lexical_coverage"]))
    coverage_values = [item[4] for item in base]
    ood = max(0.04, min(0.35, _percentile(coverage_values, 0.03))) if coverage_values else 0.08
    best = {"confidence_threshold": 0.45, "review_margin": 0.10, "ood_coverage_threshold": ood, "score": -1.0}
    for threshold in (0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70):
        for margin in (0.04, 0.07, 0.10, 0.13, 0.16, 0.20):
            covered = [item for item in base if item[2] >= threshold and item[3] >= margin and item[4] >= ood]
            coverage = len(covered) / max(len(base), 1)
            if coverage < 0.55:
                continue
            selective_accuracy = sum(actual == predicted for actual, predicted, *_ in covered) / max(len(covered), 1)
            score = 0.68 * selective_accuracy + 0.32 * coverage
            if score > best["score"]:
                best = {"confidence_threshold": threshold, "review_margin": margin, "ood_coverage_threshold": ood, "score": score}
    return best


def train_realworld_model(
    input_path: Path,
    output_model: Path,
    output_metrics: Path,
    output_card: Path,
    *,
    source_display_name: str | None = None,
    external_test_path: Path | None = None,
) -> dict[str, Any]:
    started = time.time()
    source_hash = hashlib.sha256(input_path.read_bytes()).hexdigest()
    raw, raw_mode = load_raw_records(input_path)
    records, adapter_info = normalise_records(raw, source_display_name or input_path.name)
    adapter_info["raw_mode"] = raw_mode
    audit = audit_records(records, adapter_info, source_hash)
    if audit["synthetic_records"]:
        raise ValueError("The training dataset contains records marked synthetic. Remove them before creating a real-world model.")
    if len(records) < 200:
        raise ValueError("At least 200 verified real incident records are required for this real-data training profile.")
    if len(audit["class_distribution"]) < 2:
        raise ValueError("At least two verified attack classes are required.")

    deduplicated = deduplicate_records(records)
    split, split_info = split_records(deduplicated)
    for name in ("train", "validation", "test"):
        if len(split[name]) < 20:
            raise ValueError(f"The {name} partition contains only {len(split[name])} records. Supply more independent real incidents.")

    candidates = []
    for alpha in (0.05, 0.10, 0.20, 0.35, 0.60, 1.0):
        for balanced in (True, False):
            model = train_model(
                split["train"], alpha=alpha, min_document_frequency=2,
                max_features=30000, feature_profile="real_world", balanced_priors=balanced,
            )
            model.update({"source_is_synthetic": False, "validation_status": "internal_real_data"})
            classifier = PortableTextClassifier(model)
            metrics = evaluate_records(_prediction_records(classifier, split["validation"]), classifier.classes)
            candidates.append((metrics["macro_f1"], metrics["balanced_accuracy"], -metrics["log_loss"], alpha, balanced, model, metrics))
    candidates.sort(key=lambda item: item[:3], reverse=True)
    _, _, _, alpha, balanced, model, validation_metrics = candidates[0]
    classifier = PortableTextClassifier(model)
    tuning = _tune_thresholds(classifier, split["validation"])
    model.update({
        "model_name": "Real-World Cybercrime Incident Text Classifier",
        "source_name": source_display_name or input_path.name,
        "source_sha256": source_hash,
        "source_is_synthetic": False,
        "validation_status": "internal_real_data",
        "split_strategy": split_info,
        "training_records": len(split["train"]),
        "validation_records": len(split["validation"]),
        "test_records": len(split["test"]),
        "confidence_threshold": tuning["confidence_threshold"],
        "review_margin": tuning["review_margin"],
        "ood_coverage_threshold": tuning["ood_coverage_threshold"],
        "selected_alpha": alpha,
        "balanced_priors": balanced,
        "training_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "dataset_audit": audit,
    })
    save_model(model, output_model)
    classifier = PortableTextClassifier.load(output_model)
    test_metrics = evaluate_records(_prediction_records(classifier, split["test"]), classifier.classes)
    external_metrics = None
    external_audit = None
    if external_test_path:
        external_hash = hashlib.sha256(external_test_path.read_bytes()).hexdigest()
        if external_hash == source_hash:
            raise ValueError("The external-test file is identical to the training source and cannot establish external validation.")
        ext_raw, ext_mode = load_raw_records(external_test_path)
        ext_records, ext_info = normalise_records(ext_raw, external_test_path.name)
        external_audit = audit_records(ext_records, {**ext_info, "raw_mode": ext_mode}, external_hash)
        if external_audit["synthetic_records"]:
            raise ValueError("The external validation dataset contains synthetic records.")
        ext_deduplicated = deduplicate_records(ext_records)
        training_hashes = {_normalised_text_hash(record["incident_text"]) for record in deduplicated}
        external_overlap = [record for record in ext_deduplicated if _normalised_text_hash(record["incident_text"]) in training_hashes]
        ext_independent = [record for record in ext_deduplicated if _normalised_text_hash(record["incident_text"]) not in training_hashes]
        external_audit["training_text_overlap_records"] = len(external_overlap)
        external_audit["independent_records_after_overlap_removal"] = len(ext_independent)
        external_audit["training_text_overlap_rate"] = len(external_overlap) / max(len(ext_deduplicated), 1)
        if external_overlap:
            external_audit.setdefault("warnings", []).append(
                f"Removed {len(external_overlap)} external records that duplicated training narratives."
            )
        if len(ext_independent) < 20:
            raise ValueError("Fewer than 20 independent external records remain after removing training-text overlap.")
        external_metrics = evaluate_records(_prediction_records(classifier, ext_independent), classifier.classes)
        model["validation_status"] = "externally_validated"
        model["external_validation_source"] = external_test_path.name
        model["external_validation_sha256"] = external_hash
        save_model(model, output_model)
        classifier = PortableTextClassifier.load(output_model)

    metrics_payload = {
        "model_name": model["model_name"],
        "source_is_synthetic": False,
        "validation_status": model["validation_status"],
        "dataset_audit": audit,
        "split": {**split_info, "train": len(split["train"]), "validation": len(split["validation"]), "test": len(split["test"])},
        "selected_hyperparameters": {
            "alpha": alpha, "balanced_priors": balanced,
            "confidence_threshold": tuning["confidence_threshold"],
            "review_margin": tuning["review_margin"],
            "ood_coverage_threshold": tuning["ood_coverage_threshold"],
            "feature_profile": "real_world",
        },
        "validation_metrics": validation_metrics,
        "internal_test_metrics": test_metrics,
        "external_test_metrics": external_metrics,
        "external_test_audit": external_audit,
        "elapsed_seconds": time.time() - started,
        "scientific_note": (
            "External validation was recorded on an independent file." if external_metrics else
            "This is a real-data internally validated model. Independent source-domain external validation is still required before operational use."
        ),
    }
    output_metrics.parent.mkdir(parents=True, exist_ok=True)
    output_metrics.write_text(json.dumps(metrics_payload, indent=2, ensure_ascii=False), encoding="utf-8")
    card = {
        "name": model["model_name"],
        "task": "English cybercrime incident-text multiclass triage",
        "algorithm": model["algorithm"],
        "feature_profile": "word unigrams, word bigrams, and character 3-5 grams",
        "classes": model["classes"],
        "training_source": model["source_name"],
        "training_source_sha256": source_hash,
        "source_is_synthetic": False,
        "validation_status": model["validation_status"],
        "split_strategy": split_info,
        "training_records": len(split["train"]),
        "validation_records": len(split["validation"]),
        "test_records": len(split["test"]),
        "internal_test_macro_f1": test_metrics.get("macro_f1"),
        "internal_test_balanced_accuracy": test_metrics.get("balanced_accuracy"),
        "external_test_macro_f1": external_metrics.get("macro_f1") if external_metrics else None,
        "external_test_records": external_metrics.get("records") if external_metrics else 0,
        "limitations": [
            "Performance is valid only for domains represented by the real training and evaluation sources.",
            "A class with limited independent incidents may have unstable recall.",
            "Out-of-scope and low-confidence narratives are routed to analyst review.",
            "Model evidence is not proof of causation.",
        ],
    }
    output_card.write_text(json.dumps(card, indent=2, ensure_ascii=False), encoding="utf-8")
    return {
        "model_path": str(output_model),
        "metrics_path": str(output_metrics),
        "card_path": str(output_card),
        "model_sha256": hashlib.sha256(output_model.read_bytes()).hexdigest(),
        "audit": audit,
        "split": metrics_payload["split"],
        "validation_status": model["validation_status"],
        "internal_test": {
            "records": test_metrics.get("records"),
            "accuracy": test_metrics.get("accuracy"),
            "balanced_accuracy": test_metrics.get("balanced_accuracy"),
            "macro_f1": test_metrics.get("macro_f1"),
            "review_rate": test_metrics.get("review_rate"),
            "coverage": test_metrics.get("coverage"),
            "selective_accuracy": test_metrics.get("selective_accuracy"),
        },
        "external_test": {
            "records": external_metrics.get("records"),
            "accuracy": external_metrics.get("accuracy"),
            "balanced_accuracy": external_metrics.get("balanced_accuracy"),
            "macro_f1": external_metrics.get("macro_f1"),
        } if external_metrics else None,
    }
