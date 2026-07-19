from __future__ import annotations

import csv
import json
import math
import time
from collections import Counter
from pathlib import Path
from typing import Any

from nlp_classifier import PortableTextClassifier

TEXT_COLUMNS = {
    "incident_text", "incident text", "description", "incident_description",
    "report_text", "report text", "text", "message", "narrative", "incident narrative",
}
MULTICLASS_LABEL_COLUMNS = {
    "attack_type", "attack type", "label", "class", "target", "category", "incident_type",
}
BINARY_LABEL_COLUMNS = {
    "binary_label", "binary label", "is_malicious", "malicious", "threat_label",
}
ID_COLUMNS = {"record_id", "record id", "id", "incident_id", "incident id", "case_id", "case id"}

ALIASES = {
    "NORMAL": "BENIGN",
    "LEGITIMATE": "BENIGN",
    "NO_THREAT": "BENIGN",
    "SAFE": "BENIGN",
    "PHISH": "PHISHING",
    "IDENTITY_FRAUD": "IDENTITY_THEFT",
    "ATO": "ACCOUNT_TAKEOVER",
    "DENIAL_OF_SERVICE": "DDOS",
    "D_DOS": "DDOS",
    "PORTSCAN": "PORT_SCAN",
    "BRUTEFORCE": "BRUTE_FORCE",
    "SQLI": "SQL_INJECTION",
    "CROSS_SITE_SCRIPTING": "XSS",
}


def normalise_label(value: Any) -> str:
    text = str(value or "").strip().upper().replace("-", "_").replace("/", "_").replace(" ", "_")
    while "__" in text:
        text = text.replace("__", "_")
    return ALIASES.get(text, text)


def normalise_binary(value: Any) -> str:
    label = normalise_label(value)
    if label in {"BENIGN", "0", "FALSE", "NEGATIVE", "NORMAL", "LEGITIMATE", "SAFE"}:
        return "BENIGN"
    if label in {"MALICIOUS", "1", "TRUE", "POSITIVE", "ATTACK", "THREAT"}:
        return "MALICIOUS"
    return ""


def find_column(columns: list[str], candidates: set[str]) -> str | None:
    lookup = {str(column).strip().lower(): column for column in columns}
    return next((lookup[name] for name in candidates if name in lookup), None)


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def _binary_auc(labels: list[int], scores: list[float]) -> float | None:
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        return None
    ordered = sorted(zip(scores, labels), key=lambda item: item[0])
    rank_sum = 0.0
    i = 0
    rank = 1
    while i < len(ordered):
        j = i + 1
        while j < len(ordered) and ordered[j][0] == ordered[i][0]:
            j += 1
        average_rank = (rank + (rank + j - i - 1)) / 2.0
        rank_sum += average_rank * sum(label for _, label in ordered[i:j])
        rank += j - i
        i = j
    return (rank_sum - positives * (positives + 1) / 2.0) / (positives * negatives)


def _average_precision(labels: list[int], scores: list[float]) -> float | None:
    positives = sum(labels)
    if positives == 0:
        return None
    ranked = sorted(zip(scores, labels), key=lambda item: item[0], reverse=True)
    tp = 0
    total = 0
    precision_sum = 0.0
    for _, label in ranked:
        total += 1
        if label:
            tp += 1
            precision_sum += tp / total
    return precision_sum / positives


def _round_payload(value: Any) -> Any:
    if isinstance(value, float):
        return round(value, 8)
    if isinstance(value, dict):
        return {k: _round_payload(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_round_payload(v) for v in value]
    return value


def evaluate_records(records: list[dict[str, Any]], model_classes: list[str]) -> dict[str, Any]:
    if not records:
        raise ValueError("No labelled records were available for NLP evaluation.")

    y_true = [record["actual_attack"] for record in records]
    y_pred = [record["predicted_attack"] for record in records]
    labels = list(dict.fromkeys(list(model_classes) + sorted(set(y_true) - set(model_classes))))
    index = {label: position for position, label in enumerate(labels)}
    confusion = [[0 for _ in labels] for _ in labels]
    for actual, predicted in zip(y_true, y_pred):
        if actual not in index:
            continue
        if predicted not in index:
            labels.append(predicted)
            for row in confusion:
                row.append(0)
            confusion.append([0 for _ in labels])
            index = {label: position for position, label in enumerate(labels)}
        confusion[index[actual]][index[predicted]] += 1

    per_class: list[dict[str, Any]] = []
    macro_precision = macro_recall = macro_f1 = 0.0
    weighted_precision = weighted_recall = weighted_f1 = 0.0
    total = len(records)
    supported_label_count = 0
    for label in labels:
        i = index[label]
        tp = confusion[i][i]
        fp = sum(confusion[row][i] for row in range(len(labels)) if row != i)
        fn = sum(confusion[i][column] for column in range(len(labels)) if column != i)
        support = sum(confusion[i])
        predicted_count = sum(confusion[row][i] for row in range(len(labels)))
        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        f1 = _safe_div(2 * precision * recall, precision + recall)
        if support:
            supported_label_count += 1
            macro_precision += precision
            macro_recall += recall
            macro_f1 += f1
            weighted_precision += precision * support
            weighted_recall += recall * support
            weighted_f1 += f1 * support
        per_class.append({
            "label": label,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": support,
            "predicted_count": predicted_count,
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "supported_by_model": label in model_classes,
        })

    correct = sum(actual == predicted for actual, predicted in zip(y_true, y_pred))
    accuracy = correct / total
    macro_precision = _safe_div(macro_precision, supported_label_count)
    macro_recall = _safe_div(macro_recall, supported_label_count)
    macro_f1 = _safe_div(macro_f1, supported_label_count)
    weighted_precision = _safe_div(weighted_precision, total)
    weighted_recall = _safe_div(weighted_recall, total)
    weighted_f1 = _safe_div(weighted_f1, total)

    actual_counts = Counter(y_true)
    predicted_counts = Counter(y_pred)
    expected_accuracy = sum(actual_counts[label] * predicted_counts[label] for label in set(actual_counts) | set(predicted_counts)) / (total * total)
    kappa = _safe_div(accuracy - expected_accuracy, 1.0 - expected_accuracy)

    top3_correct = 0
    log_loss = 0.0
    brier_sum = 0.0
    confidence_correct = []
    confidence_incorrect = []
    calibration_bins = [{"lower": i / 10, "upper": (i + 1) / 10, "count": 0, "confidence_sum": 0.0, "correct": 0} for i in range(10)]
    review_count = 0
    covered_correct = 0
    covered_count = 0
    for record in records:
        probabilities = record.get("probability_map", {})
        actual = record["actual_attack"]
        predicted = record["predicted_attack"]
        confidence = float(record.get("confidence", 0.0))
        if actual in record.get("top3", []):
            top3_correct += 1
        p_actual = min(max(float(probabilities.get(actual, 0.0)), 1e-15), 1.0)
        log_loss -= math.log(p_actual)
        brier_sum += sum((float(probabilities.get(label, 0.0)) - (1.0 if label == actual else 0.0)) ** 2 for label in model_classes) / max(len(model_classes), 1)
        if actual == predicted:
            confidence_correct.append(confidence)
        else:
            confidence_incorrect.append(confidence)
        bin_index = min(int(confidence * 10), 9)
        calibration_bins[bin_index]["count"] += 1
        calibration_bins[bin_index]["confidence_sum"] += confidence
        calibration_bins[bin_index]["correct"] += int(actual == predicted)
        if record.get("decision") == "REVIEW":
            review_count += 1
        else:
            covered_count += 1
            covered_correct += int(actual == predicted)

    ece = 0.0
    calibration_output = []
    for item in calibration_bins:
        count = item["count"]
        average_confidence = _safe_div(item["confidence_sum"], count)
        bin_accuracy = _safe_div(item["correct"], count)
        ece += (count / total) * abs(bin_accuracy - average_confidence)
        calibration_output.append({
            "lower": item["lower"],
            "upper": item["upper"],
            "count": count,
            "average_confidence": average_confidence,
            "accuracy": bin_accuracy,
            "gap": abs(bin_accuracy - average_confidence),
        })

    binary_actual = [0 if actual == "BENIGN" else 1 for actual in y_true]
    binary_predicted = [0 if predicted == "BENIGN" else 1 for predicted in y_pred]
    malicious_scores = [1.0 - float(record.get("probability_map", {}).get("BENIGN", 0.0)) for record in records]
    tp = sum(actual == 1 and predicted == 1 for actual, predicted in zip(binary_actual, binary_predicted))
    tn = sum(actual == 0 and predicted == 0 for actual, predicted in zip(binary_actual, binary_predicted))
    fp = sum(actual == 0 and predicted == 1 for actual, predicted in zip(binary_actual, binary_predicted))
    fn = sum(actual == 1 and predicted == 0 for actual, predicted in zip(binary_actual, binary_predicted))
    binary_precision = _safe_div(tp, tp + fp)
    binary_recall = _safe_div(tp, tp + fn)
    binary_f1 = _safe_div(2 * binary_precision * binary_recall, binary_precision + binary_recall)
    binary_specificity = _safe_div(tn, tn + fp)

    errors = [
        {
            "record_id": record.get("record_id", ""),
            "incident_text": record.get("incident_text", ""),
            "actual_attack": record["actual_attack"],
            "predicted_attack": record["predicted_attack"],
            "confidence": record.get("confidence", 0.0),
            "decision": record.get("decision", ""),
            "top3": record.get("top3", []),
        }
        for record in records if record["actual_attack"] != record["predicted_attack"]
    ]
    errors.sort(key=lambda item: float(item["confidence"]), reverse=True)

    result = {
        "records": total,
        "correct": correct,
        "accuracy": accuracy,
        "balanced_accuracy": macro_recall,
        "macro_precision": macro_precision,
        "macro_recall": macro_recall,
        "macro_f1": macro_f1,
        "weighted_precision": weighted_precision,
        "weighted_recall": weighted_recall,
        "weighted_f1": weighted_f1,
        "micro_precision": accuracy,
        "micro_recall": accuracy,
        "micro_f1": accuracy,
        "cohen_kappa": kappa,
        "top3_accuracy": top3_correct / total,
        "log_loss": log_loss / total,
        "multiclass_brier": brier_sum / total,
        "expected_calibration_error": ece,
        "review_count": review_count,
        "review_rate": review_count / total,
        "coverage": covered_count / total,
        "selective_accuracy": _safe_div(covered_correct, covered_count),
        "average_confidence": sum(record.get("confidence", 0.0) for record in records) / total,
        "average_correct_confidence": _safe_div(sum(confidence_correct), len(confidence_correct)),
        "average_error_confidence": _safe_div(sum(confidence_incorrect), len(confidence_incorrect)),
        "labels": labels,
        "per_class": per_class,
        "confusion_matrix": confusion,
        "calibration_bins": calibration_output,
        "errors": errors[:100],
        "error_count": len(errors),
        "high_confidence_error_count": sum(float(error["confidence"]) >= 0.80 for error in errors),
        "binary": {
            "records": total,
            "accuracy": (tp + tn) / total,
            "precision": binary_precision,
            "recall": binary_recall,
            "specificity": binary_specificity,
            "f1": binary_f1,
            "roc_auc": _binary_auc(binary_actual, malicious_scores),
            "pr_auc": _average_precision(binary_actual, malicious_scores),
            "confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        },
    }
    return _round_payload(result)


def _load_answer_key(path: Path | None) -> tuple[dict[str, dict[str, str]], str | None, str | None, str | None]:
    if path is None:
        return {}, None, None, None
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        columns = reader.fieldnames or []
        id_column = find_column(columns, ID_COLUMNS)
        label_column = find_column(columns, MULTICLASS_LABEL_COLUMNS)
        binary_column = find_column(columns, BINARY_LABEL_COLUMNS)
        if not id_column:
            raise ValueError("The answer key requires a record_id, id, incident_id, or case_id column.")
        if not label_column and not binary_column:
            raise ValueError("The answer key requires an attack_type/label/class column or a binary_label column.")
        mapping = {str(row.get(id_column, "")).strip(): row for row in reader if str(row.get(id_column, "")).strip()}
    return mapping, id_column, label_column, binary_column


def evaluate_text_dataset(
    classifier: PortableTextClassifier,
    dataset_path: Path,
    output_dir: Path,
    original_name: str,
    answer_key_path: Path | None = None,
    answer_key_name: str | None = None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    stem = Path(original_name).stem[:55]
    prediction_path = output_dir / f"nlp_evaluation_predictions_{stamp}_{stem}.csv"
    summary_path = output_dir / f"nlp_evaluation_summary_{stamp}_{stem}.json"
    per_class_path = output_dir / f"nlp_evaluation_per_class_{stamp}_{stem}.csv"
    confusion_path = output_dir / f"nlp_evaluation_confusion_{stamp}_{stem}.csv"
    errors_path = output_dir / f"nlp_evaluation_errors_{stamp}_{stem}.csv"
    calibration_path = output_dir / f"nlp_evaluation_calibration_{stamp}_{stem}.csv"

    key_map, _, key_label_column, key_binary_column = _load_answer_key(answer_key_path)
    records: list[dict[str, Any]] = []
    preview: list[dict[str, Any]] = []
    distribution: Counter[str] = Counter()
    skipped_missing_label = 0
    skipped_invalid_text = 0
    unmatched_answer_key = 0
    unknown_labels: Counter[str] = Counter()
    synthetic_values: list[str] = []

    with dataset_path.open(newline="", encoding="utf-8-sig", errors="replace") as source:
        reader = csv.DictReader(source)
        columns = reader.fieldnames or []
        text_column = find_column(columns, TEXT_COLUMNS)
        label_column = find_column(columns, MULTICLASS_LABEL_COLUMNS)
        binary_column = find_column(columns, BINARY_LABEL_COLUMNS)
        id_column = find_column(columns, ID_COLUMNS)
        if not text_column:
            raise ValueError("No incident-text column was detected. Use incident_text, description, incident_description, report_text, text, or message.")
        if answer_key_path and not id_column:
            raise ValueError("A separate answer key requires a record_id, id, incident_id, or case_id in the test dataset.")
        if not answer_key_path and not label_column and not binary_column:
            raise ValueError("Evaluation requires an attack_type/label/class column or a separate answer-key CSV.")

        output_fields = list(columns) + [
            "actual_attack", "actual_binary_label", "predicted_attack", "predicted_binary_label",
            "prediction_confidence", "prediction_margin", "prediction_decision", "top3_predictions",
            "correct_multiclass", "correct_binary", "predicted_severity", "recommended_action",
        ]
        with prediction_path.open("w", newline="", encoding="utf-8-sig") as target:
            writer = csv.DictWriter(target, fieldnames=output_fields, extrasaction="ignore")
            writer.writeheader()
            for index, row in enumerate(reader, start=1):
                if "synthetic" in row:
                    synthetic_values.append(str(row.get("synthetic", "")).strip().lower())
                record_id = str(row.get(id_column, index)).strip() if id_column else str(index)
                key_row = key_map.get(record_id, {}) if key_map else {}
                if key_map and not key_row:
                    unmatched_answer_key += 1
                raw_actual = row.get(label_column, "") if label_column else key_row.get(key_label_column, "") if key_label_column else ""
                raw_binary = row.get(binary_column, "") if binary_column else key_row.get(key_binary_column, "") if key_binary_column else ""
                actual_attack = normalise_label(raw_actual)
                actual_binary = normalise_binary(raw_binary)
                if not actual_attack and actual_binary:
                    # Binary-only rows are still evaluated for benign/malicious but cannot contribute to multiclass metrics.
                    actual_attack = "BENIGN" if actual_binary == "BENIGN" else "MALICIOUS"
                if not actual_attack:
                    skipped_missing_label += 1
                    continue
                text = str(row.get(text_column, "")).strip()
                try:
                    result = classifier.predict(text)
                except Exception:
                    skipped_invalid_text += 1
                    continue
                predicted = result["predicted_attack"]
                probability_map = {item["label"]: float(item["probability"]) for item in result.get("probabilities", [])}
                top3 = [item["label"] for item in result.get("probabilities", [])[:3]]
                if actual_attack not in classifier.classes and actual_attack not in {"MALICIOUS"}:
                    unknown_labels[actual_attack] += 1
                if actual_attack == "MALICIOUS":
                    # Binary-only malicious labels cannot be scored at class level; use predicted attack only for binary evaluation.
                    actual_for_multiclass = predicted
                else:
                    actual_for_multiclass = actual_attack
                actual_binary = actual_binary or ("BENIGN" if actual_attack == "BENIGN" else "MALICIOUS")
                item = {
                    "record_id": record_id,
                    "incident_text": text[:500],
                    "actual_attack": actual_for_multiclass,
                    "actual_binary_label": actual_binary,
                    "predicted_attack": predicted,
                    "predicted_binary_label": result["binary_label"],
                    "confidence": float(result["confidence"]),
                    "margin": float(result.get("margin", 0.0)),
                    "decision": result["decision"],
                    "top3": top3,
                    "probability_map": probability_map,
                    "severity": result["severity"],
                    "recommended_action": result["recommended_action"],
                    "binary_only_actual": actual_attack == "MALICIOUS",
                }
                records.append(item)
                distribution[predicted] += 1
                enriched = dict(row)
                enriched.update({
                    "actual_attack": actual_attack,
                    "actual_binary_label": actual_binary,
                    "predicted_attack": predicted,
                    "predicted_binary_label": result["binary_label"],
                    "prediction_confidence": f"{result['confidence']:.8f}",
                    "prediction_margin": f"{result.get('margin', 0.0):.8f}",
                    "prediction_decision": result["decision"],
                    "top3_predictions": " | ".join(top3),
                    "correct_multiclass": actual_attack == predicted if actual_attack != "MALICIOUS" else "",
                    "correct_binary": actual_binary == result["binary_label"],
                    "predicted_severity": result["severity"],
                    "recommended_action": result["recommended_action"],
                })
                writer.writerow(enriched)
                if len(preview) < 40:
                    preview.append({
                        "record_id": record_id,
                        "incident_text": text[:260],
                        "actual_attack": actual_attack,
                        "predicted_attack": predicted,
                        "confidence": result["confidence"],
                        "decision": result["decision"],
                        "correct": actual_attack == predicted if actual_attack != "MALICIOUS" else actual_binary == result["binary_label"],
                    })

    multiclass_records = [record for record in records if not record.get("binary_only_actual")]
    if not multiclass_records:
        raise ValueError("No fine-grained attack labels were available. Provide attack_type/label/class values for multiclass NLP evaluation.")
    evaluation = evaluate_records(multiclass_records, classifier.classes)
    evaluation["dataset"] = {
        "filename": original_name,
        "answer_key_filename": answer_key_name or "",
        "text_column": text_column,
        "label_column": label_column or key_label_column or "",
        "id_column": id_column or "",
        "total_evaluated": len(multiclass_records),
        "skipped_missing_label": skipped_missing_label,
        "skipped_invalid_text": skipped_invalid_text,
        "unmatched_answer_key_records": unmatched_answer_key,
        "unknown_label_counts": dict(unknown_labels),
        "source_is_synthetic": all(str(row.get("synthetic", "")).strip().lower() in {"true", "1", "yes"} for row in []),
    }
    evaluation["scientific_note"] = "Evaluation metrics describe only the supplied labelled dataset. Synthetic results are not evidence of real-world performance."

    summary_path.write_text(json.dumps(evaluation, indent=2, ensure_ascii=False), encoding="utf-8")
    with per_class_path.open("w", newline="", encoding="utf-8-sig") as handle:
        fields = ["label", "precision", "recall", "f1", "support", "predicted_count", "true_positive", "false_positive", "false_negative", "supported_by_model"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(evaluation["per_class"])
    with confusion_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(["actual\\predicted"] + evaluation["labels"])
        for label, values in zip(evaluation["labels"], evaluation["confusion_matrix"]):
            writer.writerow([label] + values)
    with errors_path.open("w", newline="", encoding="utf-8-sig") as handle:
        fields = ["record_id", "incident_text", "actual_attack", "predicted_attack", "confidence", "decision", "top3"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for error in evaluation["errors"]:
            row = dict(error)
            row["top3"] = " | ".join(row.get("top3", []))
            writer.writerow(row)
    with calibration_path.open("w", newline="", encoding="utf-8-sig") as handle:
        fields = ["lower", "upper", "count", "average_confidence", "accuracy", "gap"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(evaluation["calibration_bins"])

    relative = lambda path: str(path.relative_to(output_dir.parent.parent)).replace("\\", "/")
    return {
        "filename": original_name,
        "answer_key_filename": answer_key_name or "",
        "row_count": len(multiclass_records),
        "text_column": text_column,
        "label_column": label_column or key_label_column or "",
        "id_column": id_column or "",
        "class_distribution": distribution.most_common(),
        "evaluation": evaluation,
        "preview": preview,
        "downloads": {
            "predictions": relative(prediction_path),
            "summary_json": relative(summary_path),
            "per_class_csv": relative(per_class_path),
            "confusion_csv": relative(confusion_path),
            "errors_csv": relative(errors_path),
            "calibration_csv": relative(calibration_path),
        },
    }
