from __future__ import annotations

import csv
import gzip
import hashlib
import json
import math
import mimetypes
import os
import pickle
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import uuid
import webbrowser
from collections import Counter, defaultdict
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from nlp_classifier import PortableTextClassifier
from nlp_evaluation import evaluate_text_dataset
from realworld_nlp import train_realworld_model
from incident_multilabel import PortableIncidentMultiLabelClassifier, evaluate_csv as evaluate_incident_csv

APP_NAME = "AI Based Cybercrime Prediction System"
ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "web"
MODEL_PATH = ROOT / "models" / "portable_prediction_model.pkl.gz"
SYNTHETIC_TEXT_MODEL_PATH = ROOT / "models" / "portable_text_classifier.json.gz"
SYNTHETIC_TEXT_METRICS_PATH = ROOT / "models" / "text_classifier_metrics.json"
REAL_TEXT_MODEL_PATH = ROOT / "models" / "portable_text_classifier_realworld.json.gz"
REAL_TEXT_METRICS_PATH = ROOT / "models" / "realworld_text_metrics.json"
REAL_TEXT_CARD_PATH = ROOT / "models" / "realworld_text_model_card.json"
INCIDENT_MODEL_PATH = ROOT / "models" / "real_incident_multilabel_classifier.json.gz"
INCIDENT_METRICS_PATH = ROOT / "models" / "real_incident_multilabel_metrics.json"
INCIDENT_CARD_PATH = ROOT / "models" / "real_incident_multilabel_model_card.json"
INCIDENT_EVALUATIONS_DIR = ROOT / "outputs" / "real_incident_evaluations"
ACTIVE_TEXT_POINTER = ROOT / "models" / "active_text_model.json"
REAL_TRAINING_DIR = ROOT / "outputs" / "realworld_training"
REAL_DATA_DIR = ROOT / "data" / "real" / "raw"
TEXT_PREDICTIONS_DIR = ROOT / "outputs" / "text_predictions"
TEXT_EVALUATIONS_DIR = ROOT / "outputs" / "text_evaluations"
WINDOWS_PATH = ROOT / "data" / "processed" / "universal_pre_attack_windows.csv"
PREDICTIONS_PATH = ROOT / "outputs" / "predictions" / "multihorizon_test_predictions.csv"
LOG_PATH = ROOT / "outputs" / "logs" / "portable_server.log"
RUNTIME_PATH = ROOT / "outputs" / "runtime_status.json"
UPLOADS = ROOT / "data" / "uploads"
MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB
UPLOAD_CHUNK_BYTES = 8 * 1024 * 1024       # 8 MiB
UPLOAD_JOBS: dict[str, dict[str, Any]] = {}
UPLOAD_LOCK = threading.Lock()
TEXT_MODEL_LOCK = threading.RLock()
REAL_TRAINING_LOCK = threading.Lock()
REAL_TRAINING_JOBS: dict[str, dict[str, Any]] = {}

for directory in (LOG_PATH.parent, UPLOADS, TEXT_PREDICTIONS_DIR, TEXT_EVALUATIONS_DIR, REAL_TRAINING_DIR, REAL_DATA_DIR, INCIDENT_EVALUATIONS_DIR):
    directory.mkdir(parents=True, exist_ok=True)


def log(message: str) -> None:
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}"
    print(line, flush=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


with gzip.open(MODEL_PATH, "rb") as handle:
    MODEL = pickle.load(handle)
FEATURES = list(MODEL["feature_columns"])
METRICS = load_json(ROOT / "models" / "cybercrime_prediction_metrics.json", {})
MODEL_CARD = load_json(ROOT / "models" / "model_card.json", {})
MANIFEST = load_json(ROOT / "MODEL_MANIFEST.json", {})
def _resolve_active_text_files() -> tuple[Path, Path, Path | None]:
    pointer = load_json(ACTIVE_TEXT_POINTER, {})
    model_value = pointer.get("model_path") if isinstance(pointer, dict) else None
    metrics_value = pointer.get("metrics_path") if isinstance(pointer, dict) else None
    card_value = pointer.get("model_card_path") if isinstance(pointer, dict) else None
    model_path = ROOT / model_value if model_value else SYNTHETIC_TEXT_MODEL_PATH
    metrics_path = ROOT / metrics_value if metrics_value else SYNTHETIC_TEXT_METRICS_PATH
    card_path = ROOT / card_value if card_value else ROOT / "models" / "text_model_card.json"
    if not model_path.exists():
        model_path, metrics_path, card_path = SYNTHETIC_TEXT_MODEL_PATH, SYNTHETIC_TEXT_METRICS_PATH, ROOT / "models" / "text_model_card.json"
    return model_path, metrics_path, card_path


def _reload_text_model() -> None:
    global TEXT_MODEL_PATH, TEXT_METRICS_PATH, TEXT_CARD_PATH, TEXT_CLASSIFIER, TEXT_METRICS, TEXT_MODEL_CARD
    model_path, metrics_path, card_path = _resolve_active_text_files()
    classifier = PortableTextClassifier.load(model_path)
    with TEXT_MODEL_LOCK:
        TEXT_MODEL_PATH = model_path
        TEXT_METRICS_PATH = metrics_path
        TEXT_CARD_PATH = card_path
        TEXT_CLASSIFIER = classifier
        TEXT_METRICS = load_json(metrics_path, {})
        TEXT_MODEL_CARD = load_json(card_path, {}) if card_path else {}


def get_text_classifier() -> PortableTextClassifier:
    with TEXT_MODEL_LOCK:
        return TEXT_CLASSIFIER


def activate_text_model(mode: str) -> dict[str, Any]:
    if mode == "real":
        if not REAL_TEXT_MODEL_PATH.exists():
            raise FileNotFoundError("No real-data NLP model has been trained yet.")
        pointer = {
            "model_path": str(REAL_TEXT_MODEL_PATH.relative_to(ROOT)).replace("\\", "/"),
            "metrics_path": str(REAL_TEXT_METRICS_PATH.relative_to(ROOT)).replace("\\", "/"),
            "model_card_path": str(REAL_TEXT_CARD_PATH.relative_to(ROOT)).replace("\\", "/"),
            "activated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        ACTIVE_TEXT_POINTER.write_text(json.dumps(pointer, indent=2), encoding="utf-8")
    elif mode == "synthetic":
        ACTIVE_TEXT_POINTER.unlink(missing_ok=True)
    else:
        raise ValueError("Mode must be real or synthetic.")
    _reload_text_model()
    return text_model_summary()


TEXT_MODEL_PATH: Path
TEXT_METRICS_PATH: Path
TEXT_CARD_PATH: Path | None
TEXT_CLASSIFIER: PortableTextClassifier
TEXT_METRICS: dict[str, Any]
TEXT_MODEL_CARD: dict[str, Any]
_reload_text_model()
INCIDENT_CLASSIFIER = PortableIncidentMultiLabelClassifier.load(INCIDENT_MODEL_PATH)
INCIDENT_METRICS = load_json(INCIDENT_METRICS_PATH, {})
INCIDENT_CARD = load_json(INCIDENT_CARD_PATH, {})

def incident_model_summary() -> dict[str, Any]:
    primary = INCIDENT_METRICS.get("primary_test_metrics", {})
    return {"name": INCIDENT_CARD.get("name", "Real Incident Multi-Label Classifier"), "algorithm": INCIDENT_CARD.get("algorithm", "Portable multi-label linear model"), "source_is_synthetic": False, "validation_status": "real_data_internal_chronological_holdout", "training_records": INCIDENT_CARD.get("training_records", 0), "validation_records": INCIDENT_CARD.get("validation_records", 0), "test_records": INCIDENT_CARD.get("test_records", 0), "feature_count": INCIDENT_CARD.get("features", len(INCIDENT_CLASSIFIER.vocabulary)), "primary_labels": INCIDENT_CLASSIFIER.primary_labels, "experimental_labels": INCIDENT_CLASSIFIER.experimental_labels, "primary_test_metrics": primary, "model_sha256": hashlib.sha256(INCIDENT_MODEL_PATH.read_bytes()).hexdigest(), "scientific_status": INCIDENT_CLASSIFIER.model.get("scientific_note", "")}


def sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-min(value, 700.0))
        return 1.0 / (1.0 + z)
    z = math.exp(max(value, -700.0))
    return z / (1.0 + z)


def tree_probability(tree: dict[str, Any], values: list[float]) -> list[float]:
    node = 0
    left, right, feature, threshold = tree["l"], tree["r"], tree["f"], tree["t"]
    while left[node] != -1:
        idx = feature[node]
        current = values[idx] if 0 <= idx < len(values) else 0.0
        node = left[node] if current <= threshold[node] else right[node]
    probs = tree["v"][node]
    total = sum(probs)
    return [float(x) / total for x in probs] if total else [0.0 for _ in probs]


def forest_probability(forest: dict[str, Any], values: list[float]) -> list[float]:
    classes = forest["classes"]
    output = [0.0] * len(classes)
    trees = forest["trees"]
    for tree in trees:
        probs = tree_probability(tree, values)
        for i, probability in enumerate(probs):
            output[i] += probability
    count = max(len(trees), 1)
    return [x / count for x in output]


def score_features(feature_map: dict[str, Any]) -> dict[str, Any]:
    values = []
    for feature in FEATURES:
        try:
            value = float(feature_map.get(feature, 0.0) or 0.0)
            if not math.isfinite(value):
                value = 0.0
        except Exception:
            value = 0.0
        values.append(value)

    horizon_results: dict[str, Any] = {}
    for h in sorted(MODEL["horizons"], key=int):
        stage = MODEL["horizons"][h]
        binary = forest_probability(stage["binary_forest"], values)
        raw_probability = binary[1] if len(binary) > 1 else binary[0]
        calibration = stage.get("binary_calibrator")
        if calibration:
            p = min(max(raw_probability, 1e-6), 1.0 - 1e-6)
            raw_logit = math.log(p / (1.0 - p))
            probability = sigmoid(calibration["coef"] * raw_logit + calibration["intercept"])
        else:
            probability = raw_probability
        threshold_value = float(stage["threshold"])
        warning = probability >= threshold_value
        uncertain = abs(probability - threshold_value) <= 0.05

        type_probs = forest_probability(stage["type_forest"], values)
        type_index = max(range(len(type_probs)), key=type_probs.__getitem__) if type_probs else 0
        type_confidence = type_probs[type_index] if type_probs else 0.0
        labels = stage["type_labels"]
        predicted_type = labels[type_index] if type_index < len(labels) else "UNKNOWN_ATTACK"
        if not warning:
            final_type = "NO_THREAT"
        elif type_confidence < 0.45:
            final_type = "UNKNOWN_ATTACK"
        else:
            final_type = predicted_type
        decision = "REVIEW" if uncertain else ("WARNING" if warning else "CLEAR")
        horizon_results[str(h)] = {
            "horizon_seconds": int(h),
            "probability": probability,
            "threshold": threshold_value,
            "warning": warning,
            "decision": decision,
            "attack_type": final_type,
            "type_confidence": type_confidence if warning else 1.0 - probability,
        }

    selected = max(horizon_results.values(), key=lambda item: item["probability"])
    risk_score = round(selected["probability"] * 100)
    if selected["decision"] == "REVIEW":
        risk_level, priority = "Under Review", "P3"
    elif selected["warning"] and risk_score >= 85:
        risk_level, priority = "Critical", "P1"
    elif selected["warning"]:
        risk_level, priority = "High", "P2"
    elif risk_score >= 40:
        risk_level, priority = "Medium", "P3"
    else:
        risk_level, priority = "Low", "P4"
    attack = selected["attack_type"]
    actions = {
        "DDOS": "Apply rate limiting, validate upstream filtering, and protect the targeted service.",
        "DOS_HULK": "Throttle repeated HTTP requests and activate application-layer protections.",
        "DOS_GOLDENEYE": "Inspect abnormal keep-alive sessions and enforce connection limits.",
        "DOS_SLOWLORIS": "Reduce header timeouts and restrict slow incomplete connections.",
        "DOS_SLOWHTTPTEST": "Enforce request-body timeouts and limit concurrent slow sessions.",
        "PORTSCAN": "Inspect source fan-out, restrict unnecessary ports, and review firewall telemetry.",
        "BOT": "Isolate the suspected endpoint and inspect command-and-control communication.",
        "FTP_PATATOR": "Rate-limit FTP authentication and review repeated login failures.",
        "SSH_PATATOR": "Rate-limit SSH authentication and require strong key-based access.",
        "WEB_ATTACK_BRUTE_FORCE": "Apply account lockout controls and inspect repeated web authentication attempts.",
        "WEB_ATTACK_SQL_INJECTION": "Enable relevant WAF rules and review parameterised-query controls.",
        "WEB_ATTACK_XSS": "Enable output encoding, CSP controls, and relevant WAF protections.",
        "INFILTRATION": "Segment the affected endpoint and inspect unusual internal movement.",
        "HEARTBLEED": "Patch vulnerable TLS services and rotate exposed credentials or keys.",
        "UNKNOWN_ATTACK": "Escalate for analyst review and inspect the strongest abnormal traffic signals.",
        "NO_THREAT": "Continue monitoring; no immediate preventive intervention is indicated.",
    }
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "horizons": horizon_results,
        "selected_horizon": selected["horizon_seconds"],
        "current_attack": "No Threat" if attack == "NO_THREAT" else attack.replace("_", " ").title(),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "priority": priority,
        "recommended_action": actions.get(attack, actions["UNKNOWN_ATTACK"]),
    }


def read_windows(limit: int = 4000) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with WINDOWS_PATH.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader):
            rows.append(row)
            if index + 1 >= limit:
                break
    return rows


WINDOW_ROWS = read_windows()
if not WINDOW_ROWS:
    WINDOW_ROWS = [{feature: 0.0 for feature in FEATURES}]


def load_prediction_history() -> list[dict[str, Any]]:
    result = []
    try:
        with PREDICTIONS_PATH.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                result.append(row)
    except Exception:
        pass
    return result


PREDICTION_HISTORY = load_prediction_history()


def feature_deviations(row: dict[str, Any], count: int = 6) -> list[dict[str, Any]]:
    evidence = []
    reference = MODEL.get("feature_reference", {})
    for feature in FEATURES:
        try:
            value = float(row.get(feature, 0.0) or 0.0)
        except Exception:
            continue
        stats = reference.get(feature, {})
        mean = float(stats.get("mean", 0.0) or 0.0)
        std = abs(float(stats.get("std", 0.0) or 0.0))
        score = abs(value - mean) / max(std, abs(mean) * 0.05, 1e-9)
        evidence.append({
            "feature": feature.replace("_", " ").title(),
            "value": value,
            "reference": mean,
            "deviation": score,
            "direction": "above" if value >= mean else "below",
        })
    evidence.sort(key=lambda item: item["deviation"], reverse=True)
    return evidence[:count]


@dataclass
class MonitorState:
    running: bool = True
    index: int = 0
    interval: float = 2.0
    mode: str = "Demonstration Replay"
    latest: dict[str, Any] | None = None
    history: list[dict[str, Any]] | None = None


STATE = MonitorState(history=[])
STATE_LOCK = threading.Lock()


def update_monitor() -> None:
    while True:
        with STATE_LOCK:
            running = STATE.running
            interval = STATE.interval
        if running:
            row = WINDOW_ROWS[STATE.index % len(WINDOW_ROWS)]
            prediction = score_features(row)
            prediction["window_start"] = row.get("window_start", "")
            prediction["window_end"] = row.get("window_end", "")
            prediction["evidence"] = feature_deviations(row)
            prediction["mode"] = STATE.mode
            with STATE_LOCK:
                STATE.latest = prediction
                STATE.index = (STATE.index + 1) % len(WINDOW_ROWS)
                history_item = {
                    "time": time.strftime("%H:%M:%S"),
                    **{f"p{h}": prediction["horizons"][str(h)]["probability"] for h in (5, 10, 30)},
                    "attack": prediction["current_attack"],
                    "risk": prediction["risk_score"],
                }
                STATE.history.append(history_item)
                STATE.history = STATE.history[-60:]
        time.sleep(max(interval, 0.5))


def metrics_summary() -> list[dict[str, Any]]:
    records = []
    horizon_metrics = METRICS.get("horizons", METRICS.get("horizon_metrics", {})) if isinstance(METRICS, dict) else {}
    for h in (5, 10, 30):
        raw = horizon_metrics.get(str(h), horizon_metrics.get(h, {})) if isinstance(horizon_metrics, dict) else {}
        records.append({
            "horizon": h,
            "precision": float(raw.get("test_precision", raw.get("precision", 0.0)) or 0.0),
            "recall": float(raw.get("test_recall", raw.get("recall", 0.0)) or 0.0),
            "f1": float(raw.get("test_f1", raw.get("f1", 0.0)) or 0.0),
            "pr_auc": float(raw.get("test_pr_auc", raw.get("pr_auc", 0.0)) or 0.0),
            "threshold": float(MODEL["horizons"][h]["threshold"]),
            "model": MODEL["horizons"][h]["binary_model_name"],
        })
    return records


def threat_catalogue() -> list[dict[str, Any]]:
    labels = MODEL["horizons"][5]["supported_attack_types"]
    counts = Counter()
    for row in WINDOW_ROWS:
        for key in ("future_attack_type_5s", "future_attack_type_10s", "future_attack_type_30s"):
            label = (row.get(key) or "").strip()
            if label and label not in {"NO_ATTACK", "BENIGN"}:
                counts[label] += 1
    severity = {
        "DDOS":"Critical", "HEARTBLEED":"Critical", "INFILTRATION":"Critical",
        "DOS_HULK":"High", "DOS_GOLDENEYE":"High", "DOS_SLOWLORIS":"High", "DOS_SLOWHTTPTEST":"High",
        "BOT":"High", "WEB_ATTACK_SQL_INJECTION":"High", "PORTSCAN":"Medium",
    }
    return [{
        "attack": label.replace("_", " ").title(),
        "code": label,
        "severity": severity.get(label, "Medium"),
        "examples": counts.get(label, 0),
        "status": "Demonstration Ready",
    } for label in labels]


def bundle_validation() -> dict[str, Any]:
    missing = []
    if len(FEATURES) != 91:
        missing.append("91-feature schema")
    for h in (5, 10, 30):
        if h not in MODEL["horizons"]:
            missing.append(f"{h}-second forecasting stage")
    if not TEXT_MODEL_PATH.exists():
        missing.append("portable NLP text model")
    if len(get_text_classifier().classes) < 2:
        missing.append("NLP class schema")
    if not INCIDENT_MODEL_PATH.exists() or len(INCIDENT_CLASSIFIER.labels) < 2:
        missing.append("real incident multi-label NLP model")
    return {
        "valid": not missing,
        "feature_count": len(FEATURES),
        "horizon_count": len(MODEL["horizons"]),
        "horizons": sorted(MODEL["horizons"]),
        "source": MODEL["source_name"],
        "source_is_synthetic": bool(MODEL["source_is_synthetic"]),
        "missing": missing,
        "model_checksum": hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest(),
        "text_model_valid": TEXT_MODEL_PATH.exists() and len(get_text_classifier().classes) >= 2,
        "text_class_count": len(get_text_classifier().classes),
        "text_model_checksum": hashlib.sha256(TEXT_MODEL_PATH.read_bytes()).hexdigest() if TEXT_MODEL_PATH.exists() else "",
        "incident_multilabel_valid": INCIDENT_MODEL_PATH.exists() and len(INCIDENT_CLASSIFIER.labels) >= 2,
        "incident_label_count": len(INCIDENT_CLASSIFIER.labels),
        "incident_model_checksum": hashlib.sha256(INCIDENT_MODEL_PATH.read_bytes()).hexdigest() if INCIDENT_MODEL_PATH.exists() else "",
    }


def _set_job(job_id: str, **updates: Any) -> None:
    with UPLOAD_LOCK:
        job = UPLOAD_JOBS.get(job_id)
        if job is not None:
            job.update(updates)


def _job_snapshot(job_id: str) -> dict[str, Any] | None:
    with UPLOAD_LOCK:
        job = UPLOAD_JOBS.get(job_id)
        if job is None:
            return None
        return {k: v for k, v in job.items() if k not in {"temp_path", "final_path"}}


def _safe_filename(name: str) -> str:
    decoded = urllib.parse.unquote(name or "uploaded_file")
    cleaned = "".join(ch for ch in decoded if ch.isalnum() or ch in " ._-()")
    cleaned = cleaned.strip(" .") or "uploaded_file"
    return cleaned[:180]


def pcap_audit(path: Path, progress: Any | None = None) -> dict[str, Any]:
    file_size = max(path.stat().st_size, 1)
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) < 24:
            raise ValueError("The file is too short to be a PCAP capture.")
        magic = header[:4]
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
            b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
            b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
            b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
        }
        if magic not in formats:
            raise ValueError("Unsupported capture format. Use a classic PCAP file.")
        endian, divisor = formats[magic]
        _, major, minor, _, _, snaplen, network = struct.unpack(endian + "IHHIIII", header)
        packets = 0
        bytes_captured = 0
        start = None
        end = None
        lengths = []
        protocols = Counter()
        sources = Counter()
        destinations = Counter()
        ports = Counter()
        while True:
            record = handle.read(16)
            if not record:
                break
            if len(record) < 16:
                break
            ts_sec, ts_sub, incl_len, orig_len = struct.unpack(endian + "IIII", record)
            payload = handle.read(incl_len)
            if len(payload) < incl_len:
                break
            timestamp = ts_sec + ts_sub / divisor
            start = timestamp if start is None else min(start, timestamp)
            end = timestamp if end is None else max(end, timestamp)
            packets += 1
            bytes_captured += incl_len
            lengths.append(orig_len)
            if network == 1 and len(payload) >= 14:
                ethertype = struct.unpack("!H", payload[12:14])[0]
                offset = 14
                if ethertype == 0x8100 and len(payload) >= 18:
                    ethertype = struct.unpack("!H", payload[16:18])[0]
                    offset = 18
                if ethertype == 0x0800 and len(payload) >= offset + 20:
                    ihl = (payload[offset] & 0x0F) * 4
                    proto = payload[offset + 9]
                    src = ".".join(str(x) for x in payload[offset+12:offset+16])
                    dst = ".".join(str(x) for x in payload[offset+16:offset+20])
                    sources[src] += 1
                    destinations[dst] += 1
                    protocols[{6:"TCP",17:"UDP",1:"ICMP"}.get(proto, str(proto))] += 1
                    trans = offset + ihl
                    if proto in (6,17) and len(payload) >= trans + 4:
                        _, dport = struct.unpack("!HH", payload[trans:trans+4])
                        ports[dport] += 1
            if progress and packets % 5000 == 0:
                progress(min(handle.tell() / file_size, 0.995), f"Inspecting packet {packets:,}")
        if progress:
            progress(1.0, f"Inspected {packets:,} packets")
        duration = max((end or 0) - (start or 0), 0.0)
        return {
            "filename": path.name,
            "file_size_bytes": path.stat().st_size,
            "format": "Classic PCAP",
            "version": f"{major}.{minor}",
            "link_type": network,
            "snap_length": snaplen,
            "packet_count": packets,
            "captured_bytes": bytes_captured,
            "duration_seconds": duration,
            "average_packet_size": statistics.fmean(lengths) if lengths else 0.0,
            "min_packet_size": min(lengths) if lengths else 0,
            "max_packet_size": max(lengths) if lengths else 0,
            "protocols": protocols.most_common(8),
            "top_sources": sources.most_common(8),
            "top_destinations": destinations.most_common(8),
            "top_destination_ports": ports.most_common(8),
            "label_status": "UNLABELLED",
        }


def csv_audit(path: Path, progress: Any | None = None) -> dict[str, Any]:
    file_size = max(path.stat().st_size, 1)
    rows = 0
    missing = 0
    duplicate_rows = 0
    duplicate_scan_limit = 500_000
    seen_hashes: set[int] = set()
    labels = Counter()
    timestamps: list[str] = []
    columns: list[str] = []
    label_col = None
    time_col = None
    last_update = 0.0

    with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        columns = reader.fieldnames or []
        label_col = next((c for c in columns if c.strip().lower() in {"label", "attack type", "attack_type", "class", "binary_label"}), None)
        time_col = next((c for c in columns if "timestamp" in c.strip().lower() or c.strip().lower() in {"time", "date"}), None)
        text_col = next((c for c in columns if c.strip().lower() in {"incident_text", "incident text", "description", "incident_description", "report_text", "text", "message"}), None)
        for row in reader:
            rows += 1
            values = tuple(row.get(c, "") for c in columns)
            if rows <= duplicate_scan_limit:
                # A compact stable row hash avoids storing hundreds of thousands of full rows.
                digest = hashlib.blake2b("\x1f".join(str(v) for v in values).encode("utf-8", "replace"), digest_size=8).digest()
                row_hash = int.from_bytes(digest, "little")
                if row_hash in seen_hashes:
                    duplicate_rows += 1
                else:
                    seen_hashes.add(row_hash)
            missing += sum(1 for value in values if value is None or not str(value).strip())
            if label_col:
                labels[str(row.get(label_col, "")).strip() or "MISSING"] += 1
            if time_col:
                value = str(row.get(time_col, "")).strip()
                if value and len(timestamps) < 3:
                    timestamps.append(value)
            if progress and rows % 5000 == 0:
                try:
                    fraction = min(handle.buffer.tell() / file_size, 0.995)
                except Exception:
                    fraction = min(rows / max(rows + 1, 1), 0.995)
                now = time.time()
                if now - last_update >= 0.25:
                    progress(fraction, f"Scanning row {rows:,}")
                    last_update = now
    if progress:
        progress(1.0, f"Scanned {rows:,} rows")
    return {
        "filename": path.name,
        "file_size_bytes": path.stat().st_size,
        "row_count": rows,
        "column_count": len(columns),
        "columns": columns,
        "missing_cells": missing,
        "duplicate_rows_observed": duplicate_rows,
        "duplicate_scan_rows": min(rows, duplicate_scan_limit),
        "duplicate_note": "Duplicate detection is exact within the first 500,000 rows and memory-safe for very large files.",
        "label_column": label_col,
        "timestamp_column": time_col,
        "text_column": text_col,
        "label_distribution": labels.most_common(20),
        "timestamp_examples": timestamps,
        "network_readiness": "Ready for temporal review" if label_col and time_col else "Requires timestamp and label alignment",
        "nlp_readiness": ("Ready for NLP evaluation" if text_col and label_col else "Ready for NLP prediction" if text_col else "No incident-text column detected"),
        "readiness": ("Ready for NLP evaluation" if text_col and label_col else "Ready for NLP prediction" if text_col else "Ready for temporal review" if label_col and time_col else "Requires timestamp and label alignment"),
    }


def _audit_upload(job_id: str) -> None:
    with UPLOAD_LOCK:
        job = UPLOAD_JOBS.get(job_id)
        if not job:
            return
        path = Path(job["final_path"])
        original_name = job["filename"]
        job["status"] = "auditing"
        job["audit_progress"] = 0.0
        job["message"] = "Preparing local audit"

    def callback(value: float, message: str) -> None:
        _set_job(job_id, audit_progress=max(0.0, min(float(value), 1.0)), message=message)

    try:
        suffix = Path(original_name).suffix.lower()
        if suffix in {".pcap", ".cap"} or not suffix:
            result = pcap_audit(path, callback)
            kind = "pcap"
        elif suffix == ".csv":
            result = csv_audit(path, callback)
            kind = "csv"
        else:
            raise ValueError("Portable intake supports CSV and classic PCAP files.")
        _set_job(job_id, status="complete", audit_progress=1.0, message="Audit completed", audit=result, kind=kind,
                 saved_as=str(path.relative_to(ROOT)).replace("\\", "/"))
        log(f"Upload audit complete: {original_name} ({path.stat().st_size:,} bytes)")
    except Exception as exc:
        _set_job(job_id, status="error", message="Audit failed", error=str(exc))
        log(f"Upload audit failed for {original_name}: {type(exc).__name__}: {exc}")



def text_model_summary() -> dict[str, Any]:
    with TEXT_MODEL_LOCK:
        classifier = TEXT_CLASSIFIER
        metrics = dict(TEXT_METRICS) if isinstance(TEXT_METRICS, dict) else {}
        path = TEXT_MODEL_PATH
    synthetic_external = metrics.get("independent_synthetic_test", {})
    synthetic_internal = metrics.get("internal_synthetic_test", {})
    internal_real = metrics.get("internal_test_metrics", {})
    external_real = metrics.get("external_test_metrics") or {}
    source_is_synthetic = bool(classifier.model.get("source_is_synthetic", True))
    validation_status = classifier.model.get("validation_status", "synthetic_demonstration" if source_is_synthetic else "internal_real_data")
    preferred = external_real or internal_real or synthetic_external or synthetic_internal
    return {
        "name": classifier.model.get("model_name", metrics.get("model_name", "Cybercrime Incident Text Classifier")),
        "algorithm": classifier.model.get("algorithm", metrics.get("algorithm", "Portable text classifier")),
        "classes": classifier.classes,
        "class_count": len(classifier.classes),
        "training_records": int(classifier.model.get("training_records", 0)),
        "vocabulary_size": int(classifier.model.get("vocabulary_size", 0)),
        "source_name": classifier.model.get("source_name", "Synthetic demonstration corpus"),
        "source_is_synthetic": source_is_synthetic,
        "validation_status": validation_status,
        "feature_profile": classifier.model.get("feature_profile", "word"),
        "internal_accuracy": float((internal_real or synthetic_internal).get("accuracy", 0.0) or 0.0),
        "internal_macro_f1": float((internal_real or synthetic_internal).get("macro_f1", 0.0) or 0.0),
        "external_accuracy": float((external_real or synthetic_external).get("accuracy", 0.0) or 0.0),
        "external_macro_f1": float((external_real or synthetic_external).get("macro_f1", 0.0) or 0.0),
        "display_accuracy": float(preferred.get("accuracy", 0.0) or 0.0),
        "display_macro_f1": float(preferred.get("macro_f1", 0.0) or 0.0),
        "checksum": hashlib.sha256(path.read_bytes()).hexdigest(),
        "active_model_path": str(path.relative_to(ROOT)).replace("\\", "/"),
        "real_model_available": REAL_TEXT_MODEL_PATH.exists(),
        "scientific_status": metrics.get("scientific_note") or metrics.get("scientific_status") or (
            "Externally validated on an independent labelled source." if validation_status == "externally_validated" else
            "Internally validated on real data; independent source-domain testing remains required." if not source_is_synthetic else
            "Synthetic demonstration only; not real-world evidence."
        ),
    }


def _normalise_label(value: str) -> str:
    return str(value or "").strip().upper().replace(" ", "_").replace("-", "_")


def classify_text_csv(path: Path, original_name: str) -> dict[str, Any]:
    output_name = f"text_predictions_{time.strftime('%Y%m%d_%H%M%S')}_{Path(original_name).stem[:60]}.csv"
    output_path = TEXT_PREDICTIONS_DIR / output_name
    preview: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    y_true: list[str] = []
    y_pred: list[str] = []
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as source:
        reader = csv.DictReader(source)
        columns = reader.fieldnames or []
        text_column = next((c for c in columns if c.strip().lower() in {"incident_text", "incident text", "description", "incident_description", "report_text", "text", "message"}), None)
        label_column = next((c for c in columns if c.strip().lower() in {"attack_type", "attack type", "label", "class"}), None)
        id_column = next((c for c in columns if c.strip().lower() in {"record_id", "id", "incident_id", "case_id"}), None)
        if not text_column:
            raise ValueError("No incident-text column was detected. Use incident_text, description, incident_description, report_text, text, or message.")
        fieldnames = list(columns) + ["predicted_attack", "predicted_binary_label", "prediction_confidence", "prediction_decision", "predicted_severity", "recommended_action"]
        with output_path.open("w", newline="", encoding="utf-8-sig") as target:
            writer = csv.DictWriter(target, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for index, row in enumerate(reader, start=1):
                result = get_text_classifier().predict(str(row.get(text_column, "")))
                predicted = result["predicted_attack"]
                counts[predicted] += 1
                if label_column and str(row.get(label_column, "")).strip():
                    y_true.append(_normalise_label(row.get(label_column, "")))
                    y_pred.append(predicted)
                enriched = dict(row)
                enriched.update({
                    "predicted_attack": predicted,
                    "predicted_binary_label": result["binary_label"],
                    "prediction_confidence": f"{result['confidence']:.6f}",
                    "prediction_decision": result["decision"],
                    "predicted_severity": result["severity"],
                    "recommended_action": result["recommended_action"],
                })
                writer.writerow(enriched)
                if len(preview) < 50:
                    preview.append({
                        "record_id": str(row.get(id_column, index)) if id_column else str(index),
                        "incident_text": str(row.get(text_column, ""))[:260],
                        "predicted_attack": predicted,
                        "binary_label": result["binary_label"],
                        "confidence": result["confidence"],
                        "decision": result["decision"],
                        "actual_attack": _normalise_label(row.get(label_column, "")) if label_column else "",
                    })
    evaluation: dict[str, Any] | None = None
    if y_true:
        classes = sorted(set(get_text_classifier().classes) | set(y_true) | set(y_pred))
        per_class: dict[str, Any] = {}
        f1_values: list[float] = []
        for label in classes:
            tp = sum(a == label and b == label for a, b in zip(y_true, y_pred))
            fp = sum(a != label and b == label for a, b in zip(y_true, y_pred))
            fn = sum(a == label and b != label for a, b in zip(y_true, y_pred))
            precision = tp / (tp + fp) if tp + fp else 0.0
            recall = tp / (tp + fn) if tp + fn else 0.0
            f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
            f1_values.append(f1)
            per_class[label] = {"precision": precision, "recall": recall, "f1": f1, "support": sum(a == label for a in y_true)}
        evaluation = {
            "records": len(y_true),
            "accuracy": sum(a == b for a, b in zip(y_true, y_pred)) / max(len(y_true), 1),
            "macro_f1": sum(f1_values) / max(len(f1_values), 1),
            "per_class": per_class,
        }
    return {
        "filename": original_name,
        "row_count": sum(counts.values()),
        "text_column": text_column,
        "label_column": label_column,
        "class_distribution": counts.most_common(),
        "preview": preview,
        "evaluation": evaluation,
        "download_path": str(output_path.relative_to(ROOT)).replace("\\", "/"),
    }


def _real_job_snapshot(job_id: str) -> dict[str, Any] | None:
    with REAL_TRAINING_LOCK:
        job = REAL_TRAINING_JOBS.get(job_id)
        return dict(job) if job else None


def _set_real_job(job_id: str, **updates: Any) -> None:
    with REAL_TRAINING_LOCK:
        if job_id in REAL_TRAINING_JOBS:
            REAL_TRAINING_JOBS[job_id].update(updates)


def _real_training_worker(job_id: str, training_path: Path, source_name: str, external_path: Path | None) -> None:
    _set_real_job(job_id, status="running", stage="Auditing and deduplicating real incident narratives", progress=0.12)
    try:
        _set_real_job(job_id, stage="Creating source-aware chronological or group-aware partitions", progress=0.28)
        result = train_realworld_model(
            training_path, REAL_TEXT_MODEL_PATH, REAL_TEXT_METRICS_PATH, REAL_TEXT_CARD_PATH,
            source_display_name=source_name or training_path.name, external_test_path=external_path,
        )
        _set_real_job(job_id, stage="Activating the verified real-data model", progress=0.92)
        activate_text_model("real")
        _set_real_job(job_id, status="complete", stage="Training and validation complete", progress=1.0, result=result)
        log(f"Real-world NLP training completed: {source_name or training_path.name}")
    except Exception as exc:
        _set_real_job(job_id, status="error", stage="Training failed", error=str(exc), progress=1.0)
        log(f"Real-world NLP training failed: {type(exc).__name__}: {exc}")


def realworld_status() -> dict[str, Any]:
    summary = text_model_summary()
    metrics = load_json(REAL_TEXT_METRICS_PATH, {}) if REAL_TEXT_METRICS_PATH.exists() else {}
    latest_jobs = []
    with REAL_TRAINING_LOCK:
        latest_jobs = sorted(REAL_TRAINING_JOBS.values(), key=lambda item: item.get("created_at", ""), reverse=True)[:5]
    return {
        "active": summary,
        "real_model_available": REAL_TEXT_MODEL_PATH.exists(),
        "real_metrics": metrics,
        "latest_jobs": latest_jobs,
        "accepted_formats": ["csv", "json", "jsonl", "ndjson", "json.gz", "zip"],
        "minimum_verified_records": 200,
        "external_validation_required_for_claim": True,
    }


def find_port(start: int = 8765) -> int:
    for port in range(start, start + 500):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free local port was available.")


class Handler(BaseHTTPRequestHandler):
    server_version = "CPSPortable"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        log(f"HTTP {self.address_string()} - {fmt % args}")

    def send_json(self, payload: Any, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def serve_file(self, path: Path, download: bool = False) -> None:
        try:
            resolved = path.resolve()
            if ROOT not in resolved.parents and resolved != ROOT:
                raise PermissionError
            data = resolved.read_bytes()
            mime = mimetypes.guess_type(resolved.name)[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            if download:
                self.send_header("Content-Disposition", f'attachment; filename="{resolved.name}"')
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            self.send_error(404)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        if path == "/api/health":
            self.send_json({"status":"ok", "system":APP_NAME, "validation":bundle_validation()})
            return
        if path == "/api/overview":
            with STATE_LOCK:
                latest = STATE.latest
                history = list(STATE.history or [])
            self.send_json({
                "latest": latest,
                "history": history,
                "metrics": metrics_summary(),
                "validation": bundle_validation(),
                "windows": len(WINDOW_ROWS),
                "attack_classes": len(MODEL["horizons"][5]["supported_attack_types"]),
                "source_is_synthetic": MODEL["source_is_synthetic"],
            })
            return
        if path == "/api/live":
            with STATE_LOCK:
                payload = {
                    "running": STATE.running,
                    "index": STATE.index,
                    "interval": STATE.interval,
                    "mode": STATE.mode,
                    "latest": STATE.latest,
                    "history": list(STATE.history or []),
                }
            self.send_json(payload)
            return
        if path == "/api/threats":
            self.send_json({"attacks":threat_catalogue()})
            return
        if path == "/api/model":
            self.send_json({
                "validation":bundle_validation(),
                "metrics":metrics_summary(),
                "features":FEATURES,
                "feature_families":{
                    "Traffic and rates": [x for x in FEATURES if "flow" in x or "traffic" in x],
                    "Source, destination and ports": [x for x in FEATURES if any(k in x for k in ("source", "destination", "port", "protocol"))],
                    "TCP flags": [x for x in FEATURES if any(k in x for k in ("syn", "ack", "rst"))],
                    "Packet and direction": [x for x in FEATURES if any(k in x for k in ("packet", "fwd", "bwd"))],
                },
            })
            return
        if path == "/api/nlp/model":
            self.send_json(text_model_summary())
            return
        if path == "/api/nlp/realworld/status":
            self.send_json(realworld_status())
            return
        if path == "/api/nlp/real-incident/status":
            self.send_json(incident_model_summary())
            return
        if path == "/api/nlp/realworld/job":
            job_id = query.get("id", [""])[0]
            snapshot = _real_job_snapshot(job_id)
            self.send_json(snapshot if snapshot else {"error":"Training job not found."}, 200 if snapshot else 404)
            return
        if path == "/api/reports":
            files = [
                {
                    "section": "Network Forecasting",
                    "name": "Network Pre-Attack Performance",
                    "description": "5-, 10- and 30-second forecasting metrics, calibrated thresholds and operational warning measures.",
                    "path": ROOT / "models" / "cybercrime_prediction_metrics.json",
                    "color": "violet",
                    "format": "JSON",
                },
                {
                    "section": "Network Forecasting",
                    "name": "Network Model Card",
                    "description": "The 91-feature network model design, training source, intended use and scientific limitations.",
                    "path": ROOT / "models" / "model_card.json",
                    "color": "cyan",
                    "format": "JSON",
                },
                {
                    "section": "Real Incident Intelligence",
                    "name": "Real Incident Classifier Performance",
                    "description": "Internal chronological holdout metrics for the real-data multi-label incident classifier.",
                    "path": INCIDENT_METRICS_PATH,
                    "color": "pink",
                    "format": "JSON",
                },
                {
                    "section": "Real Incident Intelligence",
                    "name": "Real Incident Model Card",
                    "description": "Training coverage, supported labels, intended use and limitations of the real incident classifier.",
                    "path": INCIDENT_CARD_PATH,
                    "color": "orange",
                    "format": "JSON",
                },
                {
                    "section": "System Documentation",
                    "name": "System Architecture",
                    "description": "End-to-end architecture for network forecasting, text intelligence, local APIs and the interface.",
                    "path": ROOT / "docs" / "ARCHITECTURE.md",
                    "color": "indigo",
                    "format": "MD",
                },
                {
                    "section": "System Documentation",
                    "name": "Model Methodology",
                    "description": "Targets, preprocessing, leakage controls, evaluation rules, uncertainty and governance.",
                    "path": ROOT / "docs" / "METHODOLOGY.md",
                    "color": "red",
                    "format": "MD",
                },
                {
                    "section": "System Documentation",
                    "name": "Data Requirements",
                    "description": "Required fields and validation rules for network and incident-text datasets.",
                    "path": ROOT / "docs" / "DATA_REQUIREMENTS.md",
                    "color": "cyan",
                    "format": "MD",
                },
            ]
            reports = []
            for item in files:
                report_path = item["path"]
                if not report_path.exists():
                    continue
                reports.append({
                    "section": item["section"],
                    "name": item["name"],
                    "description": item["description"],
                    "path": str(report_path.relative_to(ROOT)).replace("\\", "/"),
                    "size": report_path.stat().st_size,
                    "color": item["color"],
                    "format": item["format"],
                })
            self.send_json({"reports": reports})
            return
        if path == "/api/upload/status":
            job_id = query.get("id", [""])[0]
            snapshot = _job_snapshot(job_id)
            if snapshot is None:
                self.send_json({"error":"Upload session not found."}, 404)
            else:
                self.send_json(snapshot)
            return
        if path == "/download":
            relative = query.get("file", [""])[0]
            target = (ROOT / relative).resolve()
            root_resolved = ROOT.resolve()
            if target != root_resolved and root_resolved not in target.parents:
                self.send_json({"error": "The requested local file path is not permitted."}, 403)
                return
            self.serve_file(target, download=True)
            return
        if path == "/":
            self.serve_file(WEB_ROOT/"index.html")
            return
        target = WEB_ROOT / path.lstrip("/")
        if target.is_file():
            self.serve_file(target)
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/nlp/real-incident/predict":
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0 or length > 2 * 1024 * 1024:
                self.send_json({"error":"The text request is empty or too large."}, 413); return
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                self.send_json({"ok":True,"result":INCIDENT_CLASSIFIER.predict(str(payload.get("text", "")))})
            except Exception as exc:
                self.send_json({"error":str(exc)}, 400)
            return
        if parsed.path == "/api/nlp/real-incident/evaluate":
            filename = _safe_filename(self.headers.get("X-Filename", "incident_multilabel_test.csv"))
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0 or length > 500 * 1024 * 1024:
                self.send_json({"error":"Select a model-ready CSV up to 500 MB."}, 413); return
            path = UPLOADS / f"incident_eval_{uuid.uuid4().hex[:8]}_{filename}"
            try:
                with path.open("wb") as handle:
                    remaining=length
                    while remaining:
                        chunk=self.rfile.read(min(1024*1024,remaining))
                        if not chunk: raise ConnectionError("The browser stopped sending the incident evaluation dataset.")
                        handle.write(chunk); remaining-=len(chunk)
                result=evaluate_incident_csv(INCIDENT_CLASSIFIER,path)
                out=INCIDENT_EVALUATIONS_DIR/f"incident_evaluation_{time.strftime('%Y%m%d_%H%M%S')}.json"
                out.write_text(json.dumps(result,indent=2),encoding="utf-8")
                self.send_json({"ok":True,"result":result,"download":str(out.relative_to(ROOT)).replace("\\","/")})
            except Exception as exc:
                self.send_json({"error":str(exc)},400)
            return
        if parsed.path == "/api/nlp/realworld/activate":
            length = int(self.headers.get("Content-Length", "0") or 0)
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                self.send_json({"ok": True, "model": activate_text_model(str(payload.get("mode", "real")))})
            except Exception as exc:
                self.send_json({"error": str(exc)}, 400)
            return
        if parsed.path == "/api/nlp/realworld/train":
            train_name = _safe_filename(urllib.parse.unquote(self.headers.get("X-Training-Filename", "real_incidents.csv")))
            external_name = _safe_filename(urllib.parse.unquote(self.headers.get("X-External-Filename", ""))) if self.headers.get("X-External-Filename") else ""
            source_name = urllib.parse.unquote(self.headers.get("X-Source-Name", ""))[:180]
            train_size = int(self.headers.get("X-Training-Size", "0") or 0)
            external_size = int(self.headers.get("X-External-Size", "0") or 0)
            total = int(self.headers.get("Content-Length", "0") or 0)
            allowed = (".csv", ".json", ".jsonl", ".ndjson", ".gz", ".zip")
            if train_size <= 0 or train_size + external_size != total:
                self.send_json({"error": "The real-world training upload was incomplete."}, 400); return
            if total > 1024 * 1024 * 1024:
                self.send_json({"error": "The combined local training upload exceeds 1 GB. Split the source into smaller verified files before training."}, 413); return
            if not train_name.lower().endswith(allowed) or (external_name and not external_name.lower().endswith(allowed)):
                self.send_json({"error": "Use CSV, JSON, JSONL, JSON.GZ, or ZIP files."}, 400); return
            job_id = uuid.uuid4().hex[:12]
            train_path = REAL_DATA_DIR / f"{job_id}_train_{train_name}"
            external_path = REAL_DATA_DIR / f"{job_id}_external_{external_name}" if external_size else None
            try:
                for path, remaining in ((train_path, train_size), (external_path, external_size)):
                    if path is None or remaining <= 0: continue
                    with path.open("wb") as handle:
                        while remaining:
                            chunk = self.rfile.read(min(1024 * 1024, remaining))
                            if not chunk: raise ConnectionError("The browser stopped sending the real-world dataset.")
                            handle.write(chunk); remaining -= len(chunk)
                job = {"id": job_id, "status": "queued", "stage": "Upload complete", "progress": 0.04,
                       "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "training_file": train_name,
                       "external_file": external_name or None, "source_name": source_name or train_name}
                with REAL_TRAINING_LOCK: REAL_TRAINING_JOBS[job_id] = job
                threading.Thread(target=_real_training_worker, args=(job_id, train_path, source_name, external_path), daemon=True).start()
                self.send_json({"ok": True, "job": job})
            except Exception as exc:
                self.send_json({"error": str(exc)}, 400)
            return
        if parsed.path == "/api/nlp/predict":
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0 or length > 2 * 1024 * 1024:
                self.send_json({"error":"The text request is empty or too large."}, 413)
                return
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                result = get_text_classifier().predict(str(payload.get("text", "")))
                self.send_json({"ok":True, "result":result})
            except Exception as exc:
                self.send_json({"error":str(exc)}, 400)
            return
        if parsed.path == "/api/nlp/evaluate":
            dataset_name = _safe_filename(urllib.parse.unquote(self.headers.get("X-Dataset-Filename", "labelled_text_dataset.csv")))
            answer_name = _safe_filename(urllib.parse.unquote(self.headers.get("X-Answer-Key-Filename", ""))) if self.headers.get("X-Answer-Key-Filename") else ""
            dataset_size = int(self.headers.get("X-Dataset-Size", "0") or 0)
            answer_size = int(self.headers.get("X-Answer-Key-Size", "0") or 0)
            total_length = int(self.headers.get("Content-Length", "0") or 0)
            if dataset_size <= 0 or total_length <= 0:
                self.send_json({"error":"Select a labelled text CSV or a test CSV with an answer key."}, 400)
                return
            if dataset_size + answer_size != total_length:
                self.send_json({"error":"The NLP evaluation upload was incomplete. Please retry."}, 400)
                return
            if total_length > 300 * 1024 * 1024:
                self.send_json({"error":"NLP evaluation supports a combined local upload up to 300 MB."}, 413)
                return
            if Path(dataset_name).suffix.lower() != ".csv" or (answer_name and Path(answer_name).suffix.lower() != ".csv"):
                self.send_json({"error":"NLP evaluation accepts CSV files only."}, 400)
                return
            dataset_path = UPLOADS / f"nlp_eval_{uuid.uuid4().hex[:8]}_{dataset_name}"
            answer_path = UPLOADS / f"nlp_key_{uuid.uuid4().hex[:8]}_{answer_name}" if answer_size else None
            try:
                with dataset_path.open("wb") as handle:
                    remaining = dataset_size
                    while remaining > 0:
                        chunk = self.rfile.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise ConnectionError("The browser stopped sending the NLP evaluation dataset.")
                        handle.write(chunk)
                        remaining -= len(chunk)
                if answer_path is not None:
                    with answer_path.open("wb") as handle:
                        remaining = answer_size
                        while remaining > 0:
                            chunk = self.rfile.read(min(1024 * 1024, remaining))
                            if not chunk:
                                raise ConnectionError("The browser stopped sending the NLP answer key.")
                            handle.write(chunk)
                            remaining -= len(chunk)
                result = evaluate_text_dataset(
                    get_text_classifier(), dataset_path, TEXT_EVALUATIONS_DIR, dataset_name,
                    answer_key_path=answer_path, answer_key_name=answer_name or None,
                )
                self.send_json({"ok":True, "result":result})
            except Exception as exc:
                log(f"NLP evaluation failed for {dataset_name}: {type(exc).__name__}: {exc}")
                self.send_json({"error":str(exc)}, 400)
            return

        if parsed.path == "/api/nlp/batch":
            filename = _safe_filename(self.headers.get("X-Filename", "text_dataset.csv"))
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0:
                self.send_json({"error":"The selected text dataset is empty."}, 400)
                return
            if length > 250 * 1024 * 1024:
                self.send_json({"error":"Text batch classification supports CSV files up to 250 MB."}, 413)
                return
            if Path(filename).suffix.lower() != ".csv":
                self.send_json({"error":"Select a CSV text dataset."}, 400)
                return
            input_path = UPLOADS / f"nlp_{uuid.uuid4().hex[:8]}_{filename}"
            remaining = length
            try:
                with input_path.open("wb") as handle:
                    while remaining > 0:
                        chunk = self.rfile.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise ConnectionError("The browser stopped sending the text dataset.")
                        handle.write(chunk)
                        remaining -= len(chunk)
                result = classify_text_csv(input_path, filename)
                self.send_json({"ok":True, "result":result})
            except Exception as exc:
                self.send_json({"error":str(exc)}, 400)
            return
        if parsed.path == "/api/control":
            length = int(self.headers.get("Content-Length", "0") or 0)
            body = self.rfile.read(length)
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except Exception:
                payload = {}
            action = payload.get("action")
            with STATE_LOCK:
                if action == "toggle":
                    STATE.running = not STATE.running
                elif action == "start":
                    STATE.running = True
                elif action == "pause":
                    STATE.running = False
                elif action == "reset":
                    STATE.index = 0
                    STATE.history = []
                elif action == "speed":
                    STATE.interval = max(0.5, min(float(payload.get("interval", 2.0)), 10.0))
            self.send_json({"ok":True, "running":STATE.running, "interval":STATE.interval})
            return
        if parsed.path == "/api/upload/init":
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length > 1024 * 1024:
                self.send_json({"error":"Invalid upload initialisation request."}, 413)
                return
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                filename = _safe_filename(str(payload.get("filename", "uploaded_file")))
                size = int(payload.get("size", 0) or 0)
                if size <= 0:
                    raise ValueError("The selected file is empty.")
                if size > MAX_UPLOAD_BYTES:
                    raise ValueError("The selected file exceeds the 2 GB local intake limit.")
                suffix = Path(filename).suffix.lower()
                if suffix not in {".csv", ".pcap", ".cap", ""}:
                    raise ValueError("Select a CSV or classic PCAP file.")
                job_id = uuid.uuid4().hex
                temp_path = UPLOADS / f".{job_id}.part"
                final_path = UPLOADS / f"{job_id[:8]}_{filename}"
                temp_path.unlink(missing_ok=True)
                with UPLOAD_LOCK:
                    UPLOAD_JOBS[job_id] = {
                        "id": job_id,
                        "filename": filename,
                        "size": size,
                        "received": 0,
                        "expected_chunk": 0,
                        "status": "uploading",
                        "upload_progress": 0.0,
                        "audit_progress": 0.0,
                        "message": "Ready to receive file",
                        "temp_path": str(temp_path),
                        "final_path": str(final_path),
                    }
                self.send_json({"ok":True, "id":job_id, "chunk_size":UPLOAD_CHUNK_BYTES, "max_size":MAX_UPLOAD_BYTES})
            except Exception as exc:
                self.send_json({"error":str(exc)}, 400)
            return

        if parsed.path == "/api/upload/chunk":
            query = urllib.parse.parse_qs(parsed.query)
            job_id = query.get("id", [""])[0]
            try:
                index = int(query.get("index", ["0"])[0])
            except Exception:
                index = -1
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0 or length > UPLOAD_CHUNK_BYTES + 1024:
                self.send_json({"error":"Invalid upload chunk size."}, 413)
                return
            with UPLOAD_LOCK:
                job = UPLOAD_JOBS.get(job_id)
                if not job:
                    self.send_json({"error":"Upload session not found."}, 404)
                    return
                expected_index = int(job["expected_chunk"])
                if index < expected_index:
                    self.rfile.read(length)
                    self.send_json({"ok":True, "received":job["received"], "progress":job["upload_progress"], "duplicate":True})
                    return
                if index != expected_index:
                    self.send_json({"error":f"Expected chunk {expected_index}, received {index}."}, 409)
                    return
                temp_path = Path(job["temp_path"])
                current_received = int(job["received"])
                expected_size = int(job["size"])
            if current_received + length > expected_size:
                self.send_json({"error":"The uploaded data exceeds the declared file size."}, 400)
                return
            remaining = length
            try:
                with temp_path.open("ab") as handle:
                    while remaining:
                        chunk = self.rfile.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise ConnectionError("The browser stopped sending the current file chunk.")
                        handle.write(chunk)
                        remaining -= len(chunk)
                received = current_received + length
                with UPLOAD_LOCK:
                    job = UPLOAD_JOBS[job_id]
                    job["received"] = received
                    job["expected_chunk"] = expected_index + 1
                    job["upload_progress"] = received / max(expected_size, 1)
                    job["message"] = f"Uploaded {received:,} of {expected_size:,} bytes"
                self.send_json({"ok":True, "received":received, "progress":received/max(expected_size,1)})
            except Exception as exc:
                _set_job(job_id, status="error", error=str(exc), message="Upload interrupted")
                self.send_json({"error":str(exc)}, 500)
            return

        if parsed.path == "/api/upload/finalize":
            length = int(self.headers.get("Content-Length", "0") or 0)
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                job_id = str(payload.get("id", ""))
                with UPLOAD_LOCK:
                    job = UPLOAD_JOBS.get(job_id)
                    if not job:
                        raise ValueError("Upload session not found.")
                    if int(job["received"]) != int(job["size"]):
                        raise ValueError(f"Upload incomplete: received {job['received']:,} of {job['size']:,} bytes.")
                    temp_path = Path(job["temp_path"])
                    final_path = Path(job["final_path"])
                final_path.unlink(missing_ok=True)
                temp_path.replace(final_path)
                _set_job(job_id, status="queued", upload_progress=1.0, message="Upload complete; audit queued")
                threading.Thread(target=_audit_upload, args=(job_id,), daemon=True, name=f"audit-{job_id[:8]}").start()
                self.send_json({"ok":True, "id":job_id, "status":"queued"}, 202)
            except Exception as exc:
                self.send_json({"error":str(exc)}, 400)
            return

        # Backward-compatible small-file endpoint. The interface uses chunked uploads.
        if parsed.path == "/api/upload":
            filename = _safe_filename(self.headers.get("X-Filename", "uploaded_file"))
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0:
                self.send_json({"error":"The selected file is empty."}, 400)
                return
            if length > MAX_UPLOAD_BYTES:
                # Drain a small amount and close cleanly; browser-side validation normally prevents this.
                self.send_json({"error":"The selected file exceeds the 2 GB local intake limit."}, 413)
                return
            path = UPLOADS / f"{uuid.uuid4().hex[:8]}_{filename}"
            remaining = length
            try:
                with path.open("wb") as handle:
                    while remaining > 0:
                        chunk = self.rfile.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise ConnectionError("Upload was interrupted before completion.")
                        handle.write(chunk)
                        remaining -= len(chunk)
                suffix = Path(filename).suffix.lower()
                if suffix in {".pcap", ".cap"} or not suffix:
                    result = pcap_audit(path)
                    kind = "pcap"
                elif suffix == ".csv":
                    result = csv_audit(path)
                    kind = "csv"
                else:
                    raise ValueError("Portable intake supports CSV and classic PCAP files.")
                self.send_json({"ok":True, "kind":kind, "audit":result, "saved_as":str(path.relative_to(ROOT)).replace("\\", "/")})
            except Exception as exc:
                self.send_json({"error":str(exc)}, 400)
            return
        self.send_json({"error":"Unknown operation"}, 404)


class PortableHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def open_browser(url: str) -> None:
    time.sleep(1.2)
    try:
        webbrowser.open(url, new=2)
    except Exception:
        if os.name == "nt":
            subprocess.Popen(["cmd", "/c", "start", "", url], shell=False)


def main() -> int:
    log(f"Starting {APP_NAME}")
    log(f"Python: {sys.version.split()[0]} | {sys.platform} | {sys.executable}")
    validation = bundle_validation()
    if not validation["valid"]:
        raise RuntimeError("Portable model validation failed: " + ", ".join(validation["missing"]))
    thread = threading.Thread(target=update_monitor, name="monitor", daemon=True)
    thread.start()
    port = find_port()
    url = f"http://127.0.0.1:{port}/"
    RUNTIME_PATH.write_text(json.dumps({
        "system_name":APP_NAME,
        "url":url,
        "port":port,
        "python":sys.executable,
        "started_at":time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "mode":"Portable dependency-free interface",
    }, indent=2), encoding="utf-8")
    server = PortableHTTPServer(("127.0.0.1", port), Handler)
    log(f"Dashboard ready: {url}")
    print("="*64)
    print(f" {APP_NAME}")
    print("="*64)
    print(f"Dashboard: {url}")
    print("The browser should open automatically.")
    print("Keep this window open. Press Ctrl+C to stop the system.")
    threading.Thread(target=open_browser, args=(url,), daemon=True).start()
    try:
        server.serve_forever(poll_interval=0.4)
    except KeyboardInterrupt:
        log("Shutdown requested by user.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        log(f"Fatal startup error: {type(exc).__name__}: {exc}")
        log(traceback.format_exc())
        print(f"\nStartup failed: {exc}")
        raise
