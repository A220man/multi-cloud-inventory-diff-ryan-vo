"""Reproducible benchmark evaluation for multi-cloud configuration drift classification."""
import json
import sys
from typing import Any
from app.ml.dataset import BENCHMARK_DATASET
from app.ml.classifier import DriftRiskClassifier

CLASSES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def calculate_metrics(y_true: list[str], y_pred: list[str]) -> dict[str, Any]:
    """Compute accuracy, precision, recall, f1, and confusion matrix without external heavy dependencies."""
    n = len(y_true)
    accuracy = sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp) / n

    # Confusion matrix: row = true, col = pred
    matrix: dict[str, dict[str, int]] = {c1: {c2: 0 for c2 in CLASSES} for c1 in CLASSES}
    for yt, yp in zip(y_true, y_pred):
        if yt in matrix and yp in matrix[yt]:
            matrix[yt][yp] += 1

    per_class = {}
    macro_p, macro_r, macro_f1 = 0.0, 0.0, 0.0
    weighted_p, weighted_r, weighted_f1 = 0.0, 0.0, 0.0

    for c in CLASSES:
        tp = matrix[c][c]
        fp = sum(matrix[other][c] for other in CLASSES if other != c)
        fn = sum(matrix[c][other] for other in CLASSES if other != c)
        support = sum(matrix[c].values())

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

        per_class[c] = {
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "support": support,
        }

        macro_p += prec
        macro_r += rec
        macro_f1 += f1

        weight = support / n
        weighted_p += prec * weight
        weighted_r += rec * weight
        weighted_f1 += f1 * weight

    num_classes = len(CLASSES)
    return {
        "total_samples": n,
        "accuracy": round(accuracy, 4),
        "macro_precision": round(macro_p / num_classes, 4),
        "macro_recall": round(macro_r / num_classes, 4),
        "macro_f1": round(macro_f1 / num_classes, 4),
        "weighted_precision": round(weighted_p, 4),
        "weighted_recall": round(weighted_r, 4),
        "weighted_f1": round(weighted_f1, 4),
        "per_class": per_class,
        "confusion_matrix": matrix,
    }


def naive_baseline_predict(item: dict[str, Any]) -> str:
    """Simple rule-based baseline: if exposure escalated -> HIGH, if unowned -> MEDIUM, else -> LOW."""
    if item.get("exposure_escalated"):
        return "HIGH"
    elif item.get("owner_drifted"):
        return "MEDIUM"
    return "LOW"


def run_benchmark() -> dict[str, Any]:
    """Execute complete benchmark comparing classifier against baseline and ground truth."""
    y_true = []
    y_model = []
    y_baseline = []
    failures = []

    for item in BENCHMARK_DATASET:
        gt = item["ground_truth_severity"]
        y_true.append(gt)

        eval_res = DriftRiskClassifier.classify(item)
        pred = eval_res.predicted_severity
        y_model.append(pred)

        base_pred = naive_baseline_predict(item)
        y_baseline.append(base_pred)

        if pred != gt:
            failures.append({
                "id": item["id"],
                "resource_name": item["resource_name"],
                "cloud_provider": item["cloud_provider"],
                "ground_truth": gt,
                "predicted": pred,
                "rationale": eval_res.rationale,
            })

    model_metrics = calculate_metrics(y_true, y_model)
    baseline_metrics = calculate_metrics(y_true, y_baseline)

    return {
        "model_metrics": model_metrics,
        "baseline_metrics": baseline_metrics,
        "failures": failures,
    }


def main():
    print("=" * 60)
    print("MULTI-CLOUD INVENTORY DIFF: ML MODEL BENCHMARK EVALUATION")
    print("=" * 60)
    res = run_benchmark()
    m = res["model_metrics"]
    b = res["baseline_metrics"]

    print(f"\nDataset Size: {m['total_samples']} incidents across AWS, GCP, and Azure")
    print("\nOverall Performance Comparison:")
    print(f"  Accuracy:          Model: {m['accuracy'] * 100:.1f}% | Baseline: {b['accuracy'] * 100:.1f}%")
    print(f"  Macro Precision:   Model: {m['macro_precision'] * 100:.1f}% | Baseline: {b['macro_precision'] * 100:.1f}%")
    print(f"  Macro Recall:      Model: {m['macro_recall'] * 100:.1f}% | Baseline: {b['macro_recall'] * 100:.1f}%")
    print(f"  Macro F1-Score:    Model: {m['macro_f1'] * 100:.1f}% | Baseline: {b['macro_f1'] * 100:.1f}%")

    print("\nPer-Class Breakdown (Model):")
    print(f"  {'Class':<10} {'Precision':<10} {'Recall':<10} {'F1-Score':<10} {'Support':<8}")
    print("  " + "-" * 48)
    for c in CLASSES:
        stats = m["per_class"][c]
        print(f"  {c:<10} {stats['precision'] * 100:<9.1f}% {stats['recall'] * 100:<9.1f}% {stats['f1'] * 100:<9.1f}% {stats['support']:<8}")

    print("\nConfusion Matrix (Rows: Ground Truth, Cols: Predicted):")
    print(f"  {'Actual \\ Pred':<14} {'LOW':<8} {'MEDIUM':<8} {'HIGH':<8} {'CRITICAL':<8}")
    for actual in CLASSES:
        row = m["confusion_matrix"][actual]
        print(f"  {actual:<14} {row['LOW']:<8} {row['MEDIUM']:<8} {row['HIGH']:<8} {row['CRITICAL']:<8}")

    print(f"\nDiscrepancies / Edge Cases ({len(res['failures'])}):")
    for f in res["failures"]:
        print(f"  [{f['id']}] {f['resource_name']} ({f['cloud_provider']}): Truth={f['ground_truth']}, Pred={f['predicted']}")
        print(f"    Rationale: {f['rationale']}")

    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
