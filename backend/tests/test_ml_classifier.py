from app.ml.classifier import DriftRiskClassifier
from app.ml.evaluate import run_benchmark
from app.models.schemas import DiffItem, FieldDelta

def test_classifier_critical_exposure_case():
    item = DiffItem(
        diff_type="modified",
        resource_id="arn:aws:s3:::customer-pii-bucket",
        resource_name="customer-pii-bucket",
        resource_type="storage.bucket",
        cloud_provider="aws",
        exposure_level="public",
        deltas=[
            FieldDelta(field="exposure_level", old_value="private", new_value="public"),
        ],
        exposure_escalated=True,
        iam_escalated=False,
        owner_drifted=True,
    )

    ev = DriftRiskClassifier.classify(item)
    assert ev.predicted_severity == "CRITICAL"
    assert ev.confidence >= 0.75
    assert ev.anomaly_score >= 0.50
    assert "public" in ev.rationale.lower()


def test_classifier_benign_low_case():
    item = DiffItem(
        diff_type="modified",
        resource_id="arn:aws:ec2:vm-worker",
        resource_name="vm-worker",
        resource_type="compute.instance",
        cloud_provider="aws",
        exposure_level="private",
        deltas=[
            FieldDelta(field="tags.Release", old_value="v1.0", new_value="v1.1"),
        ],
        exposure_escalated=False,
        iam_escalated=False,
        owner_drifted=False,
    )

    ev = DriftRiskClassifier.classify(item)
    assert ev.predicted_severity == "LOW"
    assert ev.anomaly_score < 0.20


def test_benchmark_runner_executes_and_validates():
    results = run_benchmark()
    model = results["model_metrics"]
    baseline = results["baseline_metrics"]

    assert model["total_samples"] == 32
    assert model["accuracy"] >= 0.80
    assert model["macro_f1"] >= 0.80
    assert model["accuracy"] > baseline["accuracy"]
    assert "CRITICAL" in model["per_class"]
    assert "LOW" in model["per_class"]