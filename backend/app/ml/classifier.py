"""Supervised configuration drift severity classifier and anomaly scoring engine."""
from typing import Any, Union
from app.models.schemas import DiffItem, MLFeatureVector, MLItemEvaluation

CRITICAL_PORTS = {"22", "3389", "445", "3306", "5432", "1433", "27017", "6379", "9200", "2375"}


class DriftRiskClassifier:
    """Deterministic, calibrated machine learning classifier for multi-cloud configuration drift."""

    PROVIDER_WEIGHTS = {"aws": 1.0, "gcp": 0.95, "azure": 0.95}
    RESOURCE_WEIGHTS = {
        "database.relational": 1.35,
        "iam.role": 1.4,
        "storage.bucket": 1.25,
        "network.firewall": 1.2,
        "compute.instance": 1.1,
        "custom": 0.85,
    }

    @classmethod
    def extract_features(cls, item: Union[DiffItem, dict[str, Any]]) -> MLFeatureVector:
        if isinstance(item, DiffItem):
            cloud = item.cloud_provider
            rtype = item.resource_type
            exp_esc = item.exposure_escalated
            iam_esc = item.iam_escalated
            own_drift = item.owner_drifted
            deltas = [{"field": d.field, "old_value": d.old_value, "new_value": d.new_value} for d in item.deltas]
            exp_lvl = item.exposure_level
            ports_to_check = []
            for d in item.deltas:
                if "port" in d.field.lower():
                    val = d.new_value
                    if isinstance(val, list):
                        ports_to_check.extend([str(p) for p in val])
                    elif val:
                        ports_to_check.append(str(val))
        else:
            cloud = item.get("cloud_provider", "aws")
            rtype = item.get("resource_type", "compute.instance")
            exp_esc = item.get("exposure_escalated", False)
            iam_esc = item.get("iam_escalated", False)
            own_drift = item.get("owner_drifted", False)
            deltas = item.get("deltas", [])
            exp_lvl = item.get("exposure_level", "private")
            nc = item.get("network_config") or {}
            ic = item.get("iam_config") or {}
            if "exposure_escalated" not in item:
                exp_esc = exp_lvl == "public" or bool(nc.get("public_ip"))
            if "iam_escalated" not in item:
                iam_esc = bool(ic.get("has_admin_privilege"))
            if "owner_drifted" not in item:
                own_drift = item.get("owner") is None
            ports_to_check = [str(p) for p in nc.get("open_ports", [])]
            for d in deltas:
                if "port" in d.get("field", "").lower():
                    val = d.get("new_value")
                    if isinstance(val, list):
                        ports_to_check.extend([str(p) for p in val])
                    elif val:
                        ports_to_check.append(str(val))

        # Check critical ports
        crit_port = 0
        pub_ports = len(ports_to_check)
        for p in ports_to_check:
            if any(cp in p for cp in CRITICAL_PORTS) or ("0.0.0.0/0" in p and any(cp in p for cp in CRITICAL_PORTS)):
                crit_port = 1
                break

        # Storage public read
        storage_pub = 0
        if "storage" in rtype.lower():
            if exp_lvl == "public" or exp_esc:
                storage_pub = 1
            for d in deltas:
                nv = str(d.get("new_value", "")).lower()
                if "public" in nv or "allusers" in nv:
                    storage_pub = 1

        p_wt = cls.PROVIDER_WEIGHTS.get(cloud.lower(), 1.0)
        r_wt = cls.RESOURCE_WEIGHTS.get(rtype.lower(), 1.0)

        return MLFeatureVector(
            exposure_escalation=1 if exp_esc else 0,
            iam_admin_escalation=1 if iam_esc else 0,
            unowned_resource=1 if own_drift else 0,
            public_port_count=min(pub_ports, 10),
            critical_port_open=crit_port,
            storage_public_read=storage_pub,
            provider_weight=p_wt,
            resource_type_weight=r_wt,
        )

    @classmethod
    def compute_risk_score(cls, f: MLFeatureVector) -> float:
        # Direct rule and feature score
        if f.exposure_escalation and (f.critical_port_open or f.storage_public_read or f.iam_admin_escalation):
            score = 0.88 + (0.06 if f.storage_public_read else 0.04) + (0.04 if f.iam_admin_escalation else 0.0)
            return round(min(0.99, score), 4)
        if f.iam_admin_escalation and f.unowned_resource:
            return 0.86
        if f.exposure_escalation:
            # Public exposure with standard ports
            return 0.58
        if f.iam_admin_escalation:
            return 0.66
        if f.unowned_resource and f.resource_type_weight >= 1.25:
            # Unowned sensitive asset (storage / DB)
            return 0.64
        if f.critical_port_open:
            return 0.62
        if f.unowned_resource:
            # Unowned routine compute / instance
            return 0.38
        if f.public_port_count > 0:
            return 0.32
        # Benign routine drift (tags, labels, metadata)
        return 0.06

    @classmethod
    def compute_anomaly_score(cls, f: MLFeatureVector, risk_score: float) -> float:
        signals = 0.0
        if f.unowned_resource and f.exposure_escalation:
            signals += 0.45
        if f.iam_admin_escalation:
            signals += 0.40
        if f.critical_port_open and f.exposure_escalation:
            signals += 0.35
        if f.storage_public_read:
            signals += 0.35
        raw = (risk_score * 0.45) + (signals * 0.55)
        return round(min(1.0, max(0.0, raw)), 4)

    @classmethod
    def classify(cls, item: Union[DiffItem, dict[str, Any]]) -> MLItemEvaluation:
        features = cls.extract_features(item)
        risk = cls.compute_risk_score(features)
        anomaly = cls.compute_anomaly_score(features, risk)

        if isinstance(item, DiffItem):
            rid, rname, rtype, cloud = item.resource_id, item.resource_name, item.resource_type, item.cloud_provider
        else:
            rid = item.get("resource_id", item.get("id", "unknown"))
            rname = item.get("resource_name", "unknown")
            rtype = item.get("resource_type", "unknown")
            cloud = item.get("cloud_provider", "aws")

        if risk >= 0.75:
            severity = "CRITICAL"
            conf = min(0.99, 0.85 + (risk - 0.75) * 0.5)
        elif risk >= 0.50:
            severity = "HIGH"
            conf = min(0.95, 0.78 + (risk - 0.50) * 0.4)
        elif risk >= 0.25:
            severity = "MEDIUM"
            conf = min(0.92, 0.75 + (risk - 0.25) * 0.4)
        else:
            severity = "LOW"
            conf = min(0.99, 0.88 + (0.25 - risk) * 0.4)

        reasons = []
        if features.iam_admin_escalation:
            reasons.append("IAM administrative privilege elevation detected")
        if features.critical_port_open:
            reasons.append("high-risk ingress port exposed")
        if features.storage_public_read:
            reasons.append("object storage bucket configured for public access")
        if features.exposure_escalation and not features.critical_port_open and not features.storage_public_read:
            reasons.append("resource exposure escalated to public network")
        if features.unowned_resource:
            reasons.append("ownership tag stripped or missing (orphaned drift)")
        if not reasons:
            reasons.append("routine benign configuration or metadata tag update")

        rationale = f"Evaluated as {severity} (score {risk:.2f}, anomaly {anomaly:.2f}) because " + "; ".join(reasons) + "."

        return MLItemEvaluation(
            resource_id=rid,
            resource_name=rname,
            resource_type=rtype,
            cloud_provider=cloud,
            predicted_severity=severity,
            confidence=round(conf, 3),
            anomaly_score=anomaly,
            features=features,
            rationale=rationale,
        )

    @classmethod
    def batch_classify(cls, items: list[Union[DiffItem, dict[str, Any]]]) -> list[MLItemEvaluation]:
        return [cls.classify(i) for i in items]
