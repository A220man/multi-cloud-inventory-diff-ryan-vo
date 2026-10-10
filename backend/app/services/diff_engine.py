"""Deterministic snapshot comparison and drift grouping engine."""
from app.models.schemas import CanonicalAsset, DiffItem, FieldDelta, OwnerGroup


class DiffEngine:
    @staticmethod
    def compute_diff(
        base_assets: list[CanonicalAsset],
        target_assets: list[CanonicalAsset]
    ) -> tuple[list[DiffItem], dict[str, int], list[OwnerGroup]]:
        base_map: dict[str, CanonicalAsset] = {a.resource_id: a for a in base_assets}
        target_map: dict[str, CanonicalAsset] = {a.resource_id: a for a in target_assets}

        base_ids, target_ids = set(base_map.keys()), set(target_map.keys())
        diff_items: list[DiffItem] = []

        # 1. Added
        for rid in sorted(list(target_ids - base_ids)):
            a = target_map[rid]
            diff_items.append(
                DiffItem(
                    diff_type="added",
                    resource_id=a.resource_id,
                    resource_name=a.resource_name,
                    resource_type=a.resource_type,
                    cloud_provider=a.cloud_provider,
                    owner=a.owner,
                    exposure_level=a.exposure_level,
                    deltas=[
                        FieldDelta(field="lifecycle", old_value=None, new_value="created"),
                        FieldDelta(field="exposure_level", old_value=None, new_value=a.exposure_level),
                    ],
                    exposure_escalated=a.exposure_level == "public",
                    iam_escalated=bool(a.iam_config.get("has_admin_privilege")),
                    owner_drifted=a.owner is None,
                )
            )

        # 2. Removed
        for rid in sorted(list(base_ids - target_ids)):
            a = base_map[rid]
            diff_items.append(
                DiffItem(
                    diff_type="removed",
                    resource_id=a.resource_id,
                    resource_name=a.resource_name,
                    resource_type=a.resource_type,
                    cloud_provider=a.cloud_provider,
                    owner=a.owner,
                    exposure_level=a.exposure_level,
                    deltas=[FieldDelta(field="lifecycle", old_value="active", new_value="deleted")],
                )
            )

        # 3. Modified
        for rid in sorted(list(base_ids & target_ids)):
            b, t = base_map[rid], target_map[rid]
            deltas: list[FieldDelta] = []
            exp_esc, iam_esc, own_drift = False, False, False

            checks = [
                ("exposure_level", b.exposure_level, t.exposure_level),
                ("owner", b.owner, t.owner),
                ("network_config.open_ports", b.network_config.get("open_ports", []), t.network_config.get("open_ports", [])),
                ("network_config.public_ip", b.network_config.get("public_ip"), t.network_config.get("public_ip")),
                ("iam_config.has_admin_privilege", b.iam_config.get("has_admin_privilege", False), t.iam_config.get("has_admin_privilege", False)),
                ("tags", b.tags, t.tags),
            ]

            for field, old_v, new_v in checks:
                if old_v != new_v:
                    deltas.append(FieldDelta(field=field, old_value=old_v, new_value=new_v))
                    if field == "exposure_level" and old_v in ("private", "internal") and new_v == "public":
                        exp_esc = True
                    elif field == "owner" and new_v is None:
                        own_drift = True
                    elif field == "network_config.open_ports" and len(new_v) > len(old_v):
                        exp_esc = True
                    elif field == "network_config.public_ip" and not old_v and new_v:
                        exp_esc = True
                    elif field == "iam_config.has_admin_privilege" and not old_v and new_v:
                        iam_esc = True

            if deltas:
                diff_items.append(
                    DiffItem(
                        diff_type="modified",
                        resource_id=t.resource_id,
                        resource_name=t.resource_name,
                        resource_type=t.resource_type,
                        cloud_provider=t.cloud_provider,
                        owner=t.owner,
                        exposure_level=t.exposure_level,
                        deltas=deltas,
                        exposure_escalated=exp_esc,
                        iam_escalated=iam_esc,
                        owner_drifted=own_drift,
                    )
                )

        # 4. Summary & grouping
        exposure_summary = {
            "total_changes": len(diff_items),
            "exposure_escalated": sum(1 for d in diff_items if d.exposure_escalated),
            "iam_escalated": sum(1 for d in diff_items if d.iam_escalated),
            "owner_drifted": sum(1 for d in diff_items if d.owner_drifted),
            "public_added": sum(1 for d in diff_items if d.diff_type == "added" and d.exposure_level == "public"),
        }

        owner_buckets: dict[str, list[DiffItem]] = {}
        for item in diff_items:
            owner_key = item.owner or "unassigned"
            owner_buckets.setdefault(owner_key, []).append(item)

        owner_grouping = [
            OwnerGroup(
                owner=k,
                asset_count=len(v),
                exposure_escalated_count=sum(1 for i in v if i.exposure_escalated or i.iam_escalated),
                resource_ids=[i.resource_id for i in v],
            )
            for k, v in sorted(owner_buckets.items(), key=lambda x: len(x[1]), reverse=True)
        ]

        return diff_items, exposure_summary, owner_grouping
