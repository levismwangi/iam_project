#!/usr/bin/env python3
"""
refresh_prt_watchlist.py

Rebuilds the KnownUserAppDevice Sentinel watchlist used by the PRT
replay detection rule (modules/monitoring/main.tf).

Queries the last 30 days of SigninLogs + NonInteractiveUserSignInLogs
for UserPrincipalName + AppId + DeviceId combinations seen more than
a handful of times, then upserts each as a watchlist item via the
Sentinel Watchlist Items REST API.

Deliberately kept as a standalone script (not inline in the workflow
YAML) so it can be run/tested locally with `az login` before trusting
it in the pipeline.

Requires: az CLI logged in (or OIDC-authenticated in the workflow)
with Microsoft Sentinel Contributor on the target workspace.

Env vars required:
  SUBSCRIPTION_ID
  RESOURCE_GROUP
  WORKSPACE_NAME        (Log Analytics workspace name, not the GUID)
  WATCHLIST_ALIAS        (default: KnownUserAppDevice)
  BASELINE_MIN_COUNT     (default: 5 — filters one-off noise)
  BASELINE_WINDOW_DAYS   (default: 30)
"""

import json
import os
import subprocess
import sys
import uuid

WATCHLIST_ALIAS = os.environ.get("WATCHLIST_ALIAS", "KnownUserAppDevice")
MIN_COUNT = os.environ.get("BASELINE_MIN_COUNT", "5")
WINDOW_DAYS = os.environ.get("BASELINE_WINDOW_DAYS", "30")

REQUIRED_ENV = ["SUBSCRIPTION_ID", "RESOURCE_GROUP", "WORKSPACE_NAME"]

# Deterministic namespace so re-runs update the same watchlist item
# per key instead of creating duplicates on every refresh.
ITEM_ID_NAMESPACE = uuid.UUID("7f3f4a2e-7b3e-4b8a-9c5d-1a2b3c4d5e6f")

KQL_QUERY = f"""
union isfuzzy=true SigninLogs, NonInteractiveUserSignInLogs
| where TimeGenerated > ago({WINDOW_DAYS}d)
| where ResultType == 0
| extend DeviceId = tostring(DeviceDetail.deviceId)
| where isnotempty(DeviceId) and isnotempty(UserPrincipalName) and isnotempty(AppId)
| summarize SignInCount = count() by UserPrincipalName, AppId, DeviceId
| where SignInCount > {MIN_COUNT}
| extend UserAppDeviceKey = strcat(UserPrincipalName, "|", AppId, "|", DeviceId)
| project UserAppDeviceKey, UserPrincipalName, AppId, DeviceId
""".strip()


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Command failed: {' '.join(cmd)}", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout


def get_workspace_customer_id(subscription_id: str, resource_group: str, workspace_name: str) -> str:
    out = run([
        "az", "monitor", "log-analytics", "workspace", "show",
        "--subscription", subscription_id,
        "--resource-group", resource_group,
        "--workspace-name", workspace_name,
        "--query", "customerId",
        "-o", "tsv",
    ])
    return out.strip()


def run_kql_query(customer_id: str) -> list[dict]:
    out = run([
        "az", "monitor", "log-analytics", "query",
        "--workspace", customer_id,
        "--analytics-query", KQL_QUERY,
        "-o", "json",
    ])
    rows = json.loads(out)
    return rows


def upsert_watchlist_item(subscription_id: str, resource_group: str, workspace_name: str, row: dict) -> None:
    item_id = str(uuid.uuid5(ITEM_ID_NAMESPACE, row["UserAppDeviceKey"]))
    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
        f"/providers/Microsoft.SecurityInsights/watchlists/{WATCHLIST_ALIAS}"
        f"/watchlistItems/{item_id}?api-version=2023-02-01"
    )

    body = {
        "properties": {
            "itemsKeyValue": {
                "UserAppDeviceKey": row["UserAppDeviceKey"],
                "UserPrincipalName": row["UserPrincipalName"],
                "AppId": row["AppId"],
                "DeviceId": row["DeviceId"],
                "BaselinedAt": _utc_now_iso(),
            }
        }
    }

    run([
        "az", "rest",
        "--method", "put",
        "--url", url,
        "--body", json.dumps(body),
        "--headers", "Content-Type=application/json",
    ])


def _utc_now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def main() -> None:
    missing = [v for v in REQUIRED_ENV if not os.environ.get(v)]
    if missing:
        print(f"Missing required env vars: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    subscription_id = os.environ["SUBSCRIPTION_ID"]
    resource_group = os.environ["RESOURCE_GROUP"]
    workspace_name = os.environ["WORKSPACE_NAME"]

    print(f"Resolving workspace customer ID for '{workspace_name}'...")
    customer_id = get_workspace_customer_id(subscription_id, resource_group, workspace_name)

    print(f"Querying {WINDOW_DAYS}-day sign-in baseline (min count > {MIN_COUNT})...")
    rows = run_kql_query(customer_id)
    print(f"Found {len(rows)} user/app/device combinations to baseline.")

    if not rows:
        print("No rows returned — skipping upsert. This is expected on a fresh/low-traffic tenant.")
        return

    for i, row in enumerate(rows, start=1):
        upsert_watchlist_item(subscription_id, resource_group, workspace_name, row)
        if i % 25 == 0:
            print(f"  ...{i}/{len(rows)} upserted")

    print(f"Done. Upserted {len(rows)} items into watchlist '{WATCHLIST_ALIAS}'.")


if __name__ == "__main__":
    main()