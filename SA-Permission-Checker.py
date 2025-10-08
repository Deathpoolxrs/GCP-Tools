#!/usr/bin/env python3
"""
sa_permissions_audit_with_report.py

Given a folder of Google Cloud service account JSON key files, this script:
 - authenticates with each service account
 - lists projects visible to that service account (unless --project-id was provided)
 - calls projects.testIamPermissions for each project and collects granted permissions
 - prints results per project as before
 - at the end: prints and writes a report mapping each permission -> list of SA emails that have it
"""

import argparse
import glob
import json
import os
import sys
import time
import csv
from typing import List, Optional, Set, Dict

import requests

# google-auth imports
try:
    from google.oauth2 import service_account
    from google.auth.transport.requests import Request as GoogleRequest
except Exception as e:
    print("ERROR: google-auth library is required. Install with: pip install google-auth google-auth-httplib2 requests")
    raise

PERMISSIONS_TO_TEST = [
    "cloudbuild.builds.create",
    "deploymentmanager.deployments.create",
    "iam.roles.update",
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccountKeys.create",
    "iam.serviceAccounts.implicitDelegation",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.signJwt",
    "cloudfunctions.functions.create",
    "cloudfunctions.functions.update",
    "compute.instances.create",
    "run.services.create",
    "cloudscheduler.jobs.create",
    "orgpolicy.policy.set",
    "storage.hmacKeys.create",
    "serviceusage.apiKeys.create",
    "serviceusage.apiKeys.list",
]

CLOUDRESOURCEMANAGER_API = "https://cloudresourcemanager.googleapis.com/v1"

def obtain_access_token_from_sa_key(sa_key_path: str, scopes: Optional[List[str]] = None, timeout: int = 30) -> Optional[str]:
    if scopes is None:
        scopes = ["https://www.googleapis.com/auth/cloud-platform"]

    try:
        creds = service_account.Credentials.from_service_account_file(sa_key_path, scopes=scopes)
        request = GoogleRequest()
        creds.refresh(request)
        return creds.token
    except Exception as e:
        print(f"[!] Failed to obtain token for '{sa_key_path}': {e}")
        return None

def list_projects_for_token(access_token: str) -> List[dict]:
    projects = []
    url = f"{CLOUDRESOURCEMANAGER_API}/projects"
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"pageSize": 1000}
    while True:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code == 200:
            j = resp.json()
            items = j.get("projects", [])
            projects.extend(items)
            next_token = j.get("nextPageToken")
            if not next_token:
                break
            params["pageToken"] = next_token
        else:
            print(f"[!] projects.list returned {resp.status_code}: {resp.text}")
            break
    return projects

def test_permissions(project_id: str, access_token: str, permissions: List[str]) -> Optional[set]:
    url = f"{CLOUDRESOURCEMANAGER_API}/projects/{project_id}:testIamPermissions"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    body = {"permissions": permissions}
    try:
        resp = requests.post(url, headers=headers, json=body, timeout=30)
    except Exception as e:
        print(f"[!] HTTP error testing permissions for project {project_id}: {e}")
        return None

    if resp.status_code != 200:
        print(f"[!] Failed to test permissions for project {project_id}: {resp.status_code} {resp.text}")
        return None

    data = resp.json()
    granted = set(data.get("permissions", []))
    return granted

def pretty_print_results(project_id: str, granted: Optional[set], permissions: List[str]):
    print(f"\n=== Project: {project_id} ===")
    if granted is None:
        print("[!] Could not determine permissions (request failed).")
        return
    for perm in permissions:
        status = "✅ ALLOWED" if perm in granted else "❌ DENIED"
        print(f"{perm:45} {status}")

def find_key_files(folder_path: str) -> List[str]:
    candidates = []
    patterns = ["*.json", "*.JSON"]
    for pat in patterns:
        candidates.extend(glob.glob(os.path.join(folder_path, pat)))
    filtered = []
    for f in sorted(set(candidates)):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                j = json.load(fh)
            if "type" in j and j.get("type") == "service_account" and "private_key" in j and "client_email" in j:
                filtered.append(f)
        except Exception:
            continue
    return filtered

def process_service_account_key(sa_key_path: str, args) -> (str, Set[str]):
    """
    Process a single SA key file.
    Returns tuple: (client_email, set_of_permissions_granted_by_this_SA)
    A granted permission is recorded if testIamPermissions returned it for any project tested.
    """
    print(f"\n--- Processing key: {sa_key_path} ---")
    # Read client_email for reporting
    try:
        with open(sa_key_path, "r", encoding="utf-8") as fh:
            key_json = json.load(fh)
            client_email = key_json.get("client_email", "<unknown>")
    except Exception as e:
        print(f"[!] Failed to read client_email from {sa_key_path}: {e}")
        client_email = "<unknown>"

    token = obtain_access_token_from_sa_key(sa_key_path)
    if not token:
        print("[!] Skipping this key due to token error.")
        return client_email, set()

    if args.project_id:
        project_ids = [args.project_id]
    else:
        projects = list_projects_for_token(token)
        if not projects:
            print("[!] No projects returned or permission denied for projects.list.")
            return client_email, set()
        project_ids = [p.get("projectId") for p in projects if p.get("projectId")]
        if not project_ids:
            print("[!] No project IDs parsed from projects.list response.")
            return client_email, set()

    # accumulate permissions granted anywhere for this SA
    sa_granted_permissions: Set[str] = set()

    for pid in project_ids:
        print(f"\n[+] Testing project: {pid}")
        granted = test_permissions(pid, token, PERMISSIONS_TO_TEST)
        pretty_print_results(pid, granted, PERMISSIONS_TO_TEST)
        if granted:
            sa_granted_permissions.update(granted)
        time.sleep(0.2)

    print(f"\n[+] Done processing {client_email}. Total unique granted perms found: {len(sa_granted_permissions)}")
    return client_email, sa_granted_permissions

def write_reports(permission_map: Dict[str, List[str]], json_path: str = "permission_report.json", csv_path: str = "permission_report.csv"):
    # JSON
    try:
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(permission_map, jf, indent=2)
        print(f"[+] Wrote JSON report: {os.path.abspath(json_path)}")
    except Exception as e:
        print(f"[!] Failed to write JSON report: {e}")

    # CSV (permission, comma-separated SA emails)
    try:
        with open(csv_path, "w", newline='', encoding="utf-8") as cf:
            writer = csv.writer(cf)
            writer.writerow(["permission", "service_accounts_comma_separated"])
            for perm, sa_list in permission_map.items():
                writer.writerow([perm, ",".join(sa_list)])
        print(f"[+] Wrote CSV report: {os.path.abspath(csv_path)}")
    except Exception as e:
        print(f"[!] Failed to write CSV report: {e}")

def main():
    parser = argparse.ArgumentParser(description="Use service-account JSON keys to check project-level permissions and produce a permission -> SA mapping report.")
    parser.add_argument("--keys-folder", "-k", required=True, help="Folder containing service account JSON key files.")
    parser.add_argument("--project-id", "-p", help="Optional: specific project ID to test (if omitted, script will list projects visible to each SA).")
    parser.add_argument("--single-file", "-s", help="Optional: test only a single SA key file (path).")
    args = parser.parse_args()

    if args.single_file:
        if not os.path.isfile(args.single_file):
            print(f"[!] single-file not found: {args.single_file}")
            sys.exit(1)
        key_files = [args.single_file]
    else:
        if not os.path.isdir(args.keys_folder):
            print(f"[!] keys-folder not found or not a directory: {args.keys_folder}")
            sys.exit(1)
        key_files = find_key_files(args.keys_folder)

    if not key_files:
        print("[!] No service account JSON key files found in the folder (or none looked like service account keys).")
        sys.exit(1)

    print(f"[+] Found {len(key_files)} key(s).")

    # permission -> list of SA emails that have it (deduped later)
    permission_map: Dict[str, List[str]] = {perm: [] for perm in PERMISSIONS_TO_TEST}

    for key_path in key_files:
        try:
            client_email, sa_perms = process_service_account_key(key_path, args)
            # For each permission the SA has, append the SA email to the permission_map
            for perm in sa_perms:
                if perm not in permission_map:
                    # include unexpected returned permissions too
                    permission_map.setdefault(perm, [])
                if client_email not in permission_map[perm]:
                    permission_map[perm].append(client_email)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user.")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Unexpected error while processing '{key_path}': {e}")

    # Pretty print final mapping
    print("\n\n=== Final Permission -> Service Accounts Report ===\n")
    for perm in sorted(permission_map.keys()):
        sas = permission_map.get(perm, [])
        if sas:
            print(f"{perm:45} -> {len(sas):2d} SA(s): {', '.join(sas)}")
        else:
            print(f"{perm:45} ->  0 SA(s)")

    # Save reports
    write_reports(permission_map)

if __name__ == "__main__":
    main()
