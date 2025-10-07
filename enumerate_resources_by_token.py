#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
enumerate_resources_by_token_v2.py

Usage:
    python enumerate_resources_by_token_v2.py

Prompts for a Bearer token and then lists projects the token can see.
You can pick a single project (by index) or choose "all" to probe every visible project.

For each selected project it attempts:
 - getIamPolicy
 - list GCS buckets
 - list Compute Engine instances (aggregated)
 - list GKE clusters
 - list BigQuery datasets
 - list Cloud SQL instances
 - list Pub/Sub topics & subscriptions
 - list Cloud Functions
 - list Cloud Run services
 - list Secret Manager secrets
 - list Artifact Registry repositories

Only the supplied token is used (Authorization: Bearer <token>).
"""

import json
import requests
import sys
import time

# Endpoints and templates
CRM_PROJECTS_LIST = "https://cloudresourcemanager.googleapis.com/v1/projects"
CRM_GET_IAM = "https://cloudresourcemanager.googleapis.com/v1/projects/{project}:getIamPolicy"
GCS_BUCKETS_LIST = "https://storage.googleapis.com/storage/v1/b"  # ?project=PROJECT
COMPUTE_AGG_INSTANCES = "https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/instances"
GKE_CLUSTERS_LIST = "https://container.googleapis.com/v1/projects/{project}/locations/-/clusters"
BIGQUERY_DATASETS = "https://bigquery.googleapis.com/bigquery/v2/projects/{project}/datasets"
CLOUDSQL_INSTANCES = "https://sqladmin.googleapis.com/sql/v1beta4/projects/{project}/instances"
PUBSUB_TOPICS = "https://pubsub.googleapis.com/v1/projects/{project}/topics"
PUBSUB_SUBSCRIPTIONS = "https://pubsub.googleapis.com/v1/projects/{project}/subscriptions"
CLOUD_FUNCTIONS = "https://cloudfunctions.googleapis.com/v1/projects/{project}/locations/-/functions"
CLOUD_RUN_SERVICES = "https://run.googleapis.com/v1/projects/{project}/locations/-/services"
SECRET_MANAGER_SECRETS = "https://secretmanager.googleapis.com/v1/projects/{project}/secrets"
ARTIFACT_REPOS = "https://artifactregistry.googleapis.com/v1/projects/{project}/locations/-/repositories"

# Request/Retry parameters
REQUEST_TIMEOUT = 30
RETRY_SLEEP = 1.0
MAX_RETRIES = 2

def call_api(method, url, token, params=None, json_body=None):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }
    for attempt in range(MAX_RETRIES + 1):
        try:
            if method.upper() == "GET":
                r = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
            elif method.upper() == "POST":
                r = requests.post(url, headers=headers, json=json_body, timeout=REQUEST_TIMEOUT)
            else:
                raise ValueError("Unsupported method")
        except requests.RequestException as e:
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_SLEEP)
                continue
            return {"ok": False, "status": None, "error": f"request failed: {e}"}

        # Handle server errors / rate limits with a small retry
        if r.status_code in (429, 500, 502, 503, 504) and attempt < MAX_RETRIES:
            time.sleep(RETRY_SLEEP)
            continue

        try:
            body = r.json()
        except ValueError:
            body = r.text

        if 200 <= r.status_code < 300:
            return {"ok": True, "status": r.status_code, "body": body}
        else:
            return {"ok": False, "status": r.status_code, "body": body}

    return {"ok": False, "status": None, "error": "exhausted retries"}

def list_projects(token):
    projects = []
    page_token = None
    while True:
        params = {}
        if page_token:
            params['pageToken'] = page_token
        res = call_api("GET", CRM_PROJECTS_LIST, token, params=params)
        if not res['ok']:
            return {"ok": False, "error": res.get('body') or res.get('error'), "projects": projects}
        body = res['body']
        items = body.get('projects', [])
        projects.extend(items)
        page_token = body.get('nextPageToken')
        if not page_token:
            break
    return {"ok": True, "projects": projects}

def get_project_iam(token, project_id):
    url = CRM_GET_IAM.format(project=project_id)
    body = {"options": {"requestedPolicyVersion": 3}}
    return call_api("POST", url, token, json_body=body)

def list_gcs_buckets(token, project_id):
    params = {"project": project_id}
    return call_api("GET", GCS_BUCKETS_LIST, token, params=params)

def list_compute_instances(token, project_id):
    url = COMPUTE_AGG_INSTANCES.format(project=project_id)
    return call_api("GET", url, token)

def list_gke_clusters(token, project_id):
    url = GKE_CLUSTERS_LIST.format(project=project_id)
    return call_api("GET", url, token)

def list_bigquery_datasets(token, project_id):
    url = BIGQUERY_DATASETS.format(project=project_id)
    params = {}
    datasets = []
    page_token = None
    while True:
        if page_token:
            params['pageToken'] = page_token
        res = call_api("GET", url, token, params=params)
        if not res['ok']:
            return res
        body = res['body']
        items = body.get('datasets', [])
        datasets.extend(items)
        page_token = body.get('nextPageToken')
        if not page_token:
            break
    return {"ok": True, "status": 200, "body": {"datasets": datasets}}

def list_cloudsql_instances(token, project_id):
    url = CLOUDSQL_INSTANCES.format(project=project_id)
    return call_api("GET", url, token)

def list_pubsub_topics(token, project_id):
    url = PUBSUB_TOPICS.format(project=project_id)
    topics = []
    page_token = None
    params = {}
    while True:
        if page_token:
            params['pageToken'] = page_token
        res = call_api("GET", url, token, params=params)
        if not res['ok']:
            return res
        body = res['body']
        items = body.get('topics', [])
        topics.extend(items)
        page_token = body.get('nextPageToken')
        if not page_token:
            break
    return {"ok": True, "status": 200, "body": {"topics": topics}}

def list_pubsub_subscriptions(token, project_id):
    url = PUBSUB_SUBSCRIPTIONS.format(project=project_id)
    subs = []
    page_token = None
    params = {}
    while True:
        if page_token:
            params['pageToken'] = page_token
        res = call_api("GET", url, token, params=params)
        if not res['ok']:
            return res
        body = res['body']
        items = body.get('subscriptions', [])
        subs.extend(items)
        page_token = body.get('nextPageToken')
        if not page_token:
            break
    return {"ok": True, "status": 200, "body": {"subscriptions": subs}}

def list_cloud_functions(token, project_id):
    url = CLOUD_FUNCTIONS.format(project=project_id)
    return call_api("GET", url, token)

def list_cloud_run_services(token, project_id):
    url = CLOUD_RUN_SERVICES.format(project=project_id)
    return call_api("GET", url, token)

def list_secret_manager_secrets(token, project_id):
    url = SECRET_MANAGER_SECRETS.format(project=project_id)
    return call_api("GET", url, token)

def list_artifact_repos(token, project_id):
    url = ARTIFACT_REPOS.format(project=project_id)
    return call_api("GET", url, token)

def safe_input_index(prompt, max_index):
    while True:
        s = input(prompt).strip()
        if s.lower() in ("all", "a"):
            return "all"
        try:
            i = int(s)
            if 0 <= i <= max_index:
                return i
            print(f"Please enter integer between 0 and {max_index}, or 'all'.")
        except ValueError:
            print("Please enter a valid integer index or 'all'.")

def probe_project(token, project):
    project_id = project.get('projectId') or project.get('project_id')
    name = project.get('name')
    entry = {
        "projectId": project_id,
        "name": name,
        "results": {},
        "errors": {}
    }

    # getIamPolicy
    iam_res = get_project_iam(token, project_id)
    if iam_res['ok']:
        entry['results']['iam_policy'] = iam_res['body']
    else:
        entry['errors']['getIamPolicy'] = {"status": iam_res.get('status'), "body": iam_res.get('body')}

    # GCS buckets
    gcs_res = list_gcs_buckets(token, project_id)
    if gcs_res['ok']:
        entry['results']['gcs_buckets'] = gcs_res['body'].get('items', [])
    else:
        entry['errors']['gcs_buckets'] = {"status": gcs_res.get('status'), "body": gcs_res.get('body')}

    # Compute instances (aggregated)
    comp_res = list_compute_instances(token, project_id)
    if comp_res['ok']:
        # parse aggregated instances into a list
        items = comp_res['body'].get('items', {}) or {}
        instances = []
        for zone, zone_entry in items.items():
            if not zone_entry:
                continue
            for inst in zone_entry.get('instances', []):
                instances.append({
                    "name": inst.get('name'),
                    "zone": inst.get('zone', '').split('/')[-1] if inst.get('zone') else zone,
                    "status": inst.get('status')
                })
        entry['results']['compute_instances'] = {"count": len(instances), "sample": instances[:10]}
    else:
        entry['errors']['compute_instances'] = {"status": comp_res.get('status'), "body": comp_res.get('body')}

    # GKE clusters
    gke_res = list_gke_clusters(token, project_id)
    if gke_res['ok']:
        entry['results']['gke_clusters'] = gke_res['body'].get('clusters', [])
    else:
        entry['errors']['gke_clusters'] = {"status": gke_res.get('status'), "body": gke_res.get('body')}

    # BigQuery datasets
    bq_res = list_bigquery_datasets(token, project_id)
    if bq_res['ok']:
        entry['results']['bigquery_datasets'] = bq_res['body'].get('datasets', [])
    else:
        entry['errors']['bigquery_datasets'] = {"status": bq_res.get('status'), "body": bq_res.get('body')}

    # Cloud SQL instances
    sql_res = list_cloudsql_instances(token, project_id)
    if sql_res['ok']:
        entry['results']['cloudsql_instances'] = sql_res['body'].get('items', [])
    else:
        entry['errors']['cloudsql_instances'] = {"status": sql_res.get('status'), "body": sql_res.get('body')}

    # Pub/Sub topics & subscriptions
    topics_res = list_pubsub_topics(token, project_id)
    if topics_res['ok']:
        entry['results']['pubsub_topics'] = topics_res['body'].get('topics', [])
    else:
        entry['errors']['pubsub_topics'] = {"status": topics_res.get('status'), "body": topics_res.get('body')}

    subs_res = list_pubsub_subscriptions(token, project_id)
    if subs_res['ok']:
        entry['results']['pubsub_subscriptions'] = subs_res['body'].get('subscriptions', [])
    else:
        entry['errors']['pubsub_subscriptions'] = {"status": subs_res.get('status'), "body": subs_res.get('body')}

    # Cloud Functions
    fn_res = list_cloud_functions(token, project_id)
    if fn_res['ok']:
        entry['results']['cloud_functions'] = fn_res['body'].get('functions', [])
    else:
        entry['errors']['cloud_functions'] = {"status": fn_res.get('status'), "body": fn_res.get('body')}

    # Cloud Run services
    run_res = list_cloud_run_services(token, project_id)
    if run_res['ok']:
        entry['results']['cloud_run_services'] = run_res['body'].get('items', []) or run_res['body'].get('services', [])
    else:
        entry['errors']['cloud_run_services'] = {"status": run_res.get('status'), "body": run_res.get('body')}

    # Secret Manager secrets
    sm_res = list_secret_manager_secrets(token, project_id)
    if sm_res['ok']:
        entry['results']['secrets'] = sm_res['body'].get('secrets', [])
    else:
        entry['errors']['secrets'] = {"status": sm_res.get('status'), "body": sm_res.get('body')}

    # Artifact Registry repos
    ar_res = list_artifact_repos(token, project_id)
    if ar_res['ok']:
        entry['results']['artifact_repos'] = ar_res['body'].get('repositories', [])
    else:
        entry['errors']['artifact_repos'] = {"status": ar_res.get('status'), "body": ar_res.get('body')}

    return entry

def main():
    token = input("Enter a Bearer access token: ").strip()
    if not token:
        print("No token provided. Exiting.")
        sys.exit(1)

    print("\nListing projects visible to the token...")
    proj_list_res = list_projects(token)
    if not proj_list_res['ok']:
        print("Failed to list projects. Response:")
        print(json.dumps(proj_list_res.get('error') or proj_list_res.get('body'), indent=2))
        sys.exit(1)

    projects = proj_list_res['projects']
    if not projects:
        print("No projects visible to this token.")
        sys.exit(0)

    for i, p in enumerate(projects):
        print(f"{i}) {p.get('projectId')}  -  {p.get('name', '')}")

    prompt = "\nSelect a project by index, or type 'all' to probe every visible project: "
    sel = safe_input_index(prompt, len(projects) - 1)

    targets = []
    if sel == "all":
        targets = projects
    else:
        targets = [projects[sel]]

    summary = {
        "token_truncated": token[:64] + ("..." if len(token) > 64 else ""),
        "total_visible_projects": len(projects),
        "probed_projects": {}
    }

    for project in targets:
        pid = project.get('projectId')
        print(f"\nProbing project: {pid} ...")
        try:
            result = probe_project(token, project)
            summary['probed_projects'][pid] = result
        except Exception as e:
            print(f"  Error probing project {pid}: {e}")
            summary['probed_projects'][pid] = {"error": str(e)}

    out = json.dumps(summary, indent=2)
    print("\n=== PROBE SUMMARY ===\n")
    print(out)

    save = input("\nSave summary to file? (y/N): ").strip().lower()
    if save == 'y':
        fname = input("Filename to save (default: resource_summary.json): ").strip() or "resource_summary.json"
        with open(fname, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"Saved to {fname}")

if __name__ == "__main__":
    main()
