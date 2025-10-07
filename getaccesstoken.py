#!/usr/bin/env python3

import json
from googleapiclient.discovery import build
import google.oauth2.credentials

# Prompt user for access token
ACCESS_TOKEN = input('Enter an access token to use for authentication: ').strip()

# Initialize credentials
creds = google.oauth2.credentials.Credentials(ACCESS_TOKEN)

# ---------------------------------------
# Helper: Select a project
# ---------------------------------------
def select_project(creds):
    crm = build('cloudresourcemanager', 'v1', credentials=creds)
    response = crm.projects().list().execute()
    projects = response.get('projects', [])

    if not projects:
        raise Exception("❌ No projects found for this account")

    print("\nAvailable Projects:")
    for i, p in enumerate(projects):
        print(f"{i}) {p['projectId']} ({p.get('name', '')})")

    index = int(input("\nSelect a project by index: "))
    return projects[index]


# ---------------------------------------
# Helper: Select a service account
# ---------------------------------------
def select_svc_account(creds, project_id):
    iam = build('iam', 'v1', credentials=creds)
    response = iam.projects().serviceAccounts().list(
        name=f'projects/{project_id}'
    ).execute()
    svc_accounts = response.get('accounts', [])

    if not svc_accounts:
        raise Exception("❌ No service accounts found in this project")

    print("\nAvailable Service Accounts:")
    for i, acc in enumerate(svc_accounts):
        print(f"{i}) {acc['email']}")

    index = int(input("\nSelect a service account by index: "))
    return svc_accounts[index]


# ---------------------------------------
# Main: Select project & service account
# ---------------------------------------
project = select_project(creds)
svc_account = select_svc_account(creds, project['projectId'])

# ---------------------------------------
# Generate a new access token for the selected service account
# ---------------------------------------
service = build('iamcredentials', 'v1', credentials=creds)

body = {
    'scope': [
        'https://www.googleapis.com/auth/iam',
        'https://www.googleapis.com/auth/cloud-platform'
    ]
}

print(f"\n🔐 Generating access token for: {svc_account['email']} ...")

res = service.projects().serviceAccounts().generateAccessToken(
    name=f'projects/-/serviceAccounts/{svc_account["email"]}',
    body=body
).execute()

print("\n✅ Access Token Generated Successfully:\n")
print(json.dumps(res, indent=4))
