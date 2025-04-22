# Databricks .NET Sample

A .NET 8 minimal API sample that demonstrates three authentication methods for querying Databricks SQL:

- **OAuth User‑to‑Machine (U2M)**: Interactive OAuth code flow for users. Opens a browser window for login, stores access & refresh tokens in session, auto‑refreshes tokens.
- **OAuth Machine‑to‑Machine (M2M)**: Client credentials flow for unattended scenarios (service principals). Exchanges `client_id`/`client_secret` directly at `https://<workspace>/oidc/v1/token`.
- **Personal Access Token (PAT)**: Simple bearer token flow for tools that don’t support OAuth.

After authenticating, the app runs a sample SQL query against a Databricks warehouse and returns JSON results.

---

## Prerequisites

- .NET 8 SDK  
- Valid Databricks workspace & warehouse  
- Registered OAuth integration (workspace or account level) for U2M & M2M  

---

## Configuration

Set the following environment variables before running:

```bash
# OAuth U2M / M2M / PAT
export DATABRICKS_CLIENT_ID=<your-client-id>
export DATABRICKS_CLIENT_SECRET=<your-client-secret>
export DATABRICKS_REDIRECT_URI=http://localhost:5098/callback
export DATABRICKS_AUTH_TYPE=<choose U2M / M2M OR PATH>

# Databricks endpoints
export WORKSPACE_URL=<your-workspace>
export WAREHOUSE_ID=<your-warehouse-id>
```

If running on VS Code, just change the file .vscode/launch.json.


## Endpoints

GET /: Serves the HTML UI with accordion for selecting U2M, M2M or PAT.

GET /auth?client_id=&client_secret=&redirect_uri=&auth_type=[U2M|M2M|PAT]: Initiates chosen auth flow.

GET /callback: Receives OAuth code and exchanges for tokens (U2M).

GET /query: Runs SQL using session‑stored tokens (U2M & PAT).

GET /session-data: (Debug) Returns stored session values.

## Disclaimer

This sample application is provided **“as is”** without warranty of any kind. Use it at your own risk. The author and contributors assume no liability for any damages or losses arising from its use. Always review and test code in a safe environment before deploying to production.