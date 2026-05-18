# n8n-nodes-mcp-auth-trigger

A custom n8n community node that acts as an **MCP Server Trigger with full Authorization header passthrough**.

The built-in n8n MCP Server Trigger drops all HTTP headers before forwarding to tool sub-workflows. This node solves that by exposing the full request — including the `Authorization: Bearer <token>` header — as output fields your workflow can use.

---

## The Problem This Solves

```
Claude MCP Client
    → sends: Authorization: Bearer eyJhbG...  ← LOST by default MCP trigger
    → sends: tool params (symbols, date, etc.) ← only these reach sub-workflows
```

With this node:
```
Claude MCP Client
    → MCP Auth Trigger node
        → outputs: { symbols, date, _auth: { token, tokenValid, userData }, _headers: {...} }
        → your workflow can validate the token however you want
```

---

## Installation

### Via npm (once published)
```bash
npm install n8n-nodes-mcp-auth-trigger
```

### Manual install into n8n
```bash
# Go to your n8n custom nodes directory
cd ~/.n8n/custom   # or /data/custom for Docker

# Copy the package
cp -r /path/to/n8n-nodes-mcp-auth-trigger .

# Restart n8n
```

### Via n8n Community Nodes UI
1. Go to **Settings → Community Nodes**
2. Click **Install**
3. Enter `n8n-nodes-mcp-auth-trigger`
4. Restart n8n

---

## Usage

### Node Parameters

| Parameter | Description |
|---|---|
| **Path** | URL path for the MCP endpoint, e.g. `eod_prices` |
| **Token Validation** | `none` / `auth0` / `static` |
| **Auth0 Domain** | Your Auth0 domain, e.g. `phoenix-lab.us.auth0.com` |
| **Expected Token** | For static mode — the exact token to match |
| **Reject Invalid Tokens** | Return 401 immediately, or pass failure info downstream |
| **Response Mode** | Return last node result or respond immediately (202) |

### Output Fields

Every trigger output includes:

```json
{
  "symbols": "TCS,INFY",
  "lookback_days": "10",
  "date": "2026-05-18",

  "_auth": {
    "token": "eyJhbGciOiJSUzI1NiJ9...",
    "tokenValid": true,
    "tokenError": null,
    "validationMode": "auth0",
    "userData": {
      "email": "user@example.com",
      "name": "John Doe",
      "sub": "auth0|abc123"
    }
  },

  "_headers": {
    "authorization": "Bearer eyJhbGciOiJSUzI1NiJ9...",
    "content-type": "application/json",
    "user-agent": "..."
  },

  "_method": "POST",
  "_path": "/webhook/eod_prices"
}
```

---

## Workflow Examples

### 1. Pass token to a sub-workflow for Auth0 validation

```
MCP Auth Trigger (validation: none)
    → Execute Workflow (pass _auth.token as accessToken)
        → Your existing token validation workflow
```

### 2. Validate Auth0 directly in the trigger

```
MCP Auth Trigger (validation: auth0, domain: phoenix-lab.us.auth0.com)
    → IF: {{ $json._auth.tokenValid === true }}
        → ✅ Your workflow logic
        → ❌ Stop / return error
```

### 3. Access user info after validation

```javascript
// In any downstream node:
{{ $json._auth.userData.email }}      // user@example.com
{{ $json._auth.userData.sub }}        // auth0|abc123
{{ $json._auth.token }}               // raw JWT
{{ $json._auth.tokenValid }}          // true/false
```

---

## Accessing the Token in Your Existing Workflow

If you already have a token validation sub-workflow (like the one using n8n DataTable caching), wire it like this:

```
MCP Auth Trigger
    ↓
Execute Workflow (Call Token Validation)
    → workflowInputs:
        accessToken: {{ $json._auth.token }}
    ↓
IF: {{ $json.valid === true }}
    ✅ → Parse Inputs → Fetch EOD Prices → ...
    ❌ → Return error
```

---

## Building from Source

```bash
git clone https://github.com/yourname/n8n-nodes-mcp-auth-trigger
cd n8n-nodes-mcp-auth-trigger
npm install
npm run build
```

---

## Publishing to npm

```bash
# Update name/author in package.json first
npm login
npm publish
```

---

## License

MIT
