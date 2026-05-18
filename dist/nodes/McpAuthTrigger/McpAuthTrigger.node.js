"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.McpAuthTrigger = void 0;
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const streamableHttp_js_1 = require("@modelcontextprotocol/sdk/server/streamableHttp.js");
const bearerAuth_js_1 = require("@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js");
// ── Auth0 token verifier ──────────────────────────────────────────────────────
function makeAuth0Verifier(domain) {
    return {
        async verifyAccessToken(token) {
            var _a;
            const res = await fetch(`https://${domain}/userinfo`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            if (!res.ok) {
                throw new Error(`Auth0 rejected token: ${res.status} ${res.statusText}`);
            }
            const user = (await res.json());
            let expiresAt;
            try {
                const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
                expiresAt = payload.exp;
            }
            catch (_) { }
            return {
                token,
                clientId: (_a = user['sub']) !== null && _a !== void 0 ? _a : 'unknown',
                scopes: [],
                expiresAt,
                extra: { email: user['email'], userData: user },
            };
        },
    };
}
// ── The n8n node ──────────────────────────────────────────────────────────────
class McpAuthTrigger {
    constructor() {
        this.description = {
            displayName: 'MCP Auth Trigger',
            name: 'mcpAuthTrigger',
            icon: 'fa:plug',
            group: ['trigger'],
            version: 1,
            description: 'Real MCP Server (Streamable HTTP) with Auth0 Bearer token validation. ' +
                'Tool parameters are forwarded to your n8n workflow.',
            defaults: { name: 'MCP Auth Trigger' },
            inputs: [],
            // @ts-ignore
            outputs: ['main'],
            outputNames: ['Workflow'],
            webhooks: [
                {
                    name: 'default',
                    httpMethod: 'POST',
                    responseMode: 'responseNode',
                    path: '={{$parameter["path"]}}',
                },
            ],
            properties: [
                {
                    displayName: 'Path',
                    name: 'path',
                    type: 'string',
                    default: 'mcp',
                    required: true,
                    description: 'Webhook path for the MCP endpoint (e.g. "mcp" → /webhook/mcp)',
                },
                {
                    displayName: 'Token Validation',
                    name: 'tokenValidation',
                    type: 'options',
                    options: [
                        { name: 'None', value: 'none' },
                        { name: 'Auth0 /userinfo', value: 'auth0' },
                    ],
                    default: 'auth0',
                    description: 'How to validate the incoming Bearer token',
                },
                {
                    displayName: 'Auth0 Domain',
                    name: 'auth0Domain',
                    type: 'string',
                    default: '',
                    placeholder: 'your-tenant.us.auth0.com',
                    required: true,
                    displayOptions: { show: { tokenValidation: ['auth0'] } },
                    description: 'Auth0 domain used to call /userinfo',
                },
                {
                    displayName: 'Tool Name',
                    name: 'toolName',
                    type: 'string',
                    default: 'get_eod_prices',
                    required: true,
                    description: 'MCP tool name Claude will call',
                },
                {
                    displayName: 'Tool Description',
                    name: 'toolDescription',
                    type: 'string',
                    typeOptions: { rows: 3 },
                    default: 'Get end-of-day adjusted prices for NSE symbols',
                    description: 'Description shown to the AI so it knows when to call this tool',
                },
                {
                    displayName: 'Tool Parameters (JSON Schema properties)',
                    name: 'toolSchema',
                    type: 'json',
                    default: JSON.stringify({
                        symbols: {
                            type: 'string',
                            description: 'Comma-separated NSE symbols e.g. TCS,INFY',
                        },
                        lookback_days: {
                            type: 'string',
                            description: 'Number of calendar days to look back. Use 0 for a specific date.',
                        },
                        date: {
                            type: 'string',
                            description: 'Specific date YYYY-MM-DD. Only used when lookback_days is 0.',
                        },
                    }, null, 2),
                    description: 'JSON Schema properties object (the fields inside "properties": {})',
                },
            ],
        };
    }
    async webhook() {
        const req = this.getRequestObject();
        const res = this.getResponseObject();
        const tokenValidation = this.getNodeParameter('tokenValidation', 'auth0');
        const auth0Domain = this.getNodeParameter('auth0Domain', '');
        const toolName = this.getNodeParameter('toolName', 'tool');
        const toolDescription = this.getNodeParameter('toolDescription', '');
        const toolSchemaRaw = this.getNodeParameter('toolSchema', '{}');
        // ── 1. Auth0 bearer validation ─────────────────────────────────────────
        if (tokenValidation === 'auth0') {
            const verifier = makeAuth0Verifier(auth0Domain);
            const middleware = (0, bearerAuth_js_1.requireBearerAuth)({ verifier });
            const passed = await new Promise((resolve) => {
                middleware(req, res, (err) => resolve(!err));
            });
            if (!passed)
                return { noWebhookResponse: true };
        }
        const authInfo = req.auth;
        // ── 2. Parse tool schema ───────────────────────────────────────────────
        let schemaProperties = {};
        try {
            schemaProperties =
                typeof toolSchemaRaw === 'string'
                    ? JSON.parse(toolSchemaRaw)
                    : toolSchemaRaw;
        }
        catch (_) { }
        const inputSchema = {
            type: 'object',
            properties: schemaProperties,
        };
        // ── 3. Build MCP server with low-level request handlers ───────────────
        // We use setRequestHandler directly to avoid deep zod type inference issues
        const mcpServer = new mcp_js_1.McpServer({ name: toolName, version: '1.0.0' });
        const rawServer = mcpServer.server;
        // Promise that resolves when the tool is called with args
        let resolveToolCall;
        const toolCallPromise = new Promise((r) => { resolveToolCall = r; });
        // Promise that resolves when the workflow sends back a result
        let resolveWorkflowResult;
        const workflowResultPromise = new Promise((r) => { resolveWorkflowResult = r; });
        // Store resolveWorkflowResult so Respond to Webhook node can call it
        req.__resolveWorkflowResult = resolveWorkflowResult;
        // tools/list handler
        rawServer.setRequestHandler({ method: 'tools/list' }, async () => ({
            tools: [{ name: toolName, description: toolDescription, inputSchema }],
        }));
        // tools/call handler
        rawServer.setRequestHandler({ method: 'tools/call' }, async (request) => {
            var _a, _b, _c, _d, _e;
            const args = ((_a = request.params.arguments) !== null && _a !== void 0 ? _a : {});
            resolveToolCall({
                ...args,
                _auth: authInfo
                    ? {
                        token: authInfo.token,
                        clientId: authInfo.clientId,
                        email: (_c = (_b = authInfo.extra) === null || _b === void 0 ? void 0 : _b['email']) !== null && _c !== void 0 ? _c : null,
                        userData: (_e = (_d = authInfo.extra) === null || _d === void 0 ? void 0 : _d['userData']) !== null && _e !== void 0 ? _e : null,
                        expiresAt: authInfo.expiresAt,
                        tokenValid: true,
                    }
                    : { tokenValid: false },
            });
            // Wait for workflow result (set by Respond to Webhook node)
            const result = await workflowResultPromise;
            return {
                content: [{
                        type: 'text',
                        text: typeof result === 'string' ? result : JSON.stringify(result),
                    }],
            };
        });
        // ── 4. Create Streamable HTTP transport ───────────────────────────────
        const transport = new streamableHttp_js_1.StreamableHTTPServerTransport({
            sessionIdGenerator: undefined, // stateless
        });
        await mcpServer.connect(transport);
        // Handle the incoming MCP HTTP request
        await transport.handleRequest(req, res, req.body);
        // ── 5. Return workflow data if a tool was called ───────────────────────
        const raced = await Promise.race([
            toolCallPromise.then((data) => ({ type: 'tool', data })),
            // Timeout fallback — if it was just tools/list or initialize
            new Promise((r) => setTimeout(() => r({ type: 'noop', data: null }), 100)),
        ]);
        if (raced.type === 'tool') {
            return { workflowData: [[{ json: raced.data }]] };
        }
        return { noWebhookResponse: true };
    }
}
exports.McpAuthTrigger = McpAuthTrigger;
//# sourceMappingURL=McpAuthTrigger.node.js.map